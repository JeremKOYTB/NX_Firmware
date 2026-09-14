import os
import sys
import re
import time
import json
import hashlib
import warnings
import argparse
import io
import zlib
import uuid
import shutil
import xml.etree.ElementTree as ET
from struct import unpack, pack
from binascii import hexlify
from glob import glob
from shutil import rmtree, disk_usage
from subprocess import run, PIPE
from os import makedirs, remove
from os.path import basename, exists, join, abspath, dirname, getsize
from configparser import ConfigParser
from zipfile import ZipFile, ZIP_STORED, ZipInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import HTTPError

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from tqdm import tqdm
except ImportError:
    print("Module(s) missing. Install with: pip install cryptography requests tqdm")
    sys.exit(1)

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="firmware_downloader.py: Nintendo firmware downloader and packer.\n\n"
                "This tool allows you to securely download official firmware files directly from Nintendo servers,\n"
                "verify their integrity, pack them into a standard ZIP archive, optionally build an installable NSP file,\n"
                "and maintain a ROM management DAT file for preservation purposes."
)
parser.add_argument("version", nargs="?", default="", help="Target firmware version (e.g. 15.0.1.5020).\nIf empty, the script automatically fetches the latest available version.")
parser.add_argument("--allversion", action="store_true", help="Fetch and process all available versions logged on GBATemp.")
parser.add_argument("--local", action="store_true", help="Enable local mode. Processes existing local files in the directory\ninstead of downloading them from Nintendo servers.")
parser.add_argument("--force-nsp", action="store_true", help="Force the compilation of an NSP file without asking for user confirmation.")
parser.add_argument("--extract-data", action="store_true", help="Extract underlying data (romfs, exefs, section0) from the NCA files using hactool.")
parser.add_argument("--extract-zip", action="store_true", help="Extract raw NCA files directly from the generated ZIP archive.")
parser.add_argument("--extract-nsp", action="store_true", help="Extract raw NCA files directly from the compiled NSP file.")
parser.add_argument("--datfile", action="store_true", help="Generate or update the Logiqx XML DAT file used for ROM management.")
parser.add_argument("--sync-releases", action="store_true", help="Scan all GitHub releases and generate/sync the DAT file for all available firmwares in order.")
parser.add_argument("--displayversion", action="store_true", help="Use the simplified commercial version (e.g. 22.5.0 instead of 22.5.0.0480) for folder and ZIP/NSP naming.")
parser.add_argument("--notimeout", action="store_true", help="Disable the 60 seconds timeout for user prompts.")
parser.add_argument("--logs", action="store_true", help="Enable verbose logging to display every action performed by the script.")
args, unknown_args = parser.parse_known_args()

def log_print(msg):
    if args.logs:
        print(f"[LOG] {msg}")

def ensure_readable(filepath):
    log_print(f"I/O Audit: Validating readability for {basename(filepath)}...")
    if not exists(filepath):
        print(f"\n[!] CRITICAL ERROR: File physically missing from disk: {filepath}")
        sys.exit(1)
    if not os.access(filepath, os.R_OK):
        print(f"\n[!] CRITICAL ERROR: Permission denied. Cannot read: {filepath}")
        sys.exit(1)
    try:
        with open(filepath, 'rb') as f:
            f.read(1)
        log_print(f"I/O Audit Passed: {basename(filepath)} is accessible and unlocked.")
    except IOError as e:
        print(f"\n[!] CRITICAL ERROR: Hardware or lock error on {filepath}\nSystem message: {e}")
        sys.exit(1)

def input_with_timeout(prompt, timeout=60):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    if os.name == 'nt':
        import msvcrt
        start_time = time.time()
        response = ""
        while time.time() - start_time < timeout:
            if msvcrt.kbhit():
                c = msvcrt.getch()
                if c in (b'\r', b'\n'):
                    sys.stdout.write('\n')
                    sys.stdout.flush()
                    return response
                elif c == b'\x08':
                    if len(response) > 0:
                        response = response[:-1]
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    try:
                        char = c.decode('utf-8')
                        response += char
                        sys.stdout.write(char)
                        sys.stdout.flush()
                    except UnicodeDecodeError:
                        pass
            time.sleep(0.05)
        sys.stdout.write("\n[Timeout reached. Defaulting to 'n']\n")
        sys.stdout.flush()
        return "n"
    else:
        import select
        i, o, e = select.select([sys.stdin], [], [], timeout)
        if i:
            return sys.stdin.readline().strip()
        else:
            sys.stdout.write("\n[Timeout reached. Defaulting to 'n']\n")
            sys.stdout.flush()
            return "n"

def get_user_choice(prompt_text):
    if args.notimeout:
        log_print(f"Prompting user without timeout: {prompt_text}")
        return input(prompt_text).strip().lower()
    log_print(f"Prompting user with 60s timeout: {prompt_text}")
    return input_with_timeout(prompt_text, 60).strip().lower()

GBATEMP_MAPPING = {}

def get_gbatemp_firmwares():
    global GBATEMP_MAPPING
    url = "https://gbatemp.net/download/nintendo-switch-firmware-datfile.36558/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    try:
        log_print(f"Fetching GBATemp data from {url}")
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        match = re.search(r'Logged Firmware.*?class="bbCodeBlock-content[^>]*>(.*?)</div', r.text, re.DOTALL | re.IGNORECASE)
        if match:
            content = re.sub(r'<br\s*/?>', '\n', match.group(1), flags=re.IGNORECASE)
            lines = [x.strip() for x in content.split('\n') if x.strip() and "Firmware" in x]
            for line in lines:
                m = re.search(r'^Firmware\s+(.*?)\s+\(NintendoSDK[^\)]*\)\s+\((\d+\.\d+\.\d+\.\d{4})\)\s*(.*)', line, re.IGNORECASE)
                if m:
                    c_ver = m.group(1).strip()
                    i_ver = m.group(2).strip()
                    suffix = m.group(3).strip()
                    GBATEMP_MAPPING[i_ver] = {
                        'original_line': line,
                        'disp_ver': c_ver,
                        'suffix': suffix
                    }
            log_print(f"Successfully extracted {len(lines)} lines from GBATemp.")
            return lines
    except Exception as e:
        log_print(f"Failed to fetch GBATemp data: {e}")
    return []

def format_fw_list_name(ver_full):
    if ver_full in GBATEMP_MAPPING:
        line = GBATEMP_MAPPING[ver_full]['original_line']
        m = re.search(r'^Firmware\s+(.*?)\s+\(NintendoSDK.*?\)\s+\(\d+\.\d+\.\d+\.\d{4}\)\s*(.*)', line, re.IGNORECASE)
        if m:
            c_ver = m.group(1).strip()
            suffix = m.group(2).strip()
            res = f"Firmware {ver_full} ({c_ver})"
            if suffix:
                res += f" {suffix}"
            return res
    parts = ver_full.split('.')
    if len(parts) >= 3:
        c_ver = f"{parts[0]}.{parts[1]}.{parts[2]}"
        return f"Firmware {ver_full} ({c_ver})"
    return f"Firmware {ver_full}"

def display_gbatemp_list():
    lines = get_gbatemp_firmwares()
    if not lines:
        print("ERROR: Could not retrieve the list from GBATemp.")
        return
    print("\n" + "="*80)
    print(" GBATEMP LOGGED FIRMWARE LIST")
    print("="*80)
    for line in lines:
        print(f" * {line}")
    print("="*80)
    print("INFO: Please note that some versions might be unavailable or incomplete.\n")

BASE_DIR = dirname(abspath(__file__))
KEYS_DIR = join(BASE_DIR, "keys")
HACTOOL_BIN = "hactool.exe" if os.name == "nt" else "./hactool"
HACTOOL_PATH = join(BASE_DIR, HACTOOL_BIN)

def readdata(f, addr, size):
    f.seek(addr)
    return f.read(size)

def utf8(s):
    return s.decode("utf-8")

def sha256(s):
    return hashlib.sha256(s).digest()

def readint(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<I", f.read(4))[0]

def readshort(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<H", f.read(2))[0]

def hexify(s):
    return hexlify(s).decode("utf-8")

def ihexify(n, b):
    return hex(n)[2:].zfill(b * 2)

def dlfile(url, out, user_agent, session=None, silent=False):
    req_session = session or requests.Session()
    headers = {"User-Agent": user_agent}
    
    dlded = 0
    if exists(out):
        dlded = getsize(out)
        headers["Range"] = f"bytes={dlded}-"
    
    for attempt in range(5):
        try:
            log_print(f"GET Request (Attempt {attempt+1}): {url}")
            resp = req_session.get(
                url,
                cert=(join(KEYS_DIR, "switch_client.crt"), join(KEYS_DIR, "switch_client.key")),
                headers=headers,
                stream=True, 
                verify=False,
                timeout=15
            )
            
            if resp.status_code == 416:
                log_print(f"File {basename(out)} already fully downloaded (416 Range Not Satisfiable).")
                return
                
            resp.raise_for_status()
            
            if resp.status_code == 206:
                total_size = dlded + int(resp.headers.get('Content-Length', 0))
                mode = "ab"
                log_print(f"Resuming download for {basename(out)} ({dlded}/{total_size} bytes)")
            else:
                total_size = int(resp.headers.get('Content-Length', 0))
                mode = "wb"
                dlded = 0
                log_print(f"Starting new download for {basename(out)} ({total_size} bytes)")
                
            name = basename(out)
            chunk_size = 1024 * 1024
            
            with open(out, mode) as f:
                if silent:
                    for chunk in resp.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
                else:
                    with tqdm(total=total_size, initial=dlded, unit='B', unit_scale=True, desc=f"Downloading {name}", leave=False) as pbar:
                        for chunk in resp.iter_content(chunk_size=chunk_size):
                            if chunk:
                                f.write(chunk)
                                pbar.update(len(chunk))
            break
        except Exception as e:
            log_print(f"Download failed for {basename(out)}: {e}")
            if attempt == 4:
                print(f"\n[!] Error downloading {basename(out)}: {e}")
                raise
            time.sleep(2)

def dlfiles(dltable, user_agent):
    if not dltable:
        return
    dl_tmp_path = join(BASE_DIR, f"dl_{uuid.uuid4().hex[:8]}.tmp")
    log_print(f"Creating temporary aria2c manifest: {dl_tmp_path}")
    with open(dl_tmp_path, "w") as f:
        for url, dirc, fname, fhash in dltable:
            if fhash:
                f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
            else:
                f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n")
                
    if shutil.which("aria2c"):
        try:
            log_print("Attempting to execute aria2c binary for parallel downloads.")
            run([
                "aria2c", "--no-conf", "--console-log-level=error",
                "--file-allocation=none", "--summary-interval=0",
                "--download-result=hide",
                f"--certificate={join(KEYS_DIR, 'switch_client.crt')}",
                f"--private-key={join(KEYS_DIR, 'switch_client.key')}",
                f"--header=User-Agent: {user_agent}",
                "--check-certificate=false",
                "-x", "16", "-s", "16", "-i", dl_tmp_path
            ], check=True)
        except Exception as e:
            log_print(f"aria2c execution failed: {e}. Falling back to Python requests.")
            _dlfiles_fallback(dltable, user_agent)
    else:
        print("INFO: aria2c not found (this is normal if not installed). Using parallel Python requests fallback.")
        log_print("aria2c not found in PATH. Using parallel Python requests fallback.")
        _dlfiles_fallback(dltable, user_agent)
        
    try:
        remove(dl_tmp_path)
        log_print(f"Cleaned up temporary manifest: {dl_tmp_path}")
    except FileNotFoundError:
        pass

def _dlfiles_fallback(dltable, user_agent):
    with requests.Session() as global_session:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for url, dirc, fname, fhash in dltable:
                out_dir = join(BASE_DIR, dirc)
                makedirs(out_dir, exist_ok=True)
                out = join(out_dir, fname)
                futures.append(executor.submit(dlfile, url, out, user_agent, global_session, True))
            
            with tqdm(total=len(futures), unit='file', desc="Downloading NCAs") as pbar:
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        log_print(f"Fallback download error logged safely: {e}")
                    pbar.update(1)

def nin_request(method, url, user_agent, headers=None, session=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    req_session = session or requests
    for attempt in range(5):
        try:
            log_print(f"{method} Request (Attempt {attempt+1}): {url}")
            resp = req_session.request(
                method, url,
                cert=(join(KEYS_DIR, "switch_client.crt"), join(KEYS_DIR, "switch_client.key")),
                headers=headers, verify=False, timeout=15
            )
            resp.raise_for_status()
            return resp
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                log_print(f"404 Not Found response received for {url}")
                raise
            if attempt == 4:
                raise
            time.sleep(2)
        except requests.exceptions.RequestException as e:
            log_print(f"Request exception for {url}: {e}")
            if attempt == 4:
                raise
            time.sleep(2)

def parse_cnmt(nca):
    ncaf = basename(nca)
    cnmt_temp_dir = join(BASE_DIR, f"cnmt_tmp_{uuid.uuid4().hex[:8]}_{ncaf}")
    log_print(f"Parsing CNMT: {ncaf} via hactool.")
    ensure_readable(nca)
    
    try:
        cmd = [HACTOOL_PATH, "-k", join(BASE_DIR, "prod.keys"), nca, "--section0dir", cnmt_temp_dir]
        log_print(f"Executing: {' '.join(cmd)}")
        result = run(cmd, stdout=PIPE, stderr=PIPE)
        if result.returncode != 0:
            print(f"\n[!] CRITICAL ERROR: Hactool failed to extract CNMT {ncaf}.")
            print(result.stderr.decode('utf-8', 'ignore').strip())
            sys.exit(1)
    except FileNotFoundError:
        print(f"\n[!] CRITICAL ERROR: '{HACTOOL_BIN}' not found in {BASE_DIR}.")
        sys.exit(1)
    
    try:
        extracted_files = glob(join(cnmt_temp_dir, "*.cnmt"))
        if not extracted_files:
            raise FileNotFoundError(f"Failed to extract CNMT from {ncaf}. Check prod.keys.")
            
        cnmt_file = extracted_files[0]
        entries = []
        with open(cnmt_file, "rb") as c:
            c.seek(0)
            cnmt_title_id = ihexify(unpack("<Q", c.read(8))[0], 8)
            
            c_type = readdata(c, 0xc, 1)
            is_su_type = (c_type[0] == 0x3)
            log_print(f"CNMT Title ID: {cnmt_title_id}, Type 0x3 (SystemUpdate): {is_su_type}")
            
            if is_su_type:
                n_entries = readshort(c, 0x12)
                offset    = readshort(c, 0xe)
                base = 0x20 + offset
                for i in range(n_entries):
                    c.seek(base + i*0x10)
                    title_id = unpack("<Q", c.read(8))[0]
                    version  = unpack("<I", c.read(4))[0]
                    entries.append((ihexify(title_id, 8), version, None, 0))
            else:
                n_entries = readshort(c, 0x10)
                offset    = readshort(c, 0xe)
                base = 0x20 + offset
                for i in range(n_entries):
                    c.seek(base + i*0x38)
                    h      = c.read(32)
                    nid    = hexify(c.read(16))
                    c.seek(base + i*0x38 + 0x30)
                    nca_size = int.from_bytes(c.read(6), byteorder='little')
                    c.seek(base + i*0x38 + 0x36)
                    entry_type = unpack("<B", c.read(1))[0]
                    entries.append((nid, hexify(h), entry_type, nca_size))
        return cnmt_title_id, entries, is_su_type
    finally:
        if exists(cnmt_temp_dir):
            rmtree(cnmt_temp_dir)
            log_print(f"Cleaned up CNMT extraction directory: {cnmt_temp_dir}")

def read_cnmt_entries(cnmt_path):
    try:
        with open(cnmt_path, "rb") as c:
            c.seek(0)
            tid_int = int.from_bytes(c.read(8), "little")
            tid_hex = hex(tid_int)[2:].zfill(16).lower()
            c.seek(8)
            ver_int = int.from_bytes(c.read(4), "little")
            c.seek(0xc)
            is_su = (c.read(1)[0] == 0x3)
            
            nca_ids = []
            if not is_su:
                c.seek(0x10)
                n_entries = int.from_bytes(c.read(2), "little")
                c.seek(0xe)
                offset = int.from_bytes(c.read(2), "little")
                base = 0x20 + offset
                for i in range(n_entries):
                    c.seek(base + i * 0x38)
                    h = c.read(32)
                    nid = c.read(16).hex().lower()
                    nca_ids.append(nid)
            return tid_hex, ver_int, nca_ids
    except Exception:
        return None, 0, []

def find_firmware_identity(folder_path):
    hactool_path = HACTOOL_PATH if exists(HACTOOL_PATH) else ("hactool.exe" if os.name == "nt" else "hactool")
    keys_path = join(BASE_DIR, "prod.keys")
    if not exists(keys_path):
        log_print(f"FATAL: '{keys_path}' not found for firmware identity verification.")
        return None, False

    nca_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            if f.endswith(".nca"):
                nca_files.append(join(root, f))

    log_print(f"find_firmware_identity: Total NCA files detected in {folder_path} : {len(nca_files)}")
    if not nca_files:
        return None, False

    real_full_ver = ""
    sdk_title = ""
    system_version_data_nca = None
    sdk_found = False

    log_print("--- STEP 1 : Global analysis of CNMT metadata ---")

    def process_cnmt_nca(nca):
        if not nca.endswith(".cnmt.nca"):
            return None
        
        tmp_dir = join(BASE_DIR, f"tmp_cnmt_{uuid.uuid4().hex[:8]}")
        try:
            res = run([hactool_path, "-k", keys_path, nca, "--section0dir", tmp_dir], stdout=PIPE, stderr=PIPE, timeout=10)
            if res.returncode == 0 and exists(tmp_dir):
                cnmts = glob(join(tmp_dir, "*.cnmt"))
                if cnmts:
                    tid_hex, ver_int, nca_ids = read_cnmt_entries(cnmts[0])
                    return tid_hex, ver_int, nca_ids, nca
        except Exception:
            pass
        finally:
            rmtree(tmp_dir, ignore_errors=True)
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(process_cnmt_nca, nca) for nca in nca_files]
        for future in as_completed(futures):
            res = future.result()
            if res:
                tid_hex, ver_int, nca_ids, cnmt_nca = res
                
                if tid_hex == "0100000000000816":  # SystemUpdate
                    l_maj = ver_int >> 26
                    l_min = (ver_int >> 20) & 0x3F
                    l_sub = (ver_int >> 16) & 0xF
                    l_bld = ver_int & 0xFFFF
                    real_full_ver = f"{l_maj}.{l_min}.{l_sub}.{l_bld:04d}"
                    log_print(f"✨ Full firmware version detected from SystemUpdate: {real_full_ver}")

                if tid_hex == "0100000000000809" and nca_ids:
                    target_nid = nca_ids[0].lower()
                    for cand in nca_files:
                        if basename(cand).lower() == f"{target_nid}.nca":
                            system_version_data_nca = cand
                            log_print(f"🎯 SystemVersion Data NCA found: {basename(cand)}")
                            break

    if system_version_data_nca:
        log_print("--- STEP 2 : RomFS extraction of SystemVersion Data NCA ---")
        tmp_romfs = join(BASE_DIR, f"tmp_romfs_{uuid.uuid4().hex[:8]}")
        try:
            res = run([hactool_path, "-k", keys_path, system_version_data_nca, "--romfsdir", tmp_romfs], stdout=PIPE, stderr=PIPE, timeout=15)
            file_path = join(tmp_romfs, "file")
            raw_data = b""
            if exists(file_path):
                with open(file_path, "rb") as vf:
                    raw_data = vf.read()
            elif exists(tmp_romfs):
                for r, _, fls in os.walk(tmp_romfs):
                    for fl in fls:
                        with open(join(r, fl), "rb") as vf:
                            raw_data += vf.read()
            if raw_data:
                sdk_m = re.search(rb'NintendoSDK Firmware for NX [0-9.-]+', raw_data)
                if sdk_m:
                    sdk_title = sdk_m.group(0).decode("utf-8")
                    sdk_found = True
                    log_print(f"✨ Raw NintendoSDK signature discovered: {sdk_title}")
        except Exception as e:
            log_print(f"RomFS error: {e}")
        finally:
            rmtree(tmp_romfs, ignore_errors=True)
    else:
        log_print("⚠️ Warning: SystemVersion Data NCA not found.")

    if real_full_ver:
        simple_ver = ".".join(real_full_ver.split(".")[:3])
    else:
        base_name = basename(folder_path.rstrip("/\\"))
        ver_match = re.search(r'(\d+\.\d+\.\d+)', base_name)
        simple_ver = ver_match.group(1) if ver_match else "0.0.0"
        real_full_ver = f"{simple_ver}.0000"

    comm_ver = None
    if sdk_title:
        sdk_v_match = re.search(r'NX\s+(\d+\.\d+\.\d+)', sdk_title)
        if sdk_v_match:
            comm_ver = sdk_v_match.group(1)

    if not comm_ver and real_full_ver in GBATEMP_MAPPING:
        comm_ver = GBATEMP_MAPPING[real_full_ver]['disp_ver']

    if not comm_ver:
        comm_ver = ".".join(real_full_ver.split(".")[:3]) if real_full_ver else simple_ver

    if sdk_found and sdk_title and real_full_ver:
        final_line = f"Firmware {comm_ver} ({sdk_title}) ({real_full_ver})"
    elif real_full_ver in GBATEMP_MAPPING:
        final_line = GBATEMP_MAPPING[real_full_ver]['original_line']
    elif real_full_ver:
        final_line = f"Firmware {comm_ver} ({real_full_ver})"
    else:
        final_line = f"Firmware {comm_ver}"

    if real_full_ver in GBATEMP_MAPPING and GBATEMP_MAPPING[real_full_ver].get('suffix'):
        sfx = GBATEMP_MAPPING[real_full_ver]['suffix']
        if sfx and sfx not in final_line:
            final_line = f"{final_line} {sfx}"

    return final_line, sdk_found

def zipdir(src_dir, out_zip):
    src_dir_path = join(BASE_DIR, src_dir)
    out_zip_path = join(BASE_DIR, out_zip)
    log_print(f"Archiving directory {src_dir_path} to {out_zip_path}")
    
    total_files = sum(len(files) for _, _, files in os.walk(src_dir_path))

    with ZipFile(out_zip_path, "w", compression=ZIP_STORED) as zf:
        with tqdm(total=total_files, unit='files', desc=f"Archiving {basename(out_zip)}") as pbar:
            for root, dirs, files in os.walk(src_dir_path):
                dirs.sort()
                for name in sorted(files):
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, start=src_dir_path) 
                    
                    os.utime(full, (1780315200, 1780315200))
                    
                    zinfo = ZipInfo.from_file(full, arcname=rel)
                    zinfo.date_time = (2026, 1, 1, 0, 0, 0)
                    zinfo.create_system = 0
                    zinfo.external_attr = 0 
                    zinfo.compress_type = ZIP_STORED
                    
                    with open(full, 'rb') as f:
                        zf.writestr(zinfo, f.read())
                    pbar.update(1)

class NSPRepacker:
    def __init__(self, out_path, file_map):
        self.path = out_path
        self.file_map = file_map
        self.sorted_files = []
        self.expected_total_size = 0
        
    def _sort_pfs0_order(self):
        order_list = []
        order_keys = ["tik", "cert", "meta_nca", 1, 3, 5, 4, 2]
        for key in order_keys:
            if key in self.file_map:
                items = self.file_map[key]
                if isinstance(items, list) and items:
                    order_list.extend(sorted(items, key=lambda x: basename(x)))
        self.sorted_files = order_list

    def repack(self):
        self._sort_pfs0_order()
        log_print(f"Compiling {len(self.sorted_files)} components into rigorous PFS0 archive...")
        log_print(f"PFS0 Canonical Write Order Enforced: {[basename(f) for f in self.sorted_files]}")
        
        for f_path in self.sorted_files:
            ensure_readable(f_path)
            
        hd = self._gen_header()
        self.expected_total_size = len(hd) + sum(getsize(file) for file in self.sorted_files)
        
        log_print(f"Calculated target container size: {self.expected_total_size} bytes.")
        
        if exists(self.path) and getsize(self.path) == self.expected_total_size:
            log_print(f"NSP {basename(self.path)} already exists and matches expected size.")
            return self.path
            
        with open(self.path, 'wb') as outf:
            outf.write(hd)
            with tqdm(total=sum(getsize(f) for f in self.sorted_files), unit='B', unit_scale=True, desc="Writing NSP", leave=False) as pbar:
                for file in self.sorted_files:
                    with open(file, 'rb') as inf:
                        while True:
                            buf = inf.read(4096 * 1024)
                            if not buf:
                                break
                            outf.write(buf)
                            pbar.update(len(buf))
        log_print("Local PFS0 Write Complete.")
        return self.path

    def verify_integrity(self):
        log_print(f"Deep Integrity Audit for {basename(self.path)}...")
        ensure_readable(self.path)
        try:
            with open(self.path, "rb") as f:
                magic = f.read(4)
                log_print(f"Integrity Audit: Read Magic Bytes -> {magic}")
                if magic != b'PFS0':
                    return False
                file_count = unpack('<I', f.read(4))[0]
                log_print(f"Integrity Audit: File Count -> {file_count} (Expected: {len(self.sorted_files)})")
                if file_count != len(self.sorted_files):
                    return False
                string_table_size = unpack('<I', f.read(4))[0]
                log_print(f"Integrity Audit: Raw String Table Size -> {string_table_size} bytes")
                f.read(4)
                header_size = 0x10 + (file_count * 0x18) + string_table_size
                log_print(f"Integrity Audit: Computed Header Boundary -> {header_size} bytes")
                
                for i in range(file_count):
                    offset = unpack('<Q', f.read(8))[0]
                    size = unpack('<Q', f.read(8))[0]
                    name_offset = unpack('<I', f.read(4))[0]
                    f.read(4)
                    if name_offset >= string_table_size:
                        log_print(f"Integrity Audit: String offset out of bounds on file index {i}.")
                        return False
                    if (header_size + offset + size) > self.expected_total_size:
                        log_print(f"Integrity Audit: OOB Exception. File index {i} bounds exceed expected archive EOF.")
                        return False
                        
                f.seek(0, 2)
                actual_size = f.tell()
                if actual_size != self.expected_total_size:
                    log_print(f"Integrity Audit: EOF Mismatch. Got {actual_size}, Expected {self.expected_total_size}.")
                    return False
                    
            log_print("PFS0 Container mathematically verified (Magic, Structure, Boundaries, and EOF).")
            return True
        except Exception as e:
            log_print(f"Integrity Audit Exception: {e}")
            return False
            
    def _gen_header(self):
        files_nb = len(self.sorted_files)
        string_table = b'\x00'.join(basename(file).encode('utf-8') for file in self.sorted_files) + b'\x00'
        
        raw_header_size = 0x10 + files_nb * 0x18 + len(string_table)
        remainder = (0x10 - (raw_header_size % 0x10)) % 0x10
        padded_string_table_size = len(string_table) + remainder
        
        log_print(f"Generating Header | Files: {files_nb}, StringTable Size: {len(string_table)}, Padding: {remainder} bytes.")
        
        file_sizes = [getsize(file) for file in self.sorted_files]
        file_offsets = [sum(file_sizes[:n]) for n in range(files_nb)]
        file_names_lengths = [len(basename(file).encode('utf-8')) + 1 for file in self.sorted_files]
        string_table_offsets = [sum(file_names_lengths[:n]) for n in range(files_nb)]
        
        header = b'PFS0'
        header += pack('<I', files_nb)
        header += pack('<I', padded_string_table_size)
        header += b'\x00\x00\x00\x00'
        for n in range(files_nb):
            header += pack('<Q', file_offsets[n])
            header += pack('<Q', file_sizes[n])
            header += pack('<I', string_table_offsets[n])
            header += b'\x00\x00\x00\x00'
        header += string_table
        header += remainder * b'\x00'
        return header

class FirmwareDownloader:
    def __init__(self, device_id: str, ver_string_full: str):
        self.device_id = device_id
        self.ver_string_full = ver_string_full
        self.user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{self.device_id}; eid:{ENV})"
        
        parts = list(map(int, self.ver_string_full.split(".")))
        if len(parts) == 3: parts.append(0) 
        self.ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]
        self.ver_string_simple = f"{parts[0]}.{parts[1]}.{parts[2]}"

        if self.ver_string_full in GBATEMP_MAPPING:
            self.disp_ver = GBATEMP_MAPPING[self.ver_string_full]['disp_ver']
            self.original_line = GBATEMP_MAPPING[self.ver_string_full]['original_line']
        else:
            self.disp_ver = self.ver_string_simple
            self.original_line = f"Firmware {self.ver_string_simple} (NintendoSDK Firmware for NX {self.ver_string_simple}-1.0) ({self.ver_string_full})"
            
        if args.displayversion:
            self.ver_dir = f"Firmware {self.disp_ver}"
        else:
            self.ver_dir = f"Firmware {self.ver_string_full}"
            
        self.update_files = []
        self.update_dls = []
        self.sv_nca_fat = ""
        self.sv_nca_exfat = ""
        self.seen_titles = set()
        self.queued_ncas = set()
        self.nca_to_tid = {}
        self.expected_sizes = {}
        self.session = requests.Session()
        self.pfs0_map = {
            "tik": [], "cert": [], "meta_nca": [], "meta_xml": [],
            1: [], 2: [], 3: [], 4: [], 5: [], 6: []
        }
        self.init_error = False
        self.skip = False
        self.hash_failed = False
        self.is_cached = False
        self.sdk_found = False
        self.exact_sdk_line = None

    def dltitle(self, title_id: str, version: int, is_su: bool = False):
        key = (title_id, version, is_su)
        if key in self.seen_titles:
            return
        self.seen_titles.add(key)

        p = "s" if is_su else "a"
        full_ver_dir = join(BASE_DIR, self.ver_dir)
        makedirs(full_ver_dir, exist_ok=True)

        if LOCAL_ONLY:
            if title_id.lower() == "010000000000081b" and not glob(join(full_ver_dir, "*.nca")):
                 self.sv_nca_exfat = ""
            return

        try:
            cnmt_id = nin_request(
                "HEAD",
                f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={self.device_id}",
                self.user_agent,
                session=self.session
            ).headers["X-Nintendo-Content-ID"]
            log_print(f"Resolved CNMT ID for title {title_id} v{version}: {cnmt_id}")
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                if not args.allversion: print(f"INFO: Title {title_id} version {version} not found (404).")
                if title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = ""
                return
            raise

        cnmt_nca = join(full_ver_dir, f"{cnmt_id}.cnmt.nca")
        self.update_files.append(cnmt_nca)
        self.pfs0_map["meta_nca"].append(cnmt_nca)
        
        dlfile(
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={self.device_id}",
            cnmt_nca,
            self.user_agent,
            session=self.session,
            silent=True
        )

        cnmt_title_id, entries, is_su_type = parse_cnmt(cnmt_nca)

        if exists(cnmt_nca):
            self.expected_sizes[f"{cnmt_id}.cnmt.nca"] = getsize(cnmt_nca)
        else:
            self.expected_sizes[f"{cnmt_id}.cnmt.nca"] = 0
            
        self.update_dls.append((
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={self.device_id}",
            self.ver_dir,
            f"{cnmt_id}.cnmt.nca",
            ""
        ))

        if is_su_type:
            log_print(f"CNMT {cnmt_id} identified as SystemUpdate. Queueing dependencies...")
            for t_id, ver, _, _ in entries:
                self.dltitle(t_id, ver, is_su=False)
        else:
            log_print(f"CNMT {cnmt_id} identified as Data. Queueing {len(entries)} NCAs...")
            for nca_id, nca_hash, entry_type, nca_size in entries:
                self.nca_to_tid[nca_id] = cnmt_title_id
                self.expected_sizes[f"{nca_id}.nca"] = nca_size
                if cnmt_title_id.lower() == "0100000000000809" and entry_type in (1, 2):
                    self.sv_nca_fat = f"{nca_id}.nca"
                elif cnmt_title_id.lower() == "010000000000081b" and entry_type in (1, 2):
                    self.sv_nca_exfat = f"{nca_id}.nca"

                if nca_id not in self.queued_ncas:
                    self.queued_ncas.add(nca_id)
                    nca_path = join(full_ver_dir, f"{nca_id}.nca")
                    self.update_files.append(nca_path)
                    if entry_type in self.pfs0_map:
                        self.pfs0_map[entry_type].append(nca_path)
                        
                    self.update_dls.append((
                        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={self.device_id}",
                        self.ver_dir,
                        f"{nca_id}.nca",
                        nca_hash
                    ))

def extract_version_order(game_data):
    name = game_data.get('name', '')
    match = re.search(r'Firmware\s+(\d+(?:\.\d+)+)', name)
    if match:
        v_parts = [int(p) for p in match.group(1).split('.')]
        while len(v_parts) < 3:
            v_parts.append(0)
    else:
        v_parts = [0, 0, 0]

    name_lower = name.lower()
    if "-pre" in name_lower or "(pre)" in name_lower:
        sub = -2
    elif "card" in name_lower or "cartridge" in name_lower:
        sub = -1
    elif "rebootless" in name_lower:
        rm = re.search(r'rebootless(?:\s*update)?\s*(\d+)', name_lower)
        sub = int(rm.group(1)) if rm else 1
    else:
        sub = 0

    raw_match = re.search(r'\((\d+\.\d+\.\d+\.\d{4})\)', name)
    raw_val = raw_match.group(1) if raw_match else ""

    return (*v_parts, sub, raw_val)

def sync_datfile_from_releases():
    log_print("Starting automated DATfile synchronization from GitHub releases...")
    get_gbatemp_firmwares()

    dat_files = glob(join(BASE_DIR, "Nintendo*Nintendo Switch Firmware (*)*.dat"))
    existing_games = {}

    for old_dat in dat_files:
        try:
            tree = ET.parse(old_dat)
            root = tree.getroot()
            for game_elem in root.findall('game'):
                g_name = game_elem.get('name')
                roms = []
                for rom_elem in game_elem.findall('rom'):
                    roms.append({
                        'name': rom_elem.get('name'),
                        'size': rom_elem.get('size'),
                        'crc': rom_elem.get('crc'),
                        'md5': rom_elem.get('md5'),
                        'sha1': rom_elem.get('sha1')
                    })
                existing_games[g_name] = {'name': g_name, 'roms': roms}
        except Exception as e:
            log_print(f"Failed to parse existing DAT file {old_dat}: {e}")

    print(f"INFO: Loaded {len(existing_games)} existing firmware entry/entries from local DAT file(s).")

    try:
        cmd = ["gh", "release", "list", "-L", "1000", "--json", "tagName", "--jq", ".[].tagName"]
        res = run(cmd, stdout=PIPE, stderr=PIPE, text=True)
        if res.returncode != 0:
            print(f"ERROR: Failed to retrieve release list via gh CLI: {res.stderr.strip()}")
            sys.exit(1)
        release_tags = [t.strip() for t in res.stdout.splitlines() if t.strip()]
    except Exception as e:
        print(f"ERROR: Exception executing gh command: {e}")
        sys.exit(1)

    print(f"INFO: Found {len(release_tags)} release(s) on GitHub.")

    for tag in release_tags:
        clean_v = tag.replace("-card", "").replace("-pre", "")
        found_key = None

        for g_name in existing_games.keys():
            if f"({clean_v})" in g_name or f"Firmware {tag}" in g_name:
                found_key = g_name
                break

        if found_key and len(existing_games[found_key]['roms']) > 0:
            log_print(f"Release {tag} already present in DAT as '{found_key}'. Skipping download.")
            continue

        target_zip_name = f"Firmware.{tag}.zip"
        print(f"\n[DAT] Missing release in DAT: {tag}. Downloading {target_zip_name}...")
        tmp_dl_dir = join(BASE_DIR, f"tmp_dat_{uuid.uuid4().hex[:8]}")
        makedirs(tmp_dl_dir, exist_ok=True)
        try:
            dl_cmd = ["gh", "release", "download", tag, "-p", target_zip_name, "--dir", tmp_dl_dir, "--clobber"]
            res = run(dl_cmd, stdout=PIPE, stderr=PIPE, text=True)
            if res.returncode != 0:
                print(f"WARNING: Could not download {target_zip_name} for release {tag}: {res.stderr.strip()}")
                continue

            zip_file = join(tmp_dl_dir, target_zip_name)
            if not exists(zip_file):
                print(f"WARNING: {target_zip_name} not found in download directory.")
                continue

            extract_folder = join(tmp_dl_dir, "extracted")
            makedirs(extract_folder, exist_ok=True)
            with ZipFile(zip_file, 'r') as zf:
                zf.extractall(extract_folder)

            nca_files = []
            for root, _, files in os.walk(extract_folder):
                for f in files:
                    if f.endswith(".nca"):
                        nca_files.append(join(root, f))

            if not nca_files:
                print(f"WARNING: No NCA files found in archive for release {tag}.")
                continue

            current_roms = []
            with tqdm(total=len(nca_files), unit='file', desc=f"Hashing NCAs for {tag}") as pbar:
                for nca in sorted(nca_files, key=basename):
                    md5_h = hashlib.md5()
                    sha1_h = hashlib.sha1()
                    crc_val = 0
                    sz = getsize(nca)
                    with open(nca, "rb") as f:
                        for chunk in iter(lambda: f.read(1048576), b""):
                            md5_h.update(chunk)
                            sha1_h.update(chunk)
                            crc_val = zlib.crc32(chunk, crc_val)
                    current_roms.append({
                        'name': basename(nca),
                        'size': str(sz),
                        'crc': "%08x" % (crc_val & 0xFFFFFFFF),
                        'md5': md5_h.hexdigest(),
                        'sha1': sha1_h.hexdigest()
                    })
                    pbar.update(1)

            identity_line, _ = find_firmware_identity(extract_folder)
            if identity_line:
                resolved_name = identity_line
                if "-pre" in tag.lower() and "pre" not in resolved_name.lower():
                    resolved_name = f"{resolved_name} (pre)"
                elif "-card" in tag.lower() and "card" not in resolved_name.lower() and "cartridge" not in resolved_name.lower():
                    resolved_name = f"{resolved_name} (cartridge)"
            else:
                resolved_name = f"Firmware {tag}"
                if clean_v in GBATEMP_MAPPING:
                    resolved_name = GBATEMP_MAPPING[clean_v]['original_line']

            existing_games[resolved_name] = {'name': resolved_name, 'roms': current_roms}
            print(f"[DAT] Added '{resolved_name}' with {len(current_roms)} NCAs.")
        finally:
            if exists(tmp_dl_dir):
                rmtree(tmp_dl_dir, ignore_errors=True)

    sorted_games = sorted(existing_games.values(), key=extract_version_order, reverse=False)

    def escape_xml(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")

    timestamp_disp = time.strftime("%Y%m%d%H%M%S")

    xml_lines = []
    xml_lines.append('<?xml version="1.0"?>')
    xml_lines.append('<!DOCTYPE datafile PUBLIC "' + chr(45) + '//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/Dats/datafile.dtd">')
    xml_lines.append('<datafile>')
    xml_lines.append('    <header>')
    xml_lines.append('        <name>Nintendo ' + chr(45) + ' Nintendo Switch Firmware</name>')
    xml_lines.append('        <description>Nintendo ' + chr(45) + ' Nintendo Switch Firmware</description>')
    xml_lines.append(f'        <version>{timestamp_disp}</version>')
    xml_lines.append('        <author>Twitter: @JeremKOYTB</author>')
    xml_lines.append('        <comment>DAT generated by firmware_downloader.py. Inspired by the work of 8BitWonder to help him better archive this!</comment>')
    xml_lines.append('        <homepage>gbatemp.net</homepage>')
    xml_lines.append('        <url>https://gbatemp.net/download/nintendo' + chr(45) + 'switch' + chr(45) + 'firmware' + chr(45) + 'datfile.36558/</url>')
    xml_lines.append('    </header>')

    for game in sorted_games:
        game_name = escape_xml(game['name'])
        xml_lines.append(f'    <game name="{game_name}">')
        xml_lines.append(f'        <category>Games</category>')
        xml_lines.append(f'        <description>{game_name}</description>')
        for rom in game['roms']:
            r_name = escape_xml(rom['name'])
            r_size = rom['size']
            r_crc = rom['crc']
            r_md5 = rom['md5']
            r_sha1 = rom['sha1']
            xml_lines.append(f'        <rom name="{r_name}" size="{r_size}" crc="{r_crc}" md5="{r_md5}" sha1="{r_sha1}"/>')
        xml_lines.append('    </game>')

    xml_lines.append('</datafile>')

    new_dat_name = f"Nintendo - Nintendo Switch Firmware ({len(sorted_games)}) ({timestamp_disp}).dat"
    with open(join(BASE_DIR, new_dat_name), "w", encoding="utf-8") as f:
        f.write("\n".join(xml_lines) + "\n")

    for old_dat in dat_files:
        if basename(old_dat) != new_dat_name:
            try:
                remove(old_dat)
            except Exception:
                pass

    print(f"\n✅ DATfile successfully generated at repository root: {new_dat_name} ({len(sorted_games)} registered firmware(s)).")


if __name__ == "__main__":
    log_print(f"Script launched with arguments: {sys.argv}")

    if args.sync_releases:
        sync_datfile_from_releases()
        sys.exit(0)

    if args.allversion or args.displayversion or args.datfile:
        get_gbatemp_firmwares()

    if os.name == 'nt' and not exists(HACTOOL_PATH):
        print("INFO: hactool.exe not found. Downloading automatically...")
        hactool_url = "https://github.com/SciresM/hactool/releases/download/1.4.0/hactool-1.4.0-win.zip"
        try:
            log_print(f"Downloading hactool from {hactool_url}")
            resp = requests.get(hactool_url)
            resp.raise_for_status()
            with ZipFile(io.BytesIO(resp.content)) as z:
                with open(HACTOOL_PATH, "wb") as f:
                    f.write(z.read("hactool.exe"))
            print("INFO: hactool.exe successfully retrieved and extracted.")
            print("INFO: Restarting script to apply changes...")
            run([sys.executable] + sys.argv)
            sys.exit(0)
        except Exception as e:
            print(f"CRITICAL ERROR: Failed to download hactool.exe: {e}")
            sys.exit(1)

    cert_path = join(BASE_DIR, "certificat.pem")
    if not exists(cert_path):
        print(f"File 'certificat.pem' not found in {BASE_DIR}.")
        sys.exit(1)

    with open(cert_path, "r", encoding="utf8") as f:
        pem_text = f.read()

    cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_text, re.DOTALL)
    key_match = re.search(r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----", pem_text, re.DOTALL)

    if not cert_match or not key_match:
        print("ERROR: Invalid certificat.pem structure.")
        sys.exit(1)

    makedirs(KEYS_DIR, exist_ok=True)

    with open(join(KEYS_DIR, "switch_client.crt"), "w", encoding="utf8") as crt_f:
        crt_f.write(cert_match.group(0) + "\n")

    with open(join(KEYS_DIR, "switch_client.key"), "w", encoding="utf8") as key_f:
        key_f.write(key_match.group(0) + "\n")

    prod_keys_path = join(BASE_DIR, "prod.keys")
    if not exists(prod_keys_path):
        print(f"File 'prod.keys' not found in {BASE_DIR}.")
        sys.exit(1)

    prod_keys = ConfigParser(strict=False)
    with open(prod_keys_path) as f:
        prod_keys.read_string("[keys]\n" + f.read())

    prodinfo_path = join(BASE_DIR, "PRODINFO.bin")
    if not exists(prodinfo_path):
        print(f"File 'PRODINFO.bin' not found in {BASE_DIR}.")
        sys.exit(1)

    with open(prodinfo_path, "rb") as pf:
        prod_data = pf.read()

    if prod_data[:4] == b"CAL0":
        decrypted_prod = prod_data
        log_print("PRODINFO loaded and determined to be already decrypted.")
    else:
        log_print("PRODINFO is encrypted. Attempting to decrypt using bis_key_00...")
        bis_key_00_hex = prod_keys.get("keys", "bis_key_00", fallback=None)
        if not bis_key_00_hex:
            print("PRODINFO is encrypted but bis_key_00 is missing from prod.keys!")
            sys.exit(1)

        bis_key_00 = bytes.fromhex(bis_key_00_hex.strip())
        sector_size = 0x4000
        decrypted_prod = bytearray()
        backend = default_backend()

        for i in range(0, len(prod_data), sector_size):
            chunk = prod_data[i:i+sector_size]
            if len(chunk) < 16:
                decrypted_prod += chunk
                continue

            tweak = (i // sector_size).to_bytes(16, 'little')
            cipher = Cipher(algorithms.AES(bis_key_00), modes.XTS(tweak), backend=backend)
            decryptor = cipher.decryptor()
            decrypted_prod += decryptor.update(chunk)

        decrypted_prod = bytes(decrypted_prod)

    if decrypted_prod[:4] != b"CAL0":
        print("Invalid PRODINFO (Decryption failed or invalid header)!")
        sys.exit(1)

    device_id = decrypted_prod[0x2b56 : 0x2b56 + 0x10].decode("utf-8").strip('\x00')
    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"
    global_session = requests.Session()
    log_print(f"Using Device ID: {device_id} with User-Agent: {user_agent}")

    latest_ver_full = ""
    latest_ver_raw = 0

    if VERSION == "" or args.allversion:
        try:
            log_print("Querying Nintendo server for the latest firmware version...")
            su_meta = nin_request(
                "GET",
                f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}",
                user_agent,
                session=global_session
            ).json()
            latest_ver_raw = su_meta["system_update_metas"][0]["title_version"]
            l_major = latest_ver_raw // 0x4000000
            l_minor = (latest_ver_raw - l_major*0x4000000) // 0x100000
            l_sub1  = (latest_ver_raw - l_major*0x4000000 - l_minor*0x100000) // 0x10000
            l_build = latest_ver_raw % 0x10000
            latest_ver_full = f"{l_major}.{l_minor}.{l_sub1}.{l_build:04d}"
            log_print(f"Latest version fetched from Nintendo: {latest_ver_full} (Raw: {latest_ver_raw})")
        except Exception as e:
            log_print(f"Failed to fetch latest version from Nintendo: {e}")
            latest_ver_full = ""

    versions_to_process = []

    if args.allversion:
        for full_v in GBATEMP_MAPPING.keys():
            versions_to_process.append(full_v)
        versions_to_process = list(dict.fromkeys(versions_to_process))
        v_count = len(versions_to_process)
        print(f"INFO: Found {v_count} version{'s' if v_count > 1 else ''} to process.")

        if latest_ver_full and latest_ver_full not in versions_to_process:
            print(f"WARNING: The latest firmware ({latest_ver_full}) is missing from the GBATemp list. The list might be outdated.")
    else:
        if VERSION == "":
            print("INFO: No version specified, searching for the latest version...")
            if LOCAL_ONLY:
                print("ERROR: Cannot determine latest version in LOCAL_ONLY mode.")
                sys.exit(1)
            if not latest_ver_full:
                print("ERROR: Failed to retrieve the latest version from Nintendo.")
                sys.exit(1)
            versions_to_process = [latest_ver_full]
        else:
            versions_to_process = [VERSION]

    def prepare_downloader(device_id_val, ua_val, v_string, sess):
        parts = list(map(int, v_string.split(".")))
        if len(parts) == 3: parts.append(0) 
        ver_raw_val = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]

        log_print(f"Preparing Downloader for version {v_string} (Raw: {ver_raw_val})")
        dl = FirmwareDownloader(device_id_val, v_string)
        dl.session = sess
        dl.user_agent = ua_val
        dl.ver_raw = ver_raw_val

        try:
            log_print(f"Initiating metadata fetch for {v_string}...")
            dl.dltitle("0100000000000816", ver_raw_val, is_su=True)
            if not dl.sv_nca_exfat:
                dl.dltitle("010000000000081b", ver_raw_val, is_su=False)
        except Exception as e:
            log_print(f"Network initialization failed for {v_string}: {e}")
            dl.init_error = True
        return dl

    downloaders = []

    if args.allversion:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for v in versions_to_process:
                futures.append(executor.submit(prepare_downloader, device_id, user_agent, v, global_session))
            with tqdm(total=len(futures), unit='version', desc="Preparing metadata") as pbar:
                for future in as_completed(futures):
                    dl_res = future.result()
                    downloaders.append(dl_res)
                    pbar.set_postfix_str(f"Processing: {dl_res.ver_string_full}")
                    pbar.update(1)
    else:
        dl_single = prepare_downloader(device_id, user_agent, versions_to_process[0], global_session)
        downloaders.append(dl_single)
        if LOCAL_ONLY:
            print(f"\nINFO: LOCAL mode enabled. Analyzing local files for {format_fw_list_name(dl_single.ver_string_full)}")
        else:
            print(f"\nDownloading {format_fw_list_name(dl_single.ver_string_full)}. Folder: {dl_single.ver_dir}")
            if not dl_single.sv_nca_exfat and not dl_single.is_cached:
                print("INFO: exFAT not found via meta, direct attempt 010000000000081b...")
                if not dl_single.sv_nca_exfat:
                    print("INFO: No separate SystemVersion exFAT found for this firmware version.")

    def get_version_tuple(dl_obj):
        p = list(map(int, dl_obj.ver_string_full.split(".")))
        return tuple(p) if len(p) == 4 else (*p, 0)

    downloaders.sort(key=get_version_tuple)

    valid_queued = []
    missing_firmwares = []
    total_bytes = 0
    total_missing_bytes = 0

    for dl in downloaders:
        ver_dir_path = join(BASE_DIR, dl.ver_dir)
        if LOCAL_ONLY and exists(ver_dir_path):
            local_ncas = glob(join(ver_dir_path, "*.nca"))
            for f in local_ncas:
                dl.expected_sizes[basename(f)] = getsize(f)
                if f not in dl.update_files:
                    dl.update_files.append(f)

        dl_size = sum(dl.expected_sizes.values())
        if dl.init_error or dl_size <= 52428800:
            missing_firmwares.append(dl.ver_string_full)
            dl.skip = True
        else:
            valid_queued.append(dl)
            if exists(ver_dir_path) and not LOCAL_ONLY:
                expected_names = {basename(p) for p in dl.update_files}
                for f in os.listdir(ver_dir_path):
                    full_f = join(ver_dir_path, f)
                    if os.path.isfile(full_f) and f not in expected_names:
                        try:
                            os.remove(full_f)
                            log_print(f"Removed unknown or obsolete file: {full_f}")
                        except Exception:
                            pass

            if not LOCAL_ONLY:
                total_bytes += dl_size
                for url, dirc, fname, expected_hash in dl.update_dls:
                    fpath = join(BASE_DIR, dirc, fname)
                    if not exists(fpath) or getsize(fpath) != dl.expected_sizes.get(fname, 0):
                        total_missing_bytes += dl.expected_sizes.get(fname, 0)

    if not LOCAL_ONLY:
        v_count = len(valid_queued)
        if valid_queued:
            if v_count == 1:
                print("\nINFO: Firmware queued for download:")
            else:
                print("\nINFO: Firmwares queued for download:")

            for dl in valid_queued:
                dl_size = sum(dl.expected_sizes.values())
                print(f" * {format_fw_list_name(dl.ver_string_full)} (approx. {dl_size / 1048576:.2f} MB, {len(dl.update_files)} files)")

        if missing_firmwares:
            m_count = len(missing_firmwares)
            if m_count == 1:
                print("\nINFO: The following firmware is unavailable or incomplete (<= 50MB) on Nintendo's servers:")
            else:
                print("\nINFO: The following firmwares are unavailable or incomplete (<= 50MB) on Nintendo's servers:")

            for f in missing_firmwares:
                print(f" * {format_fw_list_name(f)}")

            if m_count == 1:
                print("This firmware cannot be downloaded because it either originates from a game cartridge (not available digitally) or was removed by Nintendo.")
            else:
                print("These firmwares cannot be downloaded because they either originate from game cartridges (not available digitally) or were removed by Nintendo.")

        if total_bytes == 0:
            if v_count == 1:
                print("\nINFO: No available firmware to download.")
            else:
                print("\nINFO: No available firmwares to download.")
            sys.exit(0)

        total_bytes_str = f"{total_bytes / 1073741824:.2f} GB" if total_bytes >= 1073741824 else f"{total_bytes / 1048576:.2f} MB"
        missing_bytes_str = f"{total_missing_bytes / 1073741824:.2f} GB" if total_missing_bytes >= 1073741824 else f"{total_missing_bytes / 1048576:.2f} MB"

        if total_missing_bytes == total_bytes:
            if v_count == 1:
                print(f"\nINFO: Total size to download: {total_bytes_str}")
            else:
                print(f"\nINFO: Total size to download: {total_bytes_str}")
        elif total_missing_bytes == 0:
            if v_count == 1:
                print(f"\nINFO: Total size: {total_bytes_str}. The firmware is already fully downloaded locally.")
            else:
                print(f"\nINFO: Total size: {total_bytes_str}. All firmwares are already fully downloaded locally.")
        else:
            if v_count == 1:
                print(f"\nINFO: Total size: {total_bytes_str}")
            else:
                print(f"\nINFO: Total size: {total_bytes_str}")
            print(f"INFO: Remaining data to download: {missing_bytes_str}")

        if args.allversion and total_missing_bytes > 0:
            proceed = get_user_choice("Do you want to proceed? [y/N]: ")
            if proceed not in ['y', 'yes', 'true']:
                print("Aborted.")
                sys.exit(1)

        if total_missing_bytes > 0:
            try:
                free_space = disk_usage(BASE_DIR).free
                if free_space < total_missing_bytes:
                    free_space_str = f"{free_space / 1073741824:.2f} GB" if free_space >= 1073741824 else f"{free_space / 1048576:.2f} MB"
                    print(f"\nWARNING: Not enough free disk space detected. Need {missing_bytes_str}, but only {free_space_str} available.")
                    if args.allversion:
                        choice = get_user_choice("Do you want to continue anyway? [y/N]: ")
                        if choice not in ['y', 'yes', 'true']:
                            print("Aborted by user.")
                            sys.exit(1)
                    else:
                        print("Proceeding anyway as requested for single firmware.")
            except Exception:
                print("\nWARNING: Could not verify free disk space.")
                print("Downloads will proceed, but please ensure you have enough available storage.")

    master_dltable = []
    for dl in valid_queued:
        if not dl.skip:
            for url, dirc, fname, expected_hash in dl.update_dls:
                fpath = join(BASE_DIR, dirc, fname)
                if not exists(fpath) or getsize(fpath) != dl.expected_sizes.get(fname, 0):
                    master_dltable.append((url, dirc, fname, expected_hash))

    if master_dltable and not LOCAL_ONLY:
        dlfiles(master_dltable, user_agent)

    for dl in valid_queued:
        if dl.skip: continue
        ver_dir_path = join(BASE_DIR, dl.ver_dir)
        total_size = 0
        if exists(ver_dir_path):
            total_size = sum(getsize(join(ver_dir_path, f)) for f in os.listdir(ver_dir_path) if os.path.isfile(join(ver_dir_path, f)))

        if total_size <= 52428800:
            if not args.allversion: print(f"\nCRITICAL: {format_fw_list_name(dl.ver_string_full)} is incomplete (<= 50MB). Cleaning up and aborting.")
            dl.skip = True
            rmtree(ver_dir_path, ignore_errors=True)
            if not args.allversion: sys.exit(0)
            continue

        size_mismatch = False
        for fpath in dl.update_files:
            fname = basename(fpath)
            if not exists(fpath):
                size_mismatch = True
            elif fname in dl.expected_sizes:
                if getsize(fpath) != dl.expected_sizes[fname]:
                    size_mismatch = True

        if size_mismatch and not LOCAL_ONLY:
            if not args.allversion: print(f"\nCRITICAL: {format_fw_list_name(dl.ver_string_full)} has corrupted files (size mismatch). Cleaning up and aborting.")
            dl.skip = True
            rmtree(ver_dir_path, ignore_errors=True)
            if not args.allversion: sys.exit(0)
            continue

        fixed_time = 1780315200
        for fpath in glob(join(BASE_DIR, dl.ver_dir, "*")):
            if exists(fpath):
                os.utime(fpath, (fixed_time, fixed_time))

    if not args.allversion and not LOCAL_ONLY: print("\nINFO: Starting detailed verification of NCA hashes...")

    while True and not LOCAL_ONLY:
        failed_dls_tuples = []
        for dl in valid_queued:
            if dl.skip: continue
            dl.hash_failed = False
            for url, dirc, fname, expected_hash in dl.update_dls:
                fpath = join(BASE_DIR, dirc, fname)
                if exists(fpath):
                    if expected_hash == "":
                        continue
                    ensure_readable(fpath)
                    h = hashlib.sha256()
                    with open(fpath, "rb") as f:
                        for chunk in iter(lambda: f.read(1048576), b""):
                            h.update(chunk)
                    actual_hash = h.hexdigest()
                    if actual_hash != expected_hash:
                        if not args.allversion:
                            print(f"[ERROR] {fname}\n          Expected : {expected_hash}\n          Actual   : {actual_hash}")
                        failed_dls_tuples.append((url, dirc, fname, expected_hash))
                        dl.hash_failed = True
                else:
                    if not args.allversion: print(f"[MISSING] {fname}")
                    failed_dls_tuples.append((url, dirc, fname, expected_hash))
                    dl.hash_failed = True

        if not failed_dls_tuples:
            if not args.allversion: print("INFO: All files successfully verified against CNMT records.")
            break

        print(f"\nWARNING: {len(failed_dls_tuples)} files failed hash verification.")
        choice_text = f"Do you want to [R]etry downloading them, [S]kip affected firmware{'s' if len(failed_dls_tuples) > 1 else ''}, or [A]bort? [r/s/a]: "
        choice = get_user_choice(choice_text)
        if choice in ['r', 'retry']:
            dlfiles(failed_dls_tuples, user_agent)
        elif choice in ['s', 'skip']:
            for dl in valid_queued:
                if dl.hash_failed:
                    dl.skip = True
                    rmtree(join(BASE_DIR, dl.ver_dir), ignore_errors=True)
            break
        else:
            print("Aborting.")
            sys.exit(1)

    final_downloaders = [dl for dl in valid_queued if not dl.skip]

    if not final_downloaders:
        if len(downloaders) == 1:
            print("INFO: No valid firmware remaining to process.")
        else:
            print("INFO: No valid firmwares remaining to process.")
        sys.exit(0)

    for dl in final_downloaders:
        ver_dir_path = join(BASE_DIR, dl.ver_dir)
        if exists(ver_dir_path):
            real_identity, sdk_found = find_firmware_identity(ver_dir_path)
            if real_identity:
                dl.original_line = real_identity
            dl.sdk_found = sdk_found
            if sdk_found:
                dl.exact_sdk_line = real_identity
                log_print(f"Exact firmware identity extracted directly from binaries: {real_identity}")
            else:
                dl.exact_sdk_line = None
                log_print("RomFS signature could not be extracted (missing keys or title). SDK line omitted.")

    if LOCAL_ONLY:
        for dl in final_downloaders:
            ver_dir_path = join(BASE_DIR, dl.ver_dir)
            if exists(ver_dir_path):
                for nca_file in glob(join(ver_dir_path, "*.nca")):
                    try:
                        cnmt_title_id, entries, is_su_type = parse_cnmt(nca_file)
                        if cnmt_title_id and nca_file not in dl.pfs0_map["meta_nca"]:
                            dl.pfs0_map["meta_nca"].append(nca_file)
                        if not is_su_type:
                            for nid, h, entry_type, nca_size in entries:
                                dl.nca_to_tid[nid] = cnmt_title_id
                                if cnmt_title_id.lower() == "0100000000000809" and entry_type in (1, 2):
                                    dl.sv_nca_fat = f"{nid}.nca"
                                elif cnmt_title_id.lower() == "010000000000081b" and entry_type in (1, 2):
                                    dl.sv_nca_exfat = f"{nid}.nca"
                                nca_path = join(ver_dir_path, f"{nid}.nca")
                                if entry_type in dl.pfs0_map and exists(nca_path):
                                    if nca_path not in dl.pfs0_map[entry_type]:
                                        dl.pfs0_map[entry_type].append(nca_path)
                    except Exception:
                        pass
                mapped = set(dl.pfs0_map["meta_nca"])
                for t in [1, 2, 3, 4, 5, 6]: mapped.update(dl.pfs0_map[t])
                for nca in glob(join(ver_dir_path, "*.nca")):
                    if nca not in mapped: dl.pfs0_map[1].append(nca)

    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    if is_ci:
        if FORCE_BUILD_NSP:
            print("\nINFO: NSP creation AUTHORIZED (Requested via GitHub Actions).")
            nsp_choice = "y"
        else:
            print("\nINFO: NSP creation IGNORED (Optional, not checked in GitHub Actions).")
            nsp_choice = "n"
    else:
        nsp_choice = get_user_choice("\nDo you want to pack the raw files into an NSP? (For experimentation purposes only. !!DO NOT INSTALL ON ACTUAL HARDWARE!!) [y/N]: ")

    for dl in final_downloaders:
        out_zip = f"{dl.ver_dir}.zip"
        out_zip_path = join(BASE_DIR, out_zip)
        dl.zip_sha256 = ""

        if LOCAL_ONLY:
            if not args.allversion: print("\nINFO: LOCAL mode enabled. Archiving ignored to keep the original files intact.")
            dl.zip_sha256 = "LOCAL_MODE_KEEP_HASH"
        else:
            if exists(out_zip_path):
                remove(out_zip_path)
            zipdir(dl.ver_dir, out_zip)
            h = hashlib.sha256()
            with open(out_zip_path, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    h.update(chunk)
            dl.zip_sha256 = h.hexdigest()

        out_nsp = f"{dl.ver_dir}.nsp"
        out_nsp_path = join(BASE_DIR, out_nsp)
        dl.nsp_sha256 = ""
        dl.repacker_success = False

        if nsp_choice in ['y', 'yes', 'true'] or FORCE_BUILD_NSP:
            if exists(out_nsp_path):
                remove(out_nsp_path)
            repacker = NSPRepacker(out_nsp_path, dl.pfs0_map)
            repacker.repack()

            if repacker.verify_integrity():
                dl.repacker_success = True
                h = hashlib.sha256()
                with open(out_nsp_path, "rb") as f:
                    for chunk in iter(lambda: f.read(1048576), b""):
                        h.update(chunk)
                dl.nsp_sha256 = h.hexdigest()

    new_titles_discovered = []
    titles_updated = []
    json_was_updated = False

    if EXTRACT_ZIP or EXTRACT_NSP:
        print("\nINFO: Fetching dynamic Title List from ninupdates...")
        live_titles_raw = {}
        try:
            res = requests.get("https://yls8.mtheall.com/ninupdates/titlelist.php?sys=hac", timeout=15)
            if res.status_code == 200:
                match_table = re.search(r'<table.*?>(.*?)</table>', res.text, re.DOTALL | re.IGNORECASE)
                if match_table:
                    rows = re.findall(r'<tr.*?>(.*?)</tr>', match_table.group(1), re.DOTALL | re.IGNORECASE)
                    for row in rows[1:]:
                        cols = re.findall(r'<td.*?>(.*?)</td>', row, re.DOTALL | re.IGNORECASE)
                        if len(cols) >= 3:
                            tid = re.sub(r'<[^>]*>', '', cols[0]).strip().upper()
                            region = re.sub(r'<[^>]*>', '', cols[1]).strip().upper()
                            tname = re.sub(r'<[^>]*>', '', cols[2]).strip()

                            if tid and tname:
                                if tid not in live_titles_raw:
                                    live_titles_raw[tid] = {"name": tname, "region": region}
                                elif region == "ALL":
                                    live_titles_raw[tid] = {"name": tname, "region": region}

                print(f"INFO: Successfully scraped {len(live_titles_raw)} titles from ninupdates.")
            else:
                print(f"WARNING: Failed to reach ninupdates (Status {res.status_code}).")
        except Exception as e:
            print(f"WARNING: Exception while scraping ninupdates: {e}")

        live_titles = {tid: data["name"] for tid, data in live_titles_raw.items()}

        nx_titles = {}
        titles_file = join(BASE_DIR, "all_titles.json")

        if exists(titles_file):
            try:
                with open(titles_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    nx_titles = data.get("all_titles", data)
            except Exception as e:
                print(f"WARNING: Could not parse local all_titles.json ({e}). Recreating a new one...")
                data = {"timestamp": int(time.time()), "all_titles": {}}
                nx_titles = data["all_titles"]
                json_was_updated = True
        else:
            print("INFO: all_titles.json not found. Creating a new one from scraped data...")
            data = {"timestamp": int(time.time()), "all_titles": {}}
            nx_titles = data["all_titles"]
            json_was_updated = True

        for tid, tname in live_titles.items():
            tid_upper = tid.upper()
            if tid_upper not in nx_titles:
                nx_titles[tid_upper] = {"id": tid_upper, "name": tname}
                json_was_updated = True
                new_titles_discovered.append((tid_upper, tname))
                print(f"   [+] New Title Discovered: {tid_upper} -> {tname}")
            else:
                current_info = nx_titles[tid_upper]
                if isinstance(current_info, dict):
                    current_name = current_info.get("name", "")
                    if current_name != tname:
                        if current_name in ["", tid_upper, "ALL", "Unknown"] or current_name.startswith("v") or "," in current_name:
                            nx_titles[tid_upper]["name"] = tname
                            json_was_updated = True
                            titles_updated.append((tid_upper, current_name, tname))
                            print(f"   [*] Title Name Fixed: {tid_upper} -> {tname}")

        if json_was_updated:
            print("INFO: Saving updated all_titles.json...")
            data["all_titles"] = nx_titles
            data["timestamp"] = int(time.time())
            with open(titles_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            with open(join(BASE_DIR, "json_updated.flag"), "w") as f:
                f.write("true")

        def get_title_name(tid):
            tid_upper = tid.upper()
            tid_lower = tid.lower()
            if tid_upper in nx_titles:
                val = nx_titles[tid_upper]
                return val.get('name', val) if isinstance(val, dict) else str(val)
            if tid_lower in nx_titles:
                val = nx_titles[tid_lower]
                return val.get('name', val) if isinstance(val, dict) else str(val)
            return tid_upper 

        def extract_system_data(nca_list, out_ext_zip, tmp_dir, current_dl):
            print(f"\nINFO: Extracting System Data to {out_ext_zip}...")
            ext_base = join(BASE_DIR, tmp_dir)
            makedirs(ext_base, exist_ok=True)

            nca_files = [f for f in nca_list if not f.endswith(".cnmt.nca")]

            def process_nca(nca_path):
                nca_id = basename(nca_path).replace(".nca", "")
                tid = current_dl.nca_to_tid.get(nca_id, "UNKNOWN").lower()

                raw_tname = get_title_name(tid)
                clean_tname = "".join(c for c in raw_tname if c.isalnum() or c in " _").strip()

                if clean_tname.upper() == tid.upper():
                    out_dir = join(ext_base, clean_tname.upper())
                else:
                    out_dir = join(ext_base, f"{clean_tname} ({tid})")

                makedirs(out_dir, exist_ok=True)

                cmd = [HACTOOL_PATH, "-k", join(BASE_DIR, "prod.keys")]
                romfs = join(out_dir, f"romfs_{nca_id}")
                exefs = join(out_dir, f"exefs_{nca_id}")
                sec0 = join(out_dir, f"section0_{nca_id}")
                cmd.extend(["--romfsdir", romfs, "--exefsdir", exefs, "--section0dir", sec0, nca_path])

                result = run(cmd, stdout=PIPE, stderr=PIPE)

                if result.returncode != 0:
                    return False, nca_id, result.stderr.decode('utf-8', 'ignore').strip()

                for d in [romfs, exefs, sec0]:
                    if exists(d) and not os.listdir(d):
                        try:
                            os.rmdir(d)
                        except Exception:
                            pass

                if exists(out_dir) and not os.listdir(out_dir):
                    try:
                        os.rmdir(out_dir)
                    except Exception:
                        pass

                return True, nca_id, ""

            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = [executor.submit(process_nca, nca) for nca in nca_files]
                with tqdm(total=len(nca_files), unit='NCA', desc=f"Extracting {basename(out_ext_zip)}") as pbar:
                    for future in as_completed(futures):
                        success, nca_id, err_msg = future.result()
                        if not success:
                            print(f"\n[!] CRITICAL ERROR: Hactool failed to extract NCA {nca_id}.")
                            print(err_msg)
                            print("Extraction aborted to guarantee archive integrity.")
                            sys.exit(1)
                        pbar.update(1)

            if exists(out_ext_zip):
                remove(out_ext_zip)
            zipdir(basename(ext_base), out_ext_zip)
            rmtree(ext_base)
            print(f"Data Extraction complete: {out_ext_zip}")

        for dl in final_downloaders:
            if EXTRACT_ZIP:
                target_ncas = glob(join(BASE_DIR, dl.ver_dir, "*.nca"))
                if target_ncas:
                    out_zip_filename = f"Extracted_{dl.ver_dir}.zip"
                    extract_system_data(target_ncas, out_zip_filename, f"Extracted_{dl.ver_dir}", dl)
                else:
                    print(f"WARNING: No NCAs found for ZIP extraction in {dl.ver_string_simple}.")

            if EXTRACT_NSP:
                out_nsp_path = join(BASE_DIR, f"{dl.ver_dir}.nsp")
                target_nsp = out_nsp_path if (nsp_choice in ['y', 'yes', 'true'] and dl.repacker_success) else None
                if not target_nsp:
                    nsps_found = glob(join(BASE_DIR, f"{dl.ver_dir}.nsp"))
                    if nsps_found:
                        target_nsp = nsps_found[0]

                if target_nsp and exists(target_nsp):
                    temp_nsp_unpack = join(BASE_DIR, "temp_nsp_unpack")
                    makedirs(temp_nsp_unpack, exist_ok=True)
                    print(f"\nINFO: Unpacking NSP {basename(target_nsp)} for data extraction...")
                    res = run([HACTOOL_PATH, "-t", "pfs0", "--outdir", temp_nsp_unpack, target_nsp], stdout=PIPE, stderr=PIPE)
                    if res.returncode == 0:
                        nsp_ncas = glob(join(temp_nsp_unpack, "*.nca"))
                        out_nsp_filename = f"Extracted_NSP_{dl.ver_dir}.zip"
                        extract_system_data(nsp_ncas, out_nsp_filename, f"Extracted_NSP_{dl.ver_dir}", dl)
                    else:
                        print(f"WARNING: Failed to unpack NSP for extraction.\n{res.stderr.decode('utf-8','ignore')}")
                    rmtree(temp_nsp_unpack, ignore_errors=True)
                else:
                    print(f"\nWARNING: No NSP found for extraction. Skipping EXTRACT_NSP for {dl.ver_string_simple}.")

    print("\nDOWNLOAD COMPLETE!")

    for dl in final_downloaders:
        if dl.zip_sha256:
            print(f"Archive created: {dl.ver_dir}.zip")
            print(f"SHA256: {dl.zip_sha256}\n")

        if (nsp_choice in ['y', 'yes', 'true'] or FORCE_BUILD_NSP) and dl.repacker_success:
            if is_ci:
                print("<details>\n<summary>Click to view NSP details </summary>\n")
                print(f"NSP created: {dl.ver_dir}.nsp")
                print(f"SHA256: {dl.nsp_sha256}\n</details>\n")
            else:
                print(f"NSP created: {dl.ver_dir}.nsp")
                print(f"SHA256: {dl.nsp_sha256}\n")

        print(f"SystemVersion NCA : {dl.sv_nca_fat or 'Not Found'}")
        print(f"BootImagePackageExFat NCA : {dl.sv_nca_exfat or 'Not Found'}\n")
        print(f"Firmware Version Raw: {dl.ver_raw}")
        print("Verify hashes before installation!")
        if hasattr(dl, "exact_sdk_line") and dl.exact_sdk_line:
            print(f"\n{dl.exact_sdk_line}")

    if new_titles_discovered or titles_updated:
        print("\n***")
        print("### Title Database Updates")
        for tid, tname in new_titles_discovered:
            print(f" New Title Discovered: `{tid}` -> {tname}")
        for tid, old_name, new_name in titles_updated:
            print(f" Title Name Fixed: `{tid}` ({old_name} -> {new_name})")
        print("***")

    if args.datfile:
        print("\nINFO: Updating DAT file...")

        dat_files = glob(join(BASE_DIR, "Nintendo*Nintendo Switch Firmware (*)*.dat"))
        existing_games = {}

        for old_dat in dat_files:
            try:
                tree = ET.parse(old_dat)
                root = tree.getroot()
                for game_elem in root.findall('game'):
                    g_name = game_elem.get('name')
                    roms = []
                    for rom_elem in game_elem.findall('rom'):
                        roms.append({
                            'name': rom_elem.get('name'),
                            'size': rom_elem.get('size'),
                            'crc': rom_elem.get('crc'),
                            'md5': rom_elem.get('md5'),
                            'sha1': rom_elem.get('sha1')
                        })
                    existing_games[g_name] = {'name': g_name, 'roms': roms}
            except Exception:
                pass

        for dl in final_downloaders:
            current_game_name = dl.original_line
            current_roms = []

            nca_list = glob(join(BASE_DIR, dl.ver_dir, "*.nca"))
            with tqdm(total=len(nca_list), unit='file', desc=f"Calculating hashes for {dl.ver_dir}") as pbar:
                for nca in sorted(nca_list):
                    md5_hash = hashlib.md5()
                    sha1_hash = hashlib.sha1()
                    crc_val = 0
                    sz = getsize(nca)
                    with open(nca, "rb") as f:
                        for chunk in iter(lambda: f.read(1048576), b""):
                            md5_hash.update(chunk)
                            sha1_hash.update(chunk)
                            crc_val = zlib.crc32(chunk, crc_val)

                    current_roms.append({
                        'name': basename(nca),
                        'size': str(sz),
                        'crc': "%08x" % (crc_val & 0xFFFFFFFF),
                        'md5': md5_hash.hexdigest(),
                        'sha1': sha1_hash.hexdigest()
                    })
                    pbar.update(1)

            existing_games[current_game_name] = {'name': current_game_name, 'roms': current_roms}

        sorted_games = sorted(existing_games.values(), key=extract_version_order, reverse=False)

        def escape_xml(s):
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")

        timestamp_disp = time.strftime("%Y%m%d%H%M%S")

        xml_lines = []
        xml_lines.append('<?xml version="1.0"?>')
        xml_lines.append('<!DOCTYPE datafile PUBLIC "' + chr(45) + '//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/Dats/datafile.dtd">')
        xml_lines.append('<datafile>')
        xml_lines.append('    <header>')
        xml_lines.append('        <name>Nintendo ' + chr(45) + ' Nintendo Switch Firmware</name>')
        xml_lines.append('        <description>Nintendo ' + chr(45) + ' Nintendo Switch Firmware</description>')
        xml_lines.append(f'        <version>{timestamp_disp}</version>')
        xml_lines.append('        <author>Twitter: @JeremKOYTB</author>')
        xml_lines.append('        <comment>DAT generated by firmware_downloader.py. Inspired by the work of 8BitWonder to help him better archive this!</comment>')
        xml_lines.append('        <homepage>gbatemp.net</homepage>')
        xml_lines.append('        <url>https://gbatemp.net/download/nintendo' + chr(45) + 'switch' + chr(45) + 'firmware' + chr(45) + 'datfile.36558/</url>')
        xml_lines.append('    </header>')

        for game in sorted_games:
            game_name = escape_xml(game['name'])
            xml_lines.append(f'    <game name="{game_name}">')
            xml_lines.append(f'        <category>Games</category>')
            xml_lines.append(f'        <description>{game_name}</description>')
            for rom in game['roms']:
                r_name = escape_xml(rom['name'])
                r_size = rom['size']
                r_crc = rom['crc']
                r_md5 = rom['md5']
                r_sha1 = rom['sha1']
                xml_lines.append(f'        <rom name="{r_name}" size="{r_size}" crc="{r_crc}" md5="{r_md5}" sha1="{r_sha1}"/>')
            xml_lines.append('    </game>')

        xml_lines.append('</datafile>')

        new_dat_name = f"Nintendo - Nintendo Switch Firmware ({len(sorted_games)}) ({timestamp_disp}).dat"
        with open(join(BASE_DIR, new_dat_name), "w", encoding="utf-8") as f:
            f.write("\n".join(xml_lines) + "\n")

        for old_dat in dat_files:
            if basename(old_dat) != new_dat_name:
                try:
                    remove(old_dat)
                except Exception:
                    pass

        num_games = len(sorted_games)
        if num_games == 1:
            print(f"INFO: File {new_dat_name} available with {num_games} registered firmware.")
        else:
            print(f"INFO: File {new_dat_name} available with {num_games} registered firmwares.")

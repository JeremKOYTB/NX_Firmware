#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Project: TriCoreDownloader / Firmware Downloader
# Author: JérémKO
# Complete Firmware Downloader, Verifier, Repacker & DAT Manager.

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
    print("[!] Module(s) manquant(s). Installez-les via : pip install cryptography requests tqdm")
    sys.exit(1)

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="firmware_downloader.py: Nintendo Switch firmware downloader and packer.\n\n"
                "Ce script permet de télécharger en toute sécurité les firmwares officiels Nintendo,\n"
                "de vérifier leur intégrité SHA-256, de les packager au format ZIP / NSP,\n"
                "et de générer les fichiers DAT de préservation Logiqx."
)
parser.add_argument("version", nargs="?", default="", help="Version cible du firmware (ex: 23.0.1.0000).\nSi vide, télécharge automatiquement la dernière version disponible.")
parser.add_argument("--allversion", action="store_true", help="Télécharge l'intégralité des versions répertoriées sur GBATemp.")
parser.add_argument("--local", action="store_true", help="Mode local : traite les fichiers existants sans solliciter les serveurs Nintendo.")
parser.add_argument("--force-nsp", action="store_true", help="Force la compilation du fichier NSP sans confirmation utilisateur.")
parser.add_argument("--extract-data", action="store_true", help="Extrait le contenu sous-jacent (RomFS, ExeFS, Section0) via hactool.")
parser.add_argument("--extract-zip", action="store_true", help="Extrait les fichiers NCA bruts depuis l'archive ZIP générée.")
parser.add_argument("--extract-nsp", action="store_true", help="Extrait les fichiers NCA bruts depuis le conteneur NSP compilé.")
parser.add_argument("--datfile", action="store_true", help="Génère ou met à jour le fichier DAT Logiqx XML.")
parser.add_argument("--dat-from-zips", action="store_true", help="Scanne les archives local 'Firmware*.zip' pour construire le fichier DAT.")
parser.add_argument("--sync-releases", action="store_true", help="Scanne les releases GitHub et synchronise le fichier DAT.")
parser.add_argument("--sync-latest", action="store_true", help="Scanne uniquement la dernière release GitHub et la synchronise dans le DAT.")
parser.add_argument("--displayversion", action="store_true", help="Utilise la version commerciale simplifiée (ex: 23.0.1 au lieu de 23.0.1.0000) pour les dossiers.")
parser.add_argument("--notimeout", action="store_true", help="Désactive le délai de 60 secondes sur les invites utilisateur.")
parser.add_argument("--logs", action="store_true", help="Active le journal d'exécution détaillé.")

args = None
ENV = "lp1"
SYSTEM_VERSION_DEFAULT = 2301
GBATEMP_MAPPING = {}
BASE_DIR = dirname(abspath(__file__))
KEYS_DIR = join(BASE_DIR, "keys")
HACTOOL_BIN = "hactool.exe" if os.name == "nt" else "./hactool"
HACTOOL_PATH = join(BASE_DIR, HACTOOL_BIN)

def log_print(msg):
    if args and getattr(args, 'logs', False):
        print(f"[LOG] {msg}")

def ensure_readable(filepath):
    log_print(f"I/O Audit: Validating readability for {basename(filepath)}...")
    if not exists(filepath):
        print(f"\n[!] ERREUR CRITIQUE : Fichier manquant sur le disque : {filepath}")
        sys.exit(1)
    if not os.access(filepath, os.R_OK):
        print(f"\n[!] ERREUR CRITIQUE : Permission de lecture refusée : {filepath}")
        sys.exit(1)
    try:
        with open(filepath, 'rb') as f:
            f.read(1)
        log_print(f"I/O Audit Passed: {basename(filepath)} est accessible.")
    except IOError as e:
        print(f"\n[!] ERREUR CRITIQUE : Erreur d'E/S ou de verrou matériel sur {filepath}\nMessage système : {e}")
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
        sys.stdout.write("\n[Délai dépassé. Choix par défaut : 'n']\n")
        sys.stdout.flush()
        return "n"
    else:
        import select
        i, o, e = select.select([sys.stdin], [], [], timeout)
        if i:
            return sys.stdin.readline().strip()
        else:
            sys.stdout.write("\n[Délai dépassé. Choix par défaut : 'n']\n")
            sys.stdout.flush()
            return "n"

def get_user_choice(prompt_text):
    if args and getattr(args, 'notimeout', False):
        log_print(f"Prompting user without timeout: {prompt_text}")
        return input(prompt_text).strip().lower()
    log_print(f"Prompting user with 60s timeout: {prompt_text}")
    return input_with_timeout(prompt_text, 60).strip().lower()

def get_gbatemp_firmwares():
    global GBATEMP_MAPPING
    url = "https://gbatemp.net/download/nintendo-switch-firmware-datfile.36558/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
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
        print("[!] ERREUR : Impossible de récupérer la liste depuis GBATemp.")
        return
    print("\n" + "="*80)
    print(" LISTE DES FIRMWARES REGISTRÉS SUR GBATEMP")
    print("="*80)
    for line in lines:
        print(f" * {line}")
    print("="*80 + "\n")

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
                log_print(f"File {basename(out)} fully downloaded (416 Range Not Satisfiable).")
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
                    with tqdm(total=total_size, initial=dlded, unit='B', unit_scale=True, desc=f"Téléchargement {name}", leave=False) as pbar:
                        for chunk in resp.iter_content(chunk_size=chunk_size):
                            if chunk:
                                f.write(chunk)
                                pbar.update(len(chunk))
            break
        except Exception as e:
            log_print(f"Download failed for {basename(out)}: {e}")
            if attempt == 4:
                print(f"\n[!] Erreur lors du téléchargement de {basename(out)}: {e}")
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
            log_print("Attempting parallel download via aria2c.")
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
            log_print(f"aria2c failed: {e}. Falling back to Python requests.")
            _dlfiles_fallback(dltable, user_agent)
    else:
        log_print("aria2c not found. Using parallel Python requests fallback.")
        _dlfiles_fallback(dltable, user_agent)
        
    try:
        remove(dl_tmp_path)
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
            
            with tqdm(total=len(futures), unit='file', desc="Téléchargement des NCAs") as pbar:
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        log_print(f"Fallback error: {e}")
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
        result = run(cmd, stdout=PIPE, stderr=PIPE)
        if result.returncode != 0:
            print(f"\n[!] ERREUR CRITIQUE : Échec hactool sur CNMT {ncaf}.")
            print(result.stderr.decode('utf-8', 'ignore').strip())
            sys.exit(1)
    except FileNotFoundError:
        print(f"\n[!] ERREUR CRITIQUE : '{HACTOOL_BIN}' introuvable dans {BASE_DIR}.")
        sys.exit(1)
    
    try:
        extracted_files = glob(join(cnmt_temp_dir, "*.cnmt"))
        if not extracted_files:
            raise FileNotFoundError(f"Échec d'extraction du .cnmt depuis {ncaf}.")
            
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
            rmtree(cnmt_temp_dir, ignore_errors=True)

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
                    c.read(32)
                    nid = c.read(16).hex().lower()
                    nca_ids.append(nid)
            return tid_hex, ver_int, nca_ids
    except Exception:
        return None, 0, []

def find_firmware_identity(folder_path, tag_hint=""):
    hactool_path = HACTOOL_PATH if exists(HACTOOL_PATH) else ("hactool.exe" if os.name == "nt" else "hactool")
    keys_path = join(BASE_DIR, "prod.keys")
    if not exists(keys_path):
        log_print(f"FATAL: '{keys_path}' introuvable.")
        return None, False

    nca_files = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            if f.endswith(".nca"):
                nca_files.append(join(root, f))

    if not nca_files:
        return None, False

    real_full_ver = ""
    sdk_title = ""
    comm_ver = ""
    system_version_data_nca = None
    sdk_found = False

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

                if tid_hex == "0100000000000809" and nca_ids:
                    target_nid = nca_ids[0].lower()
                    for cand in nca_files:
                        if basename(cand).lower() == f"{target_nid}.nca":
                            system_version_data_nca = cand
                            break

    if system_version_data_nca:
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

            if raw_data and len(raw_data) >= 0x100:
                disp_ver_str = raw_data[0x68:0x80].split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                disp_title_str = raw_data[0x80:0x100].split(b'\x00')[0].decode('utf-8', errors='ignore').strip()
                if disp_ver_str:
                    comm_ver = disp_ver_str
                if disp_title_str.startswith("NintendoSDK"):
                    sdk_title = disp_title_str
                    sdk_found = True

            if not sdk_title:
                sdk_m = re.search(rb'NintendoSDK Firmware for NX [0-9.-]+', raw_data)
                if sdk_m:
                    sdk_title = sdk_m.group(0).decode("utf-8")
                    sdk_found = True
        except Exception as e:
            log_print(f"RomFS error: {e}")
        finally:
            rmtree(tmp_romfs, ignore_errors=True)

    if not comm_ver and sdk_title:
        sdk_v_match = re.search(r'NX\s+([0-9a-zA-Z\.\-_]+)', sdk_title)
        if sdk_v_match:
            comm_ver = sdk_v_match.group(1)

    if not comm_ver:
        if real_full_ver:
            comm_ver = ".".join(real_full_ver.split(".")[:3])
        else:
            base_name = basename(folder_path.rstrip("/\\"))
            ver_match = re.search(r'(\d+\.\d+\.\d+)', base_name)
            comm_ver = ver_match.group(1) if ver_match else "0.0.0"

    if not real_full_ver:
        real_full_ver = f"{comm_ver}.0000"

    hint = f"{folder_path} {tag_hint}".lower()
    suffix = ""
    if "-pre" in hint or "(pre" in hint or "pre-release" in hint:
        suffix = " (Pre-Release)"
    elif "-card" in hint or "cartridge" in hint or "card" in hint:
        suffix = " (Cartridge)"

    if sdk_found and sdk_title and real_full_ver:
        final_line = f"Firmware {comm_ver} ({sdk_title}) ({real_full_ver}){suffix}"
    elif real_full_ver in GBATEMP_MAPPING:
        final_line = GBATEMP_MAPPING[real_full_ver]['original_line']
    else:
        final_line = f"Firmware {comm_ver} ({real_full_ver}){suffix}"

    return final_line, sdk_found

def zipdir(src_dir, out_zip):
    src_dir_path = join(BASE_DIR, src_dir)
    out_zip_path = join(BASE_DIR, out_zip)
    log_print(f"Archiving directory {src_dir_path} to {out_zip_path}")
    
    total_files = sum(len(files) for _, _, files in os.walk(src_dir_path))

    with ZipFile(out_zip_path, "w", compression=ZIP_STORED) as zf:
        with tqdm(total=total_files, unit='files', desc=f"Compression {basename(out_zip)}") as pbar:
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
        for f_path in self.sorted_files:
            ensure_readable(f_path)
            
        hd = self._gen_header()
        self.expected_total_size = len(hd) + sum(getsize(file) for file in self.sorted_files)
        
        if exists(self.path) and getsize(self.path) == self.expected_total_size:
            return self.path
            
        with open(self.path, 'wb') as outf:
            outf.write(hd)
            with tqdm(total=sum(getsize(f) for f in self.sorted_files), unit='B', unit_scale=True, desc="Écriture NSP", leave=False) as pbar:
                for file in self.sorted_files:
                    with open(file, 'rb') as inf:
                        while True:
                            buf = inf.read(4096 * 1024)
                            if not buf:
                                break
                            outf.write(buf)
                            pbar.update(len(buf))
        return self.path

    def verify_integrity(self):
        ensure_readable(self.path)
        try:
            with open(self.path, "rb") as f:
                if f.read(4) != b'PFS0':
                    return False
                file_count = unpack('<I', f.read(4))[0]
                if file_count != len(self.sorted_files):
                    return False
                string_table_size = unpack('<I', f.read(4))[0]
                f.read(4)
                header_size = 0x10 + (file_count * 0x18) + string_table_size
                
                for i in range(file_count):
                    offset = unpack('<Q', f.read(8))[0]
                    size = unpack('<Q', f.read(8))[0]
                    name_offset = unpack('<I', f.read(4))[0]
                    f.read(4)
                    if name_offset >= string_table_size:
                        return False
                    if (header_size + offset + size) > self.expected_total_size:
                        return False
                        
                f.seek(0, 2)
                if f.tell() != self.expected_total_size:
                    return False
            return True
        except Exception:
            return False
            
    def _gen_header(self):
        files_nb = len(self.sorted_files)
        string_table = b'\x00'.join(basename(file).encode('utf-8') for file in self.sorted_files) + b'\x00'
        
        raw_header_size = 0x10 + files_nb * 0x18 + len(string_table)
        remainder = (0x10 - (raw_header_size % 0x10)) % 0x10
        padded_string_table_size = len(string_table) + remainder
        
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
            
        firmware_ua_str = f"{self.disp_ver}-1.0"
        self.user_agent = f"NintendoSDK Firmware for NX {firmware_ua_str} (platform:NX; did:{self.device_id}; eid:{ENV})"

        display_flag = getattr(args, 'displayversion', False) if args else False
        if display_flag:
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

        local_mode = (os.environ.get("LOCAL_ONLY") == "true") or (args and getattr(args, 'local', False))
        if local_mode:
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
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                if not (args and getattr(args, 'allversion', False)):
                    print(f"[*] Title {title_id} version {version} non trouvé sur le CDN (404).")
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
            for t_id, ver, _, _ in entries:
                self.dltitle(t_id, ver, is_su=False)
        else:
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
    if "pre-release" in name_lower or "-pre" in name_lower or "(pre)" in name_lower:
        sub = -2
    elif "cartridge" in name_lower or "-card" in name_lower:
        sub = -1
    else:
        sub = 0

    raw_match = re.search(r'\((\d+\.\d+\.\d+\.\d{4})\)', name)
    raw_val = raw_match.group(1) if raw_match else ""

    return (*v_parts, sub, raw_val)

def write_logiqx_dat(games_dict, base_dir):
    sorted_games = sorted(games_dict.values(), key=extract_version_order, reverse=False)

    def escape_xml(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")

    timestamp_disp = time.strftime("%Y%m%d%H%M%S")
    xml_lines = [
        '<?xml version="1.0"?>',
        '<!DOCTYPE datafile PUBLIC "-//Logiqx//DTD ROM Management Datafile//EN" "http://www.logiqx.com/Dats/datafile.dtd">',
        '<datafile>',
        '    <header>',
        '        <name>Nintendo - Nintendo Switch Firmware</name>',
        '        <description>Nintendo - Nintendo Switch Firmware</description>',
        f'        <version>{timestamp_disp}</version>',
        '        <author>Twitter: @JeremKOYTB</author>',
        '        <comment>DAT generated by firmware_downloader.py. Inspired by the work of 8BitWonder to help him better archive this!</comment>',
        '        <homepage>gbatemp.net</homepage>',
        '        <url>https://gbatemp.net/download/nintendo-switch-firmware-datfile.36558/</url>',
        '    </header>'
    ]

    for game in sorted_games:
        game_name = escape_xml(game['name'])
        xml_lines.append(f'    <game name="{game_name}">')
        xml_lines.append('        <category>Games</category>')
        xml_lines.append(f'        <description>{game_name}</description>')
        for rom in game['roms']:
            r_name = escape_xml(rom['name'])
            xml_lines.append(f'        <rom name="{r_name}" size="{rom["size"]}" crc="{rom["crc"]}" md5="{rom["md5"]}" sha1="{rom["sha1"]}"/>')
        xml_lines.append('    </game>')

    xml_lines.append('</datafile>')

    new_dat_name = f"Nintendo - Nintendo Switch Firmware ({len(sorted_games)}) ({timestamp_disp}).dat"
    out_path = join(base_dir, new_dat_name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(xml_lines) + "\n")

    for old_dat in glob(join(base_dir, "Nintendo*Nintendo Switch Firmware (*)*.dat")):
        if basename(old_dat) != new_dat_name:
            try: remove(old_dat)
            except Exception: pass

    print(f"\n✅ Fichier DAT généré avec succès : {new_dat_name} ({len(sorted_games)} firmwares enregistrés).")
    return new_dat_name

def generate_dat_from_local_zips():
    get_gbatemp_firmwares()

    zip_candidates = [
        f for f in os.listdir(BASE_DIR)
        if f.lower().endswith(".zip")
        and f.lower().startswith("firmware")
        and not f.lower().startswith("extracted")
    ]

    if not zip_candidates:
        print("[*] Aucun fichier 'Firmware*.zip' trouvé dans le répertoire.")
        return

    print(f"\n[*] {len(zip_candidates)} archive(s) 'Firmware*.zip' identifiée(s).")
    existing_games = {}

    for zname in sorted(zip_candidates):
        zpath = join(BASE_DIR, zname)
        ensure_readable(zpath)

        tmp_ident_dir = join(BASE_DIR, f"tmp_ident_{uuid.uuid4().hex[:8]}")
        makedirs(tmp_ident_dir, exist_ok=True)
        roms = []

        try:
            with ZipFile(zpath, "r") as zf:
                nca_members = [m for m in zf.infolist() if m.filename.lower().endswith(".nca") and not m.is_dir()]
                if not nca_members:
                    continue

                with tqdm(total=len(nca_members), unit='file', desc=f"Hachage de {zname}") as pbar:
                    for member in sorted(nca_members, key=lambda x: basename(x.filename)):
                        fname = basename(member.filename)
                        if fname.endswith(".cnmt.nca") or member.file_size <= 5242880:
                            zf.extract(member, tmp_ident_dir)

                        md5_h = hashlib.md5()
                        sha1_h = hashlib.sha1()
                        crc_val = 0
                        sz = member.file_size

                        with zf.open(member) as f:
                            for chunk in iter(lambda: f.read(1048576), b""):
                                md5_h.update(chunk)
                                sha1_h.update(chunk)
                                crc_val = zlib.crc32(chunk, crc_val)

                        roms.append({
                            'name': fname,
                            'size': str(sz),
                            'crc': "%08x" % (crc_val & 0xFFFFFFFF),
                            'md5': md5_h.hexdigest(),
                            'sha1': sha1_h.hexdigest()
                        })
                        pbar.update(1)

            m_tag = re.search(r'Firmware[\.\s]([0-9a-zA-Z\.\-_]+?)(?:\.zip|$)', zname, re.IGNORECASE)
            raw_tag = m_tag.group(1).strip() if m_tag else zname.replace(".zip", "")
            identity_line, _ = find_firmware_identity(tmp_ident_dir, raw_tag)

            resolved_name = identity_line or f"Firmware {raw_tag}"
            if not identity_line:
                clean_v = raw_tag.replace("-card", "").replace("-pre", "")
                if clean_v in GBATEMP_MAPPING:
                    resolved_name = GBATEMP_MAPPING[clean_v]['original_line']

            existing_games[resolved_name] = {'name': resolved_name, 'roms': roms}
            print(f"[DAT] Enregistré : '{resolved_name}' ({len(roms)} NCAs)")

        except Exception as e:
            print(f"[!] Erreur sur {zname}: {e}")
        finally:
            if exists(tmp_ident_dir):
                rmtree(tmp_ident_dir, ignore_errors=True)

    write_logiqx_dat(existing_games, BASE_DIR)

def sync_datfile_from_releases(latest_only=False):
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
        except Exception: pass

    limit = "1" if latest_only else "1000"
    try:
        cmd = ["gh", "release", "list", "-L", limit, "--json", "tagName", "--jq", ".[].tagName"]
        res = run(cmd, stdout=PIPE, stderr=PIPE, text=True)
        if res.returncode != 0:
            print(f"[!] Échec de récupération des releases via gh CLI : {res.stderr.strip()}")
            sys.exit(1)
        release_tags = [t.strip() for t in res.stdout.splitlines() if t.strip()]
    except Exception as e:
        print(f"[!] Erreur d'exécution de 'gh' : {e}")
        sys.exit(1)

    for tag in release_tags:
        clean_v = tag.replace("-card", "").replace("-pre", "")
        found_key = None

        for g_name in existing_games.keys():
            if f"({clean_v})" in g_name or f"Firmware {tag}" in g_name:
                found_key = g_name
                break

        if found_key and len(existing_games[found_key]['roms']) > 0:
            continue

        target_zip_name = f"Firmware.{tag}.zip"
        tmp_dl_dir = join(BASE_DIR, f"tmp_dat_{uuid.uuid4().hex[:8]}")
        makedirs(tmp_dl_dir, exist_ok=True)
        try:
            dl_cmd = ["gh", "release", "download", tag, "-p", target_zip_name, "--dir", tmp_dl_dir, "--clobber"]
            res = run(dl_cmd, stdout=PIPE, stderr=PIPE, text=True)
            if res.returncode != 0:
                continue

            zip_file = join(tmp_dl_dir, target_zip_name)
            if not exists(zip_file):
                continue

            extract_folder = join(tmp_dl_dir, "extracted")
            makedirs(extract_folder, exist_ok=True)
            with ZipFile(zip_file, 'r') as zf:
                zf.extractall(extract_folder)

            nca_files = [join(root, f) for root, _, files in os.walk(extract_folder) for f in files if f.endswith(".nca")]
            if not nca_files:
                continue

            current_roms = []
            with tqdm(total=len(nca_files), unit='file', desc=f"Hachage {tag}") as pbar:
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

            identity_line, _ = find_firmware_identity(extract_folder, tag)
            resolved_name = identity_line or f"Firmware {tag}"
            if not identity_line and clean_v in GBATEMP_MAPPING:
                resolved_name = GBATEMP_MAPPING[clean_v]['original_line']

            existing_games[resolved_name] = {'name': resolved_name, 'roms': current_roms}
        finally:
            if exists(tmp_dl_dir):
                rmtree(tmp_dl_dir, ignore_errors=True)

    write_logiqx_dat(existing_games, BASE_DIR)

# ==============================================================================
# SÉQUENCE D'EXÉCUTION PRINCIPALE
# ==============================================================================
if __name__ == "__main__":
    args, unknown_args = parser.parse_known_args()

    if args.dat_from_zips:
        generate_dat_from_local_zips()
        sys.exit(0)

    if args.sync_releases:
        sync_datfile_from_releases(latest_only=False)
        sys.exit(0)

    if args.sync_latest:
        sync_datfile_from_releases(latest_only=True)
        sys.exit(0)

    if args.allversion or args.displayversion or args.datfile:
        get_gbatemp_firmwares()

    VERSION = args.version

    if args.allversion:
        allow_fetch = get_user_choice("Autoriser la récupération automatique de la liste GBATemp ? [y/N]: ")
        if allow_fetch not in ['y', 'yes', 'true']:
            sys.exit(1)

    if VERSION != "" and not args.allversion:
        if not re.match(r"^\d+\.\d+\.\d+\.\d{4}$", VERSION):
            print(f"[!] Format de version invalide : '{VERSION}'. Requis: X.Y.Z.WWWW (ex: 23.0.1.0000).")
            fetch_choice = get_user_choice("Consulter la liste sur GBATemp ? [y/N]: ")
            if fetch_choice in ['y', 'yes', 'true']:
                display_gbatemp_list()
            choice = get_user_choice("Continuer malgré tout ? [y/N]: ")
            if choice not in ['y', 'yes', 'true']:
                sys.exit(1)

    LOCAL_ONLY = os.environ.get("LOCAL_ONLY") == "true" or args.local
    FORCE_BUILD_NSP = os.environ.get("FORCE_BUILD_NSP") == "true" or args.force_nsp
    EXTRACT_DATA = os.environ.get("EXTRACT_DATA") == "true" or args.extract_data
    EXTRACT_ZIP = os.environ.get("EXTRACT_ZIP") == "true" or EXTRACT_DATA or args.extract_zip
    EXTRACT_NSP = os.environ.get("EXTRACT_NSP") == "true" or args.extract_nsp

    if os.name == 'nt' and not exists(HACTOOL_PATH):
        print("[*] hactool.exe introuvable. Téléchargement automatique...")
        hactool_url = "https://github.com/SciresM/hactool/releases/download/1.4.0/hactool-1.4.0-win.zip"
        try:
            resp = requests.get(hactool_url)
            resp.raise_for_status()
            with ZipFile(io.BytesIO(resp.content)) as z:
                with open(HACTOOL_PATH, "wb") as f:
                    f.write(z.read("hactool.exe"))
            print("[+] hactool.exe récupéré avec succès. Relance du script...")
            run([sys.executable] + sys.argv)
            sys.exit(0)
        except Exception as e:
            print(f"[!] ERREUR CRITIQUE : Échec du téléchargement de hactool.exe : {e}")
            sys.exit(1)

    cert_path = join(BASE_DIR, "certificat.pem")
    if not exists(cert_path):
        print(f"[!] Fichier 'certificat.pem' introuvable dans {BASE_DIR}.")
        sys.exit(1)

    with open(cert_path, "r", encoding="utf8") as f:
        pem_text = f.read()

    cert_match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_text, re.DOTALL)
    key_match = re.search(r"-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----", pem_text, re.DOTALL)

    if not cert_match or not key_match:
        print("[!] Structure invalide dans certificat.pem.")
        sys.exit(1)

    makedirs(KEYS_DIR, exist_ok=True)
    with open(join(KEYS_DIR, "switch_client.crt"), "w", encoding="utf8") as crt_f:
        crt_f.write(cert_match.group(0) + "\n")
    with open(join(KEYS_DIR, "switch_client.key"), "w", encoding="utf8") as key_f:
        key_f.write(key_match.group(0) + "\n")

    prod_keys_path = join(BASE_DIR, "prod.keys")
    if not exists(prod_keys_path):
        print(f"[!] Fichier 'prod.keys' introuvable dans {BASE_DIR}.")
        sys.exit(1)

    prod_keys = ConfigParser(strict=False)
    with open(prod_keys_path) as f:
        prod_keys.read_string("[keys]\n" + f.read())

    prodinfo_path = join(BASE_DIR, "PRODINFO.bin")
    if not exists(prodinfo_path):
        print(f"[!] Fichier 'PRODINFO.bin' introuvable dans {BASE_DIR}.")
        sys.exit(1)

    with open(prodinfo_path, "rb") as pf:
        prod_data = pf.read()

    if prod_data[:4] == b"CAL0":
        decrypted_prod = prod_data
    else:
        bis_key_00_hex = prod_keys.get("keys", "bis_key_00", fallback=None)
        if not bis_key_00_hex:
            print("[!] PRODINFO chiffré mais 'bis_key_00' absente de prod.keys !")
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
            decrypted_prod += cipher.decryptor().update(chunk)
        decrypted_prod = bytes(decrypted_prod)

    if decrypted_prod[:4] != b"CAL0":
        print("[!] PRODINFO invalide (déchiffrement échoué).")
        sys.exit(1)

    device_id = decrypted_prod[0x2b56 : 0x2b56 + 0x10].decode("utf-8").strip('\x00')
    user_agent = f"NintendoSDK Firmware for NX 23.0.1-1.0 (platform:NX; did:{device_id}; eid:{ENV})"
    global_session = requests.Session()

    latest_ver_full = ""
    latest_ver_raw = 0

    if VERSION == "" or args.allversion:
        try:
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
        except Exception as e:
            log_print(f"Failed to fetch latest version: {e}")
            latest_ver_full = ""

    versions_to_process = []

    if args.allversion:
        for full_v in GBATEMP_MAPPING.keys():
            versions_to_process.append(full_v)
        versions_to_process = list(dict.fromkeys(versions_to_process))
    else:
        if VERSION == "":
            if LOCAL_ONLY or not latest_ver_full:
                print("[!] Impossible de déterminer la dernière version en mode LOCAL.")
                sys.exit(1)
            versions_to_process = [latest_ver_full]
        else:
            versions_to_process = [VERSION]

    def prepare_downloader(device_id_val, ua_val, v_string, sess):
        parts = list(map(int, v_string.split(".")))
        if len(parts) == 3: parts.append(0) 
        ver_raw_val = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]

        dl = FirmwareDownloader(device_id_val, v_string)
        dl.session = sess
        dl.user_agent = ua_val
        dl.ver_raw = ver_raw_val

        try:
            dl.dltitle("0100000000000816", ver_raw_val, is_su=True)
            if not dl.sv_nca_exfat:
                dl.dltitle("010000000000081b", ver_raw_val, is_su=False)
        except Exception as e:
            log_print(f"Initialization error for {v_string}: {e}")
            dl.init_error = True
        return dl

    downloaders = []

    if args.allversion:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(prepare_downloader, device_id, user_agent, v, global_session) for v in versions_to_process]
            with tqdm(total=len(futures), unit='version', desc="Analyse des métadonnées") as pbar:
                for future in as_completed(futures):
                    dl_res = future.result()
                    downloaders.append(dl_res)
                    pbar.update(1)
    else:
        dl_single = prepare_downloader(device_id, user_agent, versions_to_process[0], global_session)
        downloaders.append(dl_single)

    downloaders.sort(key=lambda d: tuple(map(int, d.ver_string_full.split("."))))

    valid_queued = []
    missing_firmwares = []
    total_bytes = 0
    total_missing_bytes = 0

    for dl in downloaders:
        ver_dir_path = join(BASE_DIR, dl.ver_dir)
        if LOCAL_ONLY and exists(ver_dir_path):
            for f in glob(join(ver_dir_path, "*.nca")):
                dl.expected_sizes[basename(f)] = getsize(f)
                if f not in dl.update_files:
                    dl.update_files.append(f)

        dl_size = sum(dl.expected_sizes.values())
        if dl.init_error or dl_size <= 52428800:
            missing_firmwares.append(dl.ver_string_full)
            dl.skip = True
        else:
            valid_queued.append(dl)
            if not LOCAL_ONLY:
                total_bytes += dl_size
                for url, dirc, fname, expected_hash in dl.update_dls:
                    fpath = join(BASE_DIR, dirc, fname)
                    if not exists(fpath) or getsize(fpath) != dl.expected_sizes.get(fname, 0):
                        total_missing_bytes += dl.expected_sizes.get(fname, 0)

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
        if exists(ver_dir_path):
            real_identity, sdk_found = find_firmware_identity(ver_dir_path, dl.ver_string_full)
            if real_identity:
                dl.original_line = real_identity
            dl.sdk_found = sdk_found
            if sdk_found:
                dl.exact_sdk_line = real_identity

    if LOCAL_ONLY:
        for dl in valid_queued:
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
                    except Exception: pass

    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    nsp_choice = "y" if (is_ci and FORCE_BUILD_NSP) else get_user_choice("\nEmpaqueter les fichiers bruts dans un NSP ? [y/N]: ")

    final_downloaders = [dl for dl in valid_queued if not dl.skip]

    for dl in final_downloaders:
        out_zip = f"{dl.ver_dir}.zip"
        out_zip_path = join(BASE_DIR, out_zip)
        dl.zip_sha256 = ""

        if not LOCAL_ONLY:
            if exists(out_zip_path): remove(out_zip_path)
            zipdir(dl.ver_dir, out_zip)
            h = hashlib.sha256()
            with open(out_zip_path, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""): h.update(chunk)
            dl.zip_sha256 = h.hexdigest()

        out_nsp = f"{dl.ver_dir}.nsp"
        out_nsp_path = join(BASE_DIR, out_nsp)
        dl.nsp_sha256 = ""
        dl.repacker_success = False

        if nsp_choice in ['y', 'yes', 'true'] or FORCE_BUILD_NSP:
            if exists(out_nsp_path): remove(out_nsp_path)
            repacker = NSPRepacker(out_nsp_path, dl.pfs0_map)
            repacker.repack()

            if repacker.verify_integrity():
                dl.repacker_success = True
                h = hashlib.sha256()
                with open(out_nsp_path, "rb") as f:
                    for chunk in iter(lambda: f.read(1048576), b""): h.update(chunk)
                dl.nsp_sha256 = h.hexdigest()

    def extract_system_data(nca_list, out_ext_zip, tmp_dir, current_dl):
        print(f"\nINFO: Extraction des données système vers {out_ext_zip}...")
        ext_base = join(BASE_DIR, tmp_dir)
        makedirs(ext_base, exist_ok=True)

        try:
            nca_files = [f for f in nca_list if not f.endswith(".cnmt.nca")]

            def process_nca(nca_path):
                nca_id = basename(nca_path).replace(".nca", "")
                tid = current_dl.nca_to_tid.get(nca_id, "UNKNOWN").lower()
                out_dir = join(ext_base, tid.upper())
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
                        try: os.rmdir(d)
                        except Exception: pass
                return True, nca_id, ""

            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = [executor.submit(process_nca, nca) for nca in nca_files]
                with tqdm(total=len(nca_files), unit='NCA', desc=f"Extraction {basename(out_ext_zip)}") as pbar:
                    for future in as_completed(futures):
                        success, nca_id, err_msg = future.result()
                        if not success:
                            print(f"\n[!] ERREUR CRITIQUE hactool sur NCA {nca_id}: {err_msg}")
                            sys.exit(1)
                        pbar.update(1)

            if exists(out_ext_zip): remove(out_ext_zip)
            zipdir(basename(ext_base), out_ext_zip)
            print(f"[+] Extraction de données terminée : {out_ext_zip}")
        finally:
            if exists(ext_base):
                rmtree(ext_base, ignore_errors=True)

    if EXTRACT_ZIP or EXTRACT_NSP:
        for dl in final_downloaders:
            if EXTRACT_ZIP:
                target_ncas = glob(join(BASE_DIR, dl.ver_dir, "*.nca"))
                if target_ncas:
                    extract_system_data(target_ncas, f"Extracted_{dl.ver_dir}.zip", f"Extracted_{dl.ver_dir}", dl)

    if args.datfile:
        print("\n[*] Mise à jour de la base de données DAT...")
        existing_games = {}
        for dl in final_downloaders:
            current_game_name = dl.original_line
            current_roms = []
            nca_list = glob(join(BASE_DIR, dl.ver_dir, "*.nca"))
            
            with tqdm(total=len(nca_list), unit='file', desc=f"Calcul des hachages {dl.ver_dir}") as pbar:
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

        write_logiqx_dat(existing_games, BASE_DIR)

    print("\n[+] TRAITEMENT ET TÉLÉCHARGEMENT TERMINÉS AVEC SUCCÈS !")

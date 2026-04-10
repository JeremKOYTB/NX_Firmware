#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import hashlib
import warnings
import locale
from struct import unpack
from binascii import hexlify
from glob import glob
from shutil import rmtree
from subprocess import run, PIPE
from os import makedirs, remove
from os.path import basename, exists, join
from configparser import ConfigParser
from sys import argv
from zipfile import ZipFile, ZIP_STORED, ZipInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
except ImportError:
    # Minimal fallback before i18n initialization
    print("Module 'anynet' not found / introuvable. Install it with: pip install anynet")
    exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
VERSION = argv[1] if len(argv) > 1 else ""

# ==========================================
# I18N (INTERNATIONALIZATION) SETUP
# ==========================================
def detect_language():
    try:
        # getlocale() may return (None, None) on some systems, fallback to env vars
        lang, _ = locale.getlocale()
        if not lang:
            lang = os.environ.get('LANG', 'en')
        return 'fr' if lang.lower().startswith('fr') else 'en'
    except Exception:
        return 'en'

USER_LANG = detect_language()

def _(en_str: str, fr_str: str) -> str:
    """Returns the translated string based on the user's OS language."""
    return fr_str if USER_LANG == 'fr' else en_str

# ==========================================
# UTILITY FUNCTIONS
# ==========================================
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

def dlfile(url, out, user_agent):
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            f"--out={out}", "-c", url
        ], check=True, stdout=PIPE, stderr=PIPE)
    except FileNotFoundError:
        print(_(f"Downloading {basename(out)} via requests...", f"Téléchargement de {basename(out)} via requests..."))
        resp = request(
            "GET", url,
            cert=("keys/switch_client.crt", "keys/switch_client.key"),
            headers={"User-Agent": user_agent},
            stream=True, verify=False
        )
        resp.raise_for_status()
        with open(out, "wb") as f:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)

def dlfiles(dltable, user_agent):
    with open("dl.tmp", "w") as f:
        for url, dirc, fname, fhash in dltable:
            f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            "-x", "16", "-s", "16", "-i", "dl.tmp"
        ], check=True)
    except FileNotFoundError:
        # OPTIMIZATION: Use multithreading if aria2c is missing instead of sequential downloads.
        print(_("aria2c not found. Using parallel requests fallback (16 threads).", 
                "aria2c introuvable. Utilisation du fallback de requêtes parallèles (16 threads)."))
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = []
            for url, dirc, fname, fhash in dltable:
                makedirs(dirc, exist_ok=True)
                out = join(dirc, fname)
                futures.append(executor.submit(dlfile, url, out, user_agent))
            
            for future in as_completed(futures):
                future.result() # Raises exceptions if any occurred during thread execution
    finally:
        try:
            remove("dl.tmp")
        except FileNotFoundError:
            pass

def nin_request(method, url, user_agent, headers=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    resp = request(
        method, url,
        cert=("keys/switch_client.crt", "keys/switch_client.key"),
        headers=headers, verify=False
    )
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    
    # --- KEY MODIFICATION ---
    # Force the use of the hactool executable in the current directory.
    # In the workflow, hactool-linux was renamed to hactool and made executable.
    hactool_bin = "hactool.exe" if os.name == "nt" else "./hactool" 
    # -----------------------
    
    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    
    run(
        [hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir],
        stdout=PIPE, stderr=PIPE
    )
    
    # Check if the extraction succeeded
    extracted_files = glob(f"{cnmt_temp_dir}/*.cnmt")
    if not extracted_files:
        raise FileNotFoundError(_(f"Failed to extract CNMT from {ncaf}. Check prod.keys.", 
                                  f"Échec de l'extraction CNMT de {ncaf}. Vérifiez prod.keys."))
        
    cnmt_file = extracted_files[0]
    entries = []
    with open(cnmt_file, "rb") as c:
        c_type = readdata(c, 0xc, 1)
        if c_type[0] == 0x3:
            n_entries = readshort(c, 0x12)
            offset    = readshort(c, 0xe)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x10)
                title_id = unpack("<Q", c.read(8))[0]
                version  = unpack("<I", c.read(4))[0]
                entries.append((ihexify(title_id, 8), version))
        else:
            n_entries = readshort(c, 0x10)
            offset    = readshort(c, 0xe)
            base = 0x20 + offset
            for i in range(n_entries):
                c.seek(base + i*0x38)
                h      = c.read(32)
                nid    = hexify(c.read(16))
                entries.append((nid, hexify(h)))
    
    rmtree(cnmt_temp_dir)
    return entries

def zipdir(src_dir, out_zip):
    with ZipFile(out_zip, "w", compression=ZIP_STORED) as zf:
        for root, dirs, files in os.walk(src_dir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel  = os.path.relpath(full, start=src_dir) 
                os.utime(full, (1780315200, 1780315200))
                
                zinfo = ZipInfo.from_file(full, arcname=rel)
                zinfo.date_time = (2026, 1, 1, 0, 0, 0)
                zinfo.create_system = 0
                zinfo.external_attr = 0 
                zinfo.compress_type = ZIP_STORED
                
                with open(full, 'rb') as f:
                    zf.writestr(zinfo, f.read())


# ==========================================
# CLASS ENCAPSULATION (REPLACING GLOBALS)
# ==========================================
class FirmwareDownloader:
    def __init__(self, device_id: str, ver_string_simple: str):
        self.device_id = device_id
        self.ver_string_simple = ver_string_simple
        self.user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{self.device_id}; eid:{ENV})"
        self.ver_dir = f"Firmware {self.ver_string_simple}"
        
        # Isolated States
        self.update_files = []
        self.update_dls = []
        self.sv_nca_fat = ""
        self.sv_nca_exfat = ""
        self.seen_titles = set()
        self.queued_ncas = set()

    def dltitle(self, title_id: str, version: int, is_su: bool = False):
        key = (title_id, version, is_su)
        if key in self.seen_titles:
            return
        self.seen_titles.add(key)

        p = "s" if is_su else "a"
        try:
            cnmt_id = nin_request(
                "HEAD",
                f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={self.device_id}",
                self.user_agent
            ).headers["X-Nintendo-Content-ID"]
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                print(_(f"INFO: Title {title_id} version {version} not found (404).", 
                        f"INFO : Titre {title_id} version {version} introuvable (404)."))
                if title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = ""
                return
            raise

        makedirs(self.ver_dir, exist_ok=True)

        cnmt_nca = f"{self.ver_dir}/{cnmt_id}.cnmt.nca"
        self.update_files.append(cnmt_nca)
        dlfile(
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={self.device_id}",
            cnmt_nca,
            self.user_agent
        )

        if is_su:
            for t_id, ver in parse_cnmt(cnmt_nca):
                self.dltitle(t_id, ver)
        else:
            for nca_id, nca_hash in parse_cnmt(cnmt_nca):
                if title_id.lower() == "0100000000000809":
                    self.sv_nca_fat = f"{nca_id}.nca"
                elif title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = f"{nca_id}.nca"

                if nca_id not in self.queued_ncas:
                    self.queued_ncas.add(nca_id)
                    self.update_files.append(f"{self.ver_dir}/{nca_id}.nca")
                    self.update_dls.append((
                        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={self.device_id}",
                        self.ver_dir,
                        f"{nca_id}.nca",
                        nca_hash
                    ))

    def run_downloads(self):
        dlfiles(self.update_dls, self.user_agent)

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    if not exists("certificat.pem"):
        print(_("File 'certificat.pem' not found in root directory.", 
                "Fichier 'certificat.pem' introuvable dans le répertoire racine."))
        exit(1)
        
    pem_data = open("certificat.pem", "rb").read()
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs("keys", exist_ok=True)
    cert.save("keys/switch_client.crt", tls.TYPE_PEM)
    priv.save("keys/switch_client.key", tls.TYPE_PEM)

    if not exists("prod.keys"):
        print(_("File 'prod.keys' not found in root directory.", 
                "Fichier 'prod.keys' introuvable dans le répertoire racine."))
        exit(1)
        
    prod_keys = ConfigParser(strict=False)
    with open("prod.keys") as f:
        prod_keys.read_string("[keys]\n" + f.read())

    if not exists("PRODINFO.bin"):
        print(_("File 'PRODINFO.bin' not found in root directory.", 
                "Fichier 'PRODINFO.bin' introuvable dans le répertoire racine."))
        exit(1)
        
    with open("PRODINFO.bin", "rb") as pf:
        if pf.read(4) != b"CAL0":
            print(_("Invalid PRODINFO (invalid header)!", 
                    "PRODINFO invalide (en-tête incorrect) !"))
            exit(1)
        device_id = utf8(readdata(pf, 0x2b56, 0x10))
        print(_(f"Device ID: {device_id}", f"ID de l'appareil (Device ID) : {device_id}"))

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"

    if VERSION == "":
        print(_("INFO: No version specified, searching for the latest version...", 
                "INFO : Aucune version spécifiée, recherche de la dernière version en cours..."))
        su_meta = nin_request(
            "GET",
            f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}",
            user_agent
        ).json()
        ver_raw = su_meta["system_update_metas"][0]["title_version"]
        
        ver_major = ver_raw // 0x4000000
        ver_minor = (ver_raw - ver_major*0x4000000) // 0x100000
        ver_sub1  = (ver_raw - ver_major*0x4000000 - ver_minor*0x100000) // 0x10000
        ver_sub2  = ver_raw - ver_major*0x4000000 - ver_minor*0x100000 - ver_sub1*0x10000
        
        ver_string_raw = f"{ver_major}.{ver_minor}.{ver_sub1}.{str(ver_sub2).zfill(4)}"
        ver_string_simple = f"{ver_major}.{ver_minor}.{ver_sub1}"
    else:
        ver_string_simple = VERSION
        
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3:
             parts.append(0) 

        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]
        ver_string_raw = f"{parts[0]}.{parts[1]}.{parts[2]}.{str(parts[3]).zfill(4)}"

    downloader = FirmwareDownloader(device_id, ver_string_simple)
    
    print(_(f"Downloading firmware. Internal version: {ver_string_raw}. Folder: {downloader.ver_dir}", 
            f"Téléchargement du firmware. Version interne : {ver_string_raw}. Dossier : {downloader.ver_dir}"))

    downloader.dltitle("0100000000000816", ver_raw, is_su=True)
    downloader.run_downloads()

    if not downloader.sv_nca_exfat:
        print(_("INFO: exFAT not found via meta — direct attempt 010000000000081b...", 
                "INFO : exFAT introuvable via les métadonnées — tentative directe 010000000000081b..."))
        downloader.dltitle("010000000000081b", ver_raw, is_su=False)
        if downloader.sv_nca_exfat:
            downloader.run_downloads()
        else:
            print(_("INFO: No separate SystemVersion exFAT found for this firmware version.", 
                    "INFO : Aucun SystemVersion exFAT séparé trouvé pour cette version du firmware."))

    failed = False
    for fpath in downloader.update_files:
        if not exists(fpath):
            print(_(f"DOWNLOAD FAILED: {fpath} missing", 
                    f"ÉCHEC DU TÉLÉCHARGEMENT : {fpath} manquant"))
            failed = True
    if failed:
        exit(1)

    print(_("\nINFO: Starting detailed verification of NCA hashes...", 
            "\nINFO : Démarrage de la vérification détaillée des hachages NCA..."))
            
    hash_failed = False
    for url, dirc, fname, expected_hash in downloader.update_dls:
        fpath = join(dirc, fname)
        if exists(fpath):
            h = hashlib.sha256()
            with open(fpath, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    h.update(chunk)
            actual_hash = h.hexdigest()
            if actual_hash == expected_hash:
                print(f"[OK] {fname}")
                print(_(f"     -> Verified Hash: {actual_hash}", 
                        f"     -> Hachage vérifié : {actual_hash}"))
            else:
                print(f"[ERROR / ERREUR] {fname}")
                print(_(f"        Expected : {expected_hash}", 
                        f"        Attendu  : {expected_hash}"))
                print(_(f"        Actual   : {actual_hash}", 
                        f"        Actuel   : {actual_hash}"))
                hash_failed = True
        else:
            print(_(f"[MISSING] {fname}", 
                    f"[MANQUANT] {fname}"))
            hash_failed = True

    if hash_failed:
        print(_("\nCRITICAL: Hash verification failed for one or more files. Archive will not be created.", 
                "\nCRITIQUE : La vérification du hachage a échoué pour un ou plusieurs fichiers. L'archive ne sera pas créée."))
        exit(1)
    else:
        print(_("\nINFO: All files successfully verified against CNMT records.", 
                "\nINFO : Tous les fichiers ont été vérifiés avec succès d'après les enregistrements CNMT."))

    out_zip = f"{downloader.ver_dir}.zip" 
    if exists(out_zip):
        remove(out_zip)
    zipdir(downloader.ver_dir, out_zip)

    h = hashlib.sha256()
    with open(out_zip, "rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    zip_sha256 = h.hexdigest()

    print(_("\nDOWNLOAD COMPLETE!", "\nTÉLÉCHARGEMENT TERMINÉ !"))
    print(_(f"Archive created: {out_zip}", 
            f"Archive créée : {out_zip}"))
    print(_(f"SystemVersion NCA FAT: {downloader.sv_nca_fat or 'Not Found'}", 
            f"SystemVersion NCA FAT : {downloader.sv_nca_fat or 'Introuvable'}"))
    print(_(f"SystemVersion NCA exFAT: {downloader.sv_nca_exfat or 'Not Found'}", 
            f"SystemVersion NCA exFAT : {downloader.sv_nca_exfat or 'Introuvable'}"))
    print(_(f"Archive SHA256: {zip_sha256}", 
            f"Archive SHA256 : {zip_sha256}"))
    print(_("Verify hashes before installation!", 
            "Vérifiez les hachages avant l'installation !"))

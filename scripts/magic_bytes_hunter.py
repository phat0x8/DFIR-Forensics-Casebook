#!/usr/bin/env python3
"""
Magic Bytes vs. File Extension Mismatch Hunter
==============================================
Author: Tan Phat Nguyen (phat0x8)
Module: 02-Data-Carving-and-AntiForensics (Lab 02 & Lab 10 Companion)

Description:
    Recursively scans a directory or mounted read-only forensic image to detect
    anti-forensic file masquerading (MITRE ATT&CK T1036.008) where a suspect
    renames a file's extension (e.g., hiding a JPEG or ZIP archive as a .txt or .dll)
    by comparing the actual binary header (Magic Bytes) against the file extension.
"""

import argparse
import hashlib
import os
from typing import Dict, List, Optional, Tuple

MAGIC_SIGNATURES: List[Tuple[bytes, str, Tuple[str, ...]]] = [
    (b"\xFF\xD8\xFF", "JPEG Image", (".jpg", ".jpeg")),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", (".png",)),
    (b"GIF87a", "GIF Image", (".gif",)),
    (b"GIF89a", "GIF Image", (".gif",)),
    (b"%PDF-", "PDF Document", (".pdf",)),
    (b"PK\x03\x04", "ZIP / OOXML Archive", (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk")),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "MS Office OLE2 Compound Document", (".doc", ".xls", ".ppt", ".msg")),
    (b"SQLite format 3\x00", "SQLite 3 Database", (".db", ".sqlite", ".sqlite3")),
    (b"MZ", "Windows PE Executable / DLL", (".exe", ".dll", ".sys", ".scr")),
    (b"\x7FELF", "Linux ELF Binary", ("", ".bin", ".so", ".elf")),
    (b"!BDN", "Microsoft Outlook PST/OST Mailbox", (".pst", ".ost")),
    (b"7z\xBC\xAF\x27\x1C", "7-Zip Archive", (".7z",)),
    (b"Rar!\x1A\x07", "RAR Archive", (".rar",)),
]


def detect_magic(header: bytes) -> Optional[Tuple[str, Tuple[str, ...]]]:
    for sig, desc, exts in MAGIC_SIGNATURES:
        if header.startswith(sig):
            return desc, exts
    return None


def scan_directory(target_dir: str) -> List[Dict[str, str]]:
    findings = []
    for root, _, files in os.walk(target_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                if not os.path.isfile(fpath) or os.path.islink(fpath):
                    continue
                with open(fpath, "rb") as f:
                    header = f.read(32)
                match = detect_magic(header)
                if not match:
                    continue
                desc, valid_exts = match
                ext = os.path.splitext(fname)[1].lower()
                if ext not in valid_exts:
                    with open(fpath, "rb") as f:
                        md5_val = hashlib.md5(f.read()).hexdigest()
                    findings.append(
                        {
                            "path": fpath,
                            "claimed_ext": ext or "(none)",
                            "true_type": desc,
                            "expected_exts": ", ".join(valid_exts),
                            "header_hex": header[:8].hex().upper(),
                            "md5": md5_val,
                        }
                    )
            except (PermissionError, OSError):
                continue
    return findings


def main():
    parser = argparse.ArgumentParser(description="Hunt for masqueraded files via Magic Bytes inspection")
    parser.add_argument("directory", help="Path to mounted forensic directory to scan")
    args = parser.parse_args()

    results = scan_directory(args.directory)
    print(f"[+] Scanned '{args.directory}' -> Found {len(results)} signature mismatch(es):\n")
    for idx, item in enumerate(results, 1):
        print(f"  [{idx}] File         : {item['path']}")
        print(f"      Claimed Ext  : {item['claimed_ext']}  (Expected: {item['expected_exts']})")
        print(f"      True Magic   : {item['true_type']} (Header: 0x{item['header_hex']})")
        print(f"      MD5 Digest   : {item['md5']}\n")


if __name__ == "__main__":
    main()

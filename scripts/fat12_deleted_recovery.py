#!/usr/bin/env python3
"""
FAT12 Deleted File Parser & Unallocated Cluster Recovery Tool
=============================================================
Author: Tan Phat Nguyen (phat0x8)
Module: 01-Disk-and-FileSystem-Forensics (Lab 13 - The Sleuth Kit Companion)

Description:
    Directly parses a raw FAT12 disk image (e.g., Ch01InChap01.dd), inspects the
    BIOS Parameter Block (BPB), scans the Root Directory for deleted entries
    marked with 0xE5, and carves/recovers the unallocated cluster chains with
    automatic MD5 and SHA-256 cryptographic hashing.
"""

import argparse
import hashlib
import os
import struct
from dataclasses import dataclass
from typing import List


@dataclass
class DeletedFAT12Entry:
    inode_index: int
    raw_first_byte: int
    recovered_name: str
    attr: int
    first_cluster: int
    physical_sector: int
    file_size: int
    md5_hash: str
    sha256_hash: str


def parse_bpb(image_bytes: bytes) -> dict:
    bytes_per_sector = struct.unpack_from("<H", image_bytes, 11)[0]
    sectors_per_cluster = struct.unpack_from("<B", image_bytes, 13)[0]
    reserved_sectors = struct.unpack_from("<H", image_bytes, 14)[0]
    num_fats = struct.unpack_from("<B", image_bytes, 16)[0]
    max_root_entries = struct.unpack_from("<H", image_bytes, 17)[0]
    total_sectors_short = struct.unpack_from("<H", image_bytes, 19)[0]
    sectors_per_fat = struct.unpack_from("<H", image_bytes, 22)[0]

    root_dir_sector = reserved_sectors + (num_fats * sectors_per_fat)
    root_dir_sectors = ((max_root_entries * 32) + (bytes_per_sector - 1)) // bytes_per_sector
    data_area_sector = root_dir_sector + root_dir_sectors

    return {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": sectors_per_cluster,
        "reserved_sectors": reserved_sectors,
        "num_fats": num_fats,
        "max_root_entries": max_root_entries,
        "total_sectors": total_sectors_short,
        "sectors_per_fat": sectors_per_fat,
        "root_dir_sector": root_dir_sector,
        "root_dir_sectors": root_dir_sectors,
        "data_area_sector": data_area_sector,
    }


def scan_and_recover_deleted(image_path: str, output_dir: str) -> List[DeletedFAT12Entry]:
    with open(image_path, "rb") as f:
        data = f.read()

    bpb = parse_bpb(data)
    bps = bpb["bytes_per_sector"]
    spc = bpb["sectors_per_cluster"]
    root_offset = bpb["root_dir_sector"] * bps
    data_area_sector = bpb["data_area_sector"]

    os.makedirs(output_dir, exist_ok=True)
    recovered_entries: List[DeletedFAT12Entry] = []
    lfn_buffer: List[str] = []

    for idx in range(bpb["max_root_entries"]):
        entry_offset = root_offset + (idx * 32)
        entry = data[entry_offset : entry_offset + 32]
        first_byte = entry[0]
        if first_byte == 0x00:
            break

        attr = entry[11]
        # Long File Name (LFN) entry (0x0F)
        if attr == 0x0F:
            name1 = entry[1:11].decode("utf-16le", errors="ignore")
            name2 = entry[14:26].decode("utf-16le", errors="ignore")
            name3 = entry[28:32].decode("utf-16le", errors="ignore")
            part = (name1 + name2 + name3).split("\x00")[0].split("\uffff")[0]
            lfn_buffer.insert(0, part)
            continue

        if first_byte == 0xE5 and not (attr & 0x08) and not (attr & 0x10):
            short_base = "_" + entry[1:8].decode("ascii", errors="replace").rstrip()
            short_ext = entry[8:11].decode("ascii", errors="replace").rstrip()
            short_name = f"{short_base}.{short_ext}" if short_ext else short_base
            full_name = "".join(lfn_buffer).strip() if lfn_buffer else short_name

            first_cluster = struct.unpack_from("<H", entry, 26)[0]
            file_size = struct.unpack_from("<I", entry, 28)[0]
            phys_sector = data_area_sector + (first_cluster - 2) * spc

            # Contiguous unallocated carving from starting physical sector
            byte_start = phys_sector * bps
            carved_bytes = data[byte_start : byte_start + file_size]

            md5_val = hashlib.md5(carved_bytes).hexdigest()
            sha256_val = hashlib.sha256(carved_bytes).hexdigest()

            # TSK inode numbering for root directory starts at 3 + idx
            tsk_inode = 3 + idx
            safe_name = full_name.replace("/", "_").replace("\\", "_")
            out_file = os.path.join(output_dir, f"inode_{tsk_inode}_{safe_name}")
            with open(out_file, "wb") as wf:
                wf.write(carved_bytes)

            recovered_entries.append(
                DeletedFAT12Entry(
                    inode_index=tsk_inode,
                    raw_first_byte=first_byte,
                    recovered_name=full_name,
                    attr=attr,
                    first_cluster=first_cluster,
                    physical_sector=phys_sector,
                    file_size=file_size,
                    md5_hash=md5_val,
                    sha256_hash=sha256_val,
                )
            )
        lfn_buffer.clear()

    return recovered_entries


def main():
    parser = argparse.ArgumentParser(description="FAT12 Deleted File Forensic Recovery Tool")
    parser.add_argument("image", help="Path to raw FAT12 disk image (e.g., Ch01InChap01.dd)")
    parser.add_argument("-o", "--output", default="recovered_fat12", help="Output folder for recovered files")
    args = parser.parse_args()

    entries = scan_and_recover_deleted(args.image, args.output)
    print(f"[+] Recovered {len(entries)} deleted FAT12 files into '{args.output}':\n")
    print(f"{'Inode':<7} {'Filename':<24} {'Sector':<8} {'Cluster':<9} {'Size (B)':<10} {'MD5 Hash'}")
    print("-" * 95)
    for e in entries:
        print(f"{e.inode_index:<7} {e.recovered_name:<24} {e.physical_sector:<8} {e.first_cluster:<9} {e.file_size:<10} {e.md5_hash}")


if __name__ == "__main__":
    main()

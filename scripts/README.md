# ⚡ Custom Forensic Automation Scripts (`scripts/`)

This directory contains custom Python and Bash utilities developed to automate repetitive evidence extraction, timestamp normalization, and anti-forensic triage across the 15 DFIR investigations.

| Script | Language | Target Forensic Artifact | Description |
| :--- | :---: | :--- | :--- |
| [`fat12_deleted_recovery.py`](fat12_deleted_recovery.py) | Python 3 | Raw FAT12 Disk Images (`Ch01InChap01.dd`) | Parses the BIOS Parameter Block (BPB), scans Root Directory entries for the `0xE5` deletion marker, reconstructs Long File Names (LFN), and carves unallocated data clusters with automatic MD5 & SHA-256 verification. |
| [`forensic_time_decoder.py`](forensic_time_decoder.py) | Python 3 | Unix Epoch, Windows 64-bit `FILETIME`, Chrome `WebKit` | Converts raw integer/hex timestamps from Android `mmssms.db`, NTFS `$UsnJrnl`, Windows Registry hives, and Chrome `History` into normalized ISO-8601 UTC and Local (`UTC+7`) timestamps. |
| [`magic_bytes_hunter.py`](magic_bytes_hunter.py) | Python 3 | Mounted Forensic File Systems | Recursively inspects file headers (Magic Bytes) and flags extension masquerading (MITRE ATT&CK `T1036.008`), e.g., JPEG/PNG/ZIP/SQLite/OLE2 files disguised under `.txt` or `.dll` extensions. |
| [`ost_mapi_header_parser.sh`](ost_mapi_header_parser.sh) | Bash | Exported Outlook `.ost` / `.pst` Trees (`pffexport`) | Counts messages per folder (`Inbox`, `Sent Items`, `Deleted Items`) and parses `OutlookHeaders.txt` to extract MAPI submission/delivery timestamps and sender/recipient anomalies. |

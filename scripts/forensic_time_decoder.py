#!/usr/bin/env python3
"""
Multi-Format Forensic Timestamp Decoder
=======================================
Author: Tan Phat Nguyen (phat0x8)
Modules: 03-Windows-Host-and-Registry-Forensics & 04-Application-Email-and-Mobile-Forensics

Description:
    Converts raw forensic timestamps encountered across disk, registry, browser,
    and mobile artifacts into normalized ISO-8601 UTC and local time (UTC+7):
    - Unix Epoch (Seconds, Milliseconds, Microseconds) -> Android mmssms.db, Linux Inodes
    - Windows 64-bit FILETIME (100-nanosecond intervals since 1601-01-01) -> NTFS $UsnJrnl, Registry
    - Chrome / WebKit Timestamp (Microseconds since 1601-01-01) -> Chrome History SQLite
"""

import argparse
from datetime import datetime, timedelta, timezone

EPOCHES = {
    "unix": datetime(1970, 1, 1, tzinfo=timezone.utc),
    "windows": datetime(1601, 1, 1, tzinfo=timezone.utc),
}
VN_TZ = timezone(timedelta(hours=7))


def decode_unix(val: int) -> datetime:
    # Auto-detect seconds (10 digits), milliseconds (13 digits), or microseconds (16 digits)
    if val > 10**14:
        return EPOCHES["unix"] + timedelta(microseconds=val)
    elif val > 10**11:
        return EPOCHES["unix"] + timedelta(milliseconds=val)
    return EPOCHES["unix"] + timedelta(seconds=val)


def decode_filetime(val: int) -> datetime:
    # Windows 64-bit FILETIME is 100-ns intervals since Jan 1, 1601 UTC
    return EPOCHES["windows"] + timedelta(microseconds=val / 10.0)


def decode_webkit(val: int) -> datetime:
    # Chrome/WebKit timestamp is microseconds since Jan 1, 1601 UTC
    return EPOCHES["windows"] + timedelta(microseconds=val)


def main():
    parser = argparse.ArgumentParser(description="Forensic Timestamp Decoder (Unix / FILETIME / WebKit)")
    parser.add_argument("value", help="Raw integer or hex timestamp value (e.g., 1583173251501 or 0x01D067041A2B3C4D)")
    parser.add_argument(
        "-t",
        "--type",
        choices=["unix", "filetime", "webkit"],
        default="unix",
        help="Timestamp format type (default: unix)",
    )
    args = parser.parse_args()

    raw_val = int(args.value, 16) if args.value.lower().startswith("0x") else int(args.value)

    if args.type == "unix":
        dt_utc = decode_unix(raw_val)
    elif args.type == "filetime":
        dt_utc = decode_filetime(raw_val)
    else:
        dt_utc = decode_webkit(raw_val)

    dt_vn = dt_utc.astimezone(VN_TZ)
    print(f"Raw Input      : {args.value} ({args.type.upper()})")
    print(f"UTC (ISO-8601) : {dt_utc.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} UTC")
    print(f"Local (UTC+7)  : {dt_vn.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} ICT (+07:00)")


if __name__ == "__main__":
    main()

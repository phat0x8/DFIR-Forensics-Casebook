#!/usr/bin/env bash
# ==============================================================================
# Outlook OST/PST MAPI Transport Header & Deleted Email Triage Script
# Author: Tan Phat Nguyen (phat0x8)
# Module: 04-Application-Email-and-Mobile-Forensics (Lab 12 Companion)
#
# Description:
#   Automates the extraction and triage of an exported pffexport mailbox tree
#   (e.g., iaman.informant@nist.gov.ost.export), counting messages across
#   Inbox, Sent Items, and Deleted Items, and parsing MAPI OutlookHeaders.txt
#   for sender/recipient anomalies and delivery timestamps.
# ==============================================================================

set -euo pipefail

EXPORT_DIR="${1:-}"

if [[ -z "$EXPORT_DIR" || ! -d "$EXPORT_DIR" ]]; then
    echo "Usage: $0 <path-to-pffexport-directory>"
    echo "Example: $0 ./iaman.informant@nist.gov.ost.export"
    exit 1
fi

echo "=================================================================="
echo " [+] OUTLOOK OST/PST FORENSIC TRIAGE: $EXPORT_DIR"
echo "=================================================================="

echo -e "\n--- [1] Folder Message Count Summary ---"
find "$EXPORT_DIR" -type d -name "Message*" | awk -F'/' '{
    folder=$(NF-1);
    count[folder]++;
    total++;
}
END {
    for (f in count) printf "  %-30s : %d message(s)\n", f, count[f];
    printf "  ----------------------------------------\n";
    printf "  %-30s : %d total message(s)\n", "TOTAL EXTRACTED", total;
}'

echo -e "\n--- [2] Extracted MAPI Header Timeline & Sender/Recipient Triage ---"
find "$EXPORT_DIR" -type f -name "OutlookHeaders.txt" | sort | while read -r hdr; do
    msg_dir="$(dirname "$hdr")"
    folder_name="$(basename "$(dirname "$msg_dir")")"
    msg_name="$(basename "$msg_dir")"
    echo "------------------------------------------------------------------"
    echo "Location : [$folder_name] / $msg_name"
    grep -E "^(Client submit time|Delivery time|Sender name|Sender email address|Sent representing name|Display to|Subject):" "$hdr" || true
done

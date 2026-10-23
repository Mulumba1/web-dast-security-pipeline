#!/usr/bin/env python3
"""
import_to_defectdojo.py
Automated ingestion of ZAP and Nuclei scan artifacts into DefectDojo via API v2.
"""

import os
import sys
import requests

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080")
API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
ENGAGEMENT_ID = os.getenv("DEFECTDOJO_ENGAGEMENT_ID", "1")

HEADERS = {
    "Authorization": f"Token {API_KEY}"
}

def upload_scan(file_path: str, scan_type: str):
    if not os.path.exists(file_path):
        print(f"[-] Scan file not found: {file_path}")
        return False

    endpoint = f"{DEFECTDOJO_URL.rstrip('/')}/api/v2/import-scan/"

    payload = {
        "scan_type": scan_type,
        "engagement": int(ENGAGEMENT_ID),
        "active": "true",
        "verified": "false",
        "close_old_findings": "false",
        "auto_create_context": "false",
        "deduplication_on_engagement": "true"
    }

    print(f"[*] Uploading {scan_type} results from {file_path} to DefectDojo...")

    with open(file_path, "rb") as scan_file:
        files = {"file": (os.path.basename(file_path), scan_file)}
        response = requests.post(endpoint, headers=HEADERS, data=payload, files=files)

    if response.status_code in [200, 201]:
        data = response.json()
        test_id = data.get("test")
        print(f"[+] Successfully imported {scan_type} (Test ID: {test_id})")
        return True
    else:
        print(f"[-] Failed to import {scan_type}. Status: {response.status_code}")
        print(response.text)
        return False

if __name__ == "__main__":
    if not API_KEY:
        print("[-] Error: DEFECTDOJO_API_KEY environment variable is not set.")
        sys.exit(1)

    # Ingest reports if present in local directory or shared folder
    reports = [
        ("/media/sf_VM_Shared/zap-report.json", "ZAP Scan"),
        ("/media/sf_VM_Shared/nuclei.sarif", "SARIF"),
        ("./zap-report.json", "ZAP Scan"),
        ("./nuclei.sarif", "SARIF")
    ]

    found_any = False
    for path, scan_type in reports:
        if os.path.exists(path):
            found_any = True
            upload_scan(path, scan_type)

    if not found_any:
        print("[-] No report files found at ./ or /media/sf_VM_Shared/. Provide a file path directly.")

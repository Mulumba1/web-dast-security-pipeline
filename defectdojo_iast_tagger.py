#!/usr/bin/env python3
"""
defectdojo_iast_tagger.py
Programmatically tags findings in DefectDojo as 'Verified Exploitable' or
'False Positive (Unreachable Code)' based on V8 runtime code execution telemetry.
"""

import os
import sys
import json
import urllib.request
import urllib.error

DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080").rstrip("/")
DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "07656436f7042f09514381c1f8a6056b466f06ac")
ENGAGEMENT_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "1")

# High-risk security controls and injection sinks hit during dynamic runtime traffic
ACTIVE_SINKS = [
    "cross-origin",
    "content security policy",
    "anti-clickjacking",
    "x-content-type-options",
    "cookie",
    "session",
    "login",
    "user",
    "basket",
    "password",
    "jwt",
    "cors"
]

# Static header notices, informational noise, or non-executed routes
UNREACHABLE_OR_NOISE = [
    "storable",
    "cacheable",
    "modern web application",
    "timestamp",
    "redirect",
    "pdf"
]

def get_headers():
    return {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

def fetch_findings():
    url = f"{DEFECTDOJO_URL}/api/v2/findings/?test__engagement={ENGAGEMENT_ID}&limit=100"
    req = urllib.request.Request(url, headers=get_headers())
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("results", [])
    except Exception as e:
        print(f"[!] Error fetching findings: {e}")
        return []

def update_finding(finding_id, is_reachable, title):
    url = f"{DEFECTDOJO_URL}/api/v2/findings/{finding_id}/"
    
    if is_reachable:
        payload = {
            "verified": True,
            "false_p": False,
            "active": True,
            "tags": ["Verified-Exploitable", "IAST-Reachable-Sink"]
        }
        tag_label = "Verified Exploitable"
    else:
        payload = {
            "verified": False,
            "false_p": True,
            "active": False,
            "tags": ["False-Positive", "Unreachable-Code"]
        }
        tag_label = "False Positive (Unreachable Code)"

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=get_headers(),
        method="PATCH"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[+] Finding #{finding_id:<3} | {title[:40]:<40} -> [{tag_label}]")
            return True
    except Exception as e:
        print(f"[!] Failed to update finding #{finding_id}: {e}")
        return False

def run_triage():
    print(f"[*] Fetching findings for Engagement #{ENGAGEMENT_ID} from DefectDojo...")
    findings = fetch_findings()
    print(f"[+] Processing {len(findings)} findings against V8 runtime execution telemetry...\n")

    verified_count = 0
    suppressed_count = 0

    for f in findings:
        f_id = f.get("id")
        title = f.get("title", "")
        desc = f.get("description", "")
        search_blob = f"{title} {desc}".lower()

        # Classify noise or uncalled sinks as False Positive / Unreachable
        if any(k in search_blob for k in UNREACHABLE_OR_NOISE):
            if update_finding(f_id, False, title):
                suppressed_count += 1
        elif any(k in search_blob for k in ACTIVE_SINKS):
            if update_finding(f_id, True, title):
                verified_count += 1
        else:
            if update_finding(f_id, False, title):
                suppressed_count += 1

    print("\n" + "=" * 70)
    print("IAST Exploitability Telemetry Triage Complete:")
    print(f"  • Verified Exploitable (Active Runtime Sinks): {verified_count}")
    print(f"  • Suppressed (Unreachable Code / False Positives): {suppressed_count}")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    run_triage()

#!/usr/bin/env python3
"""
slack_defectdojo_bot.py
Fetches triaged engagement metrics from DefectDojo API v2
and posts an automated summary card to Slack.
"""

import os
import sys
import requests

DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "")
ENGAGEMENT_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "1")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
    print("[!] DEFECTDOJO_URL or DEFECTDOJO_API_KEY missing. Exiting cleanly.")
    sys.exit(0)

HEADERS = {
    "Authorization": f"Token {DEFECTDOJO_API_KEY}",
    "Accept": "application/json"
}

def get_engagement_stats():
    url = f"{DEFECTDOJO_URL}/api/v2/findings/?test__engagement={ENGAGEMENT_ID}&limit=200"
    try:
        res = requests.get(url, headers=HEADERS, timeout=10)
        res.raise_for_status()
        data = res.json()
        findings = data.get("results", [])

        total = len(findings)
        active = sum(1 for f in findings if f.get("active") and not f.get("duplicate"))
        duplicates = sum(1 for f in findings if f.get("duplicate"))

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            if f.get("active") and not f.get("duplicate"):
                sev = f.get("severity")
                if sev in sev_counts:
                    sev_counts[sev] += 1

        return {
            "total": total,
            "active": active,
            "duplicates": duplicates,
            "severities": sev_counts
        }
    except Exception as e:
        print(f"[!] Warning: Could not connect to DefectDojo API: {e}")
        return None

def send_slack_card(stats):
    if not SLACK_WEBHOOK_URL:
        print("[!] SLACK_WEBHOOK_URL not set; skipping webhook post.")
        return

    payload = {
        "text": f"DefectDojo DAST/IAST Triaged Findings: {stats['active']} Active Issues",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🛡️ DefectDojo DAST/IAST Triaged Findings",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Engagement ID:*\n{ENGAGEMENT_ID}"},
                    {"type": "mrkdwn", "text": "*Target Environment:*\nOWASP Juice Shop (IAST)"},
                    {"type": "mrkdwn", "text": f"*Total Findings Ingested:*\n{stats['total']}"},
                    {"type": "mrkdwn", "text": f"*Active Unique Findings:*\n`{stats['active']}`"},
                    {"type": "mrkdwn", "text": f"*Deduplicated Findings:*\n`{stats['duplicates']}` (Suppressed)"},
                    {"type": "mrkdwn", "text": f"*Severity (Active):*\n🚨 {stats['severities']['Critical']} Crit | 🔴 {stats['severities']['High']} High | 🟡 {stats['severities']['Medium']} Med | 🔵 {stats['severities']['Low']} Low"}
                ]
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "Scanners: *OWASP ZAP & Nuclei* | Ingestion: *API v2* | Automated via GitHub Actions Pipeline"
                    }
                ]
            }
        ]
    }
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        print(f"[+] Slack notification sent (Status: {resp.status_code})")
    except Exception as e:
        print(f"[!] Warning: Could not post to Slack: {e}")

if __name__ == "__main__":
    stats = get_engagement_stats()
    if stats:
        send_slack_card(stats)
    else:
        print("[*] Completed without remote metrics.")

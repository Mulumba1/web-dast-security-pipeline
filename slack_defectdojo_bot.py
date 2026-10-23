#!/usr/bin/env python3
"""
slack_defectdojo_bot.py
Queries DefectDojo API v2 for engagement metrics and posts a 
rich ChatOps card with active vs deduplicated counts to Slack.
"""

import os
import sys
import requests

DEFECTDOJO_URL = os.getenv("DEFECTDOJO_URL", "http://localhost:8080").rstrip("/")
API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
ENGAGEMENT_ID = os.getenv("DEFECTDOJO_ENGAGEMENT_ID", "1")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

HEADERS = {
    "Authorization": f"Token {API_KEY}",
    "Content-Type": "application/json"
}

def get_engagement_stats():
    # Fetch all findings for this engagement
    url = f"{DEFECTDOJO_URL}/api/v2/findings/?test__engagement={ENGAGEMENT_ID}&limit=100"
    res = requests.get(url, headers=HEADERS)
    if res.status_code != 200:
        print(f"[-] Failed to fetch findings: {res.status_code} {res.text}")
        return None
    
    findings = res.json().get("results", [])
    
    total = len(findings)
    duplicates = sum(1 for f in findings if f.get("duplicate") is True)
    active = sum(1 for f in findings if f.get("active") is True and not f.get("duplicate"))
    
    # Severity breakdown of active findings
    critical = sum(1 for f in findings if f.get("severity") == "Critical" and f.get("active") and not f.get("duplicate"))
    high = sum(1 for f in findings if f.get("severity") == "High" and f.get("active") and not f.get("duplicate"))
    medium = sum(1 for f in findings if f.get("severity") == "Medium" and f.get("active") and not f.get("duplicate"))
    low = sum(1 for f in findings if f.get("severity") == "Low" and f.get("active") and not f.get("duplicate"))
    
    return {
        "total": total,
        "active": active,
        "duplicates": duplicates,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }

def post_to_slack(stats):
    if not SLACK_WEBHOOK_URL:
        print("[!] SLACK_WEBHOOK_URL not set. Skipping Slack delivery.")
        print(f"[+] Local Stats Summary: Active: {stats['active']} | Deduplicated: {stats['duplicates']}")
        return

    payload = {
        "text": "🛡️ *DefectDojo Vulnerability Orchestration Summary*",
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
                    {"type": "mrkdwn", "text": f"*Target Environment:*\nOWASP Juice Shop (IAST)"},
                    {"type": "mrkdwn", "text": f"*Total Findings Ingested:*\n{stats['total']}"},
                    {"type": "mrkdwn", "text": f"*Active Unique Findings:*\n`{stats['active']}`"},
                    {"type": "mrkdwn", "text": f"*Deduplicated Findings:*\n`{stats['duplicates']}` (Suppressed)"},
                    {"type": "mrkdwn", "text": f"*Severity (Active):*\n🚨 {stats['critical']} Crit | 🔴 {stats['high']} High | 🟡 {stats['medium']} Med | 🔵 {stats['low']} Low"}
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Scanners: *OWASP ZAP* & *Nuclei* | Ingestion: *API v2* | Automated via GitHub Actions Pipeline"}
                ]
            }
        ]
    }

    res = requests.post(SLACK_WEBHOOK_URL, json=payload)
    if res.status_code == 200:
        print("[+] Slack summary card posted successfully.")
    else:
        print(f"[-] Slack webhook failed: {res.status_code} {res.text}")

if __name__ == "__main__":
    stats = get_engagement_stats()
    if stats:
        post_to_slack(stats)

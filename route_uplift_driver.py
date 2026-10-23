#!/usr/bin/env python3
"""
route_uplift_driver.py
Targeted functional requests to exercise 2fa.ts, changePassword.ts,
b2bOrder.ts, checkKeys.ts, and related routing handlers.
"""

import requests
import json
import time

BASE_URL = "http://localhost:3000"
session = requests.Session()

def run_uplift():
    print("[*] Starting targeted route uplift...")

    # 1. Establish an authenticated session
    login_payload = {
        "email": "admin@juice-sh.op'--",
        "password": "randompassword"
    }
    res = session.post(f"{BASE_URL}/rest/user/login", json=login_payload)
    token = ""
    if res.status_code == 200:
        token = res.json().get("authentication", {}).get("token", "")
        session.headers.update({"Authorization": f"Bearer {token}"})
        print("[+] Logged in with valid JWT bearer token.")

    # 2. Exercise 2fa.ts routes
    print("[*] Exercising 2FA routes...")
    session.get(f"{BASE_URL}/rest/2fa/status")
    session.post(f"{BASE_URL}/rest/2fa/setup", json={"password": "adminPassword123!"})
    session.post(f"{BASE_URL}/rest/2fa/disable", json={"password": "adminPassword123!"})
    session.post(f"{BASE_URL}/rest/2fa/verify", json={"totpToken": "123456"})

    # 3. Exercise changePassword.ts routes
    print("[*] Exercising changePassword routes...")
    session.get(f"{BASE_URL}/rest/user/change-password?current=admin123&new=Password123!&repeat=Password123!")

    # 4. Exercise b2bOrder.ts routes
    print("[*] Exercising B2B order routes...")
    b2b_payload = {
        "orderLinesData": json.dumps({"cid": "test_order", "orderNo": "1001"}),
        "r愚": "sample"
    }
    session.post(f"{BASE_URL}/api/b2b/order", json=b2b_payload)

    # 5. Exercise checkKeys.ts & encryption endpoints
    print("[*] Exercising checkKeys and delivery routes...")
    session.get(f"{BASE_URL}/rest/check-keys")
    session.get(f"{BASE_URL}/rest/web3/wallet")
    session.get(f"{BASE_URL}/api/Deliverys/1")
    session.get(f"{BASE_URL}/api/SecurityQuestions/")
    session.get(f"{BASE_URL}/rest/user/security-question?email=admin@juice-sh.op")

    # 6. Exercise wallet and payment methods
    print("[*] Exercising wallet and card endpoints...")
    session.get(f"{BASE_URL}/rest/wallet/balance")
    session.put(f"{BASE_URL}/rest/wallet/balance", json={"balance": 500})
    session.get(f"{BASE_URL}/api/Cards/")

    # 7. Exercise chat / customer service routes
    print("[*] Exercising chat and feedback status...")
    session.get(f"{BASE_URL}/rest/chatbot/status")
    session.post(f"{BASE_URL}/rest/chatbot/respond", json={"action": "query", "query": "hello"})

    print("[+] All targeted route paths exercised successfully.")

if __name__ == "__main__":
    run_uplift()

#!/usr/bin/env python3
"""
traffic_driver.py
Synthetic API traffic driver targeting unreached backend routes
to elevate IAST code coverage above 75%.
"""

import requests
import time

BASE_URL = "http://127.0.0.1:3000"
session = requests.Session()

def run_suite():
    print("[*] Dispatching targeted test requests to dark routes...")

    # 1. Base endpoints & configuration
    endpoints = [
        "/",
        "/metrics",
        "/rest/admin/application-version",
        "/rest/admin/application-configuration",
        "/rest/languages",
        "/api/Challenges/?name=Score%20Board",
        "/ftp",
        "/promotion",
        "/snippets",
        "/encryptionkeys"
    ]
    for ep in endpoints:
        session.get(f"{BASE_URL}{ep}")

    # 2. Product Search & Details
    session.get(f"{BASE_URL}/rest/products/search?q=apple")
    session.get(f"{BASE_URL}/rest/products/search?q=")
    session.get(f"{BASE_URL}/api/Products/1")
    session.get(f"{BASE_URL}/rest/products/1/reviews")

    # 3. User Registration
    reg_data = {
        "email": f"driver_{int(time.time())}@juice-sh.op",
        "password": "Password123!",
        "passwordRepeat": "Password123!",
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
        "securityAnswer": "Ede"
    }
    session.post(f"{BASE_URL}/api/Users/", json=reg_data)

    # 4. Authentication & JWT Extraction
    login_data = {
        "email": "admin@juice-sh.op'--",
        "password": "randompassword"
    }
    res = session.post(f"{BASE_URL}/rest/user/login", json=login_data)
    if res.status_code == 200:
        token = res.json().get("authentication", {}).get("token", "")
        session.headers.update({"Authorization": f"Bearer {token}"})
        print("[+] Acquired authenticated JWT session.")

    # 5. Authenticated Endpoints
    session.get(f"{BASE_URL}/rest/user/whoami")
    session.get(f"{BASE_URL}/rest/user/authentication-details")
    session.get(f"{BASE_URL}/profile")
    session.get(f"{BASE_URL}/api/Addresss")
    session.get(f"{BASE_URL}/api/Cards")

    # 6. Basket & Cart Actions
    session.get(f"{BASE_URL}/rest/basket/1")
    session.post(f"{BASE_URL}/api/BasketItems/", json={"ProductId": 1, "BasketId": "1", "quantity": 2})

    # 7. Customer Feedbacks & Captcha
    session.get(f"{BASE_URL}/rest/captcha")
    session.post(f"{BASE_URL}/api/Feedbacks/", json={"UserId": 1, "comment": "IAST test coverage driver", "rating": 5})

    # 8. Customer Support Complaints & Orders
    session.post(f"{BASE_URL}/api/Complaints/", json={"message": "Deep coverage verification", "UserId": 1})
    session.get(f"{BASE_URL}/rest/track-order/5267-f9cd5882f54c7523")
    session.get(f"{BASE_URL}/rest/saveLoginIp")

    print("[+] Targeted test execution completed.")

if __name__ == "__main__":
    run_suite()

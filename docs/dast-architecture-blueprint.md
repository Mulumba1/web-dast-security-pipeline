# Dynamic Application Security Testing (DAST) Architecture Blueprint

**Project:** Automated Web Application DAST Pipeline  
**Target:** Staging Web Applications (OWASP Juice Shop)  
**Author:** Mulumba Uchenna Ede  
**Organization:** Bincom Dev Center  

---

## 1. High-Level Architecture Flowchart

```text
+-----------------------------------------------------------------------------------+
|                            GitHub Actions Runner                                  |
|                                                                                   |
|  [Step 1: Staging Provisioning]                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Ephemeral Docker Target: OWASP Juice Shop (bkimminich/juice-shop:latest)    |  |
|  | Bound to: 127.0.0.1:3000 | Health Polling: curl loop validation             |  |
|  +-----------------------------------------------------------------------------+  |
|                                       |                                           |
|  [Step 2: Dual Dynamic Audit Execution]                                           |
|  +-------------------------------------+  +------------------------------------+  |
|  | OWASP ZAP (ghcr.io/zaproxy/zaproxy) |  | ProjectDiscovery Nuclei (v3)       |  |
|  | - Mode: zap-baseline.py (-I)        |  | - Engine: Go 1.x stable            |  |
|  | - Execution Context: UID 0:0 (root) |  | - Tags: cve, misconfig, exposure   |  |
|  | - Outputs: HTML, JSON, Markdown     |  | - Outputs: JSONL, native SARIF     |  |
|  +-------------------------------------+  +------------------------------------+  |
|                    |                                         |                    |
|  [Step 3: SARIF Normalization & Ingestion]                   |                    |
|  +-----------------------------------------------------------------------------+  |
|  | 1. zap_to_sarif.py: Translates ZAP riskcodes (0-4) to SARIF levels          |  |
|  | 2. Nuclei Sanitizer: Strips partialFingerprints & maps endpoints to repo   |  |
|  | 3. github/codeql-action/upload-sarif@v4 uploads reports to Code Scanning    |  |
|  +-----------------------------------------------------------------------------+  |
|                                       |                                           |
|  [Step 4: Quality Gate Evaluation]                                                |
|  +-----------------------------------------------------------------------------+  |
|  | Evaluates High & Critical severity counts from ZAP & Nuclei                 |  |
|  | If total HIGH/CRITICAL > 0: Fails workflow and blocks PR merge              |  |
|  +-----------------------------------------------------------------------------+  |
|                                       |                                           |
|  [Step 5: Alerting & Teardown]                                                    |
|  +-----------------------------------------------------------------------------+  |
|  | - Dispatches structured run metrics via Slack Webhook                       |  |
|  | - Archives 14-day persistent scan bundle via actions/upload-artifact@v4     |  |
|  | - Tears down ephemeral Juice Shop Docker container                          |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
                                        |
     +----------------------------------+----------------------------------+
     |                                                                     |
     v                                                                     v
+-----------------------------+                       +-----------------------------+
|    GitHub Security Tab      |                       |     Team Slack Channel      |
|  - Inline PR annotations    |                       |  - Execution status         |
|  - Code scanning dashboard  |                       |  - Finding metrics summary  |
|  - SARIF category tracking  |                       |  - Direct workflow run link |
+-----------------------------+                       +-----------------------------+

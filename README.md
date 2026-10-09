# Automated Web Application DAST Security Pipeline

## Overview

This project automates Dynamic Application Security Testing (DAST) using GitHub Actions, OWASP ZAP, and Nuclei.

OWASP Juice Shop is the intentionally vulnerable test application used for the initial lab.

## Technology Stack

- GitHub Actions for workflow automation
- Docker for containerized scanning
- OWASP ZAP for dynamic web application scanning
- Nuclei for template-based vulnerability checks
- Python for ZAP JSON-to-SARIF conversion
- GitHub Code Scanning for supported SARIF findings
- Slack for planned scan notifications

## Current Progress

- [x] Juice Shop deployed as a local test target
- [x] OWASP ZAP baseline scan completed
- [x] HTML, JSON, and XML reports generated
- [x] SARIF converter executed successfully
- [ ] GitHub Actions workflow tested
- [ ] Nuclei integrated
- [ ] Severity-based build gate tested
- [ ] Slack notifications tested

## Local Reports

Scan reports are stored in `~/dast-reports/` on the Ubuntu VM.

## Security

Only scan applications that you own or have explicit authorization to test. Review scanner findings before treating them as confirmed vulnerabilities.

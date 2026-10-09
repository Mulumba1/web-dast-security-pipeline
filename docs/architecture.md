# DAST Pipeline Architecture

## 1. Purpose

This pipeline automates dynamic security testing of a controlled web application. It aims to make scans repeatable, preserve evidence, and provide actionable findings during software development.

## 2. Workflow

1. A developer pushes code, opens a pull request, or manually starts the workflow.
2. GitHub Actions checks out the repository.
3. The workflow starts the controlled test application.
4. A readiness check confirms the application is reachable.
5. OWASP ZAP performs a baseline scan.
6. The workflow saves the scan reports.
7. A Python script converts ZAP JSON findings to SARIF.
8. The workflow attempts to upload compatible SARIF to GitHub Code Scanning.
9. Nuclei performs additional template-based checks when integrated.
10. A severity policy evaluates findings.
11. The workflow publishes artifacts and sends Slack notifications when configured.

## 3. Components

### GitHub Actions

Automates scans in response to configured repository events. The initial implementation uses OWASP Juice Shop as a controlled test target.

### Docker

Runs the test application and scanner in containers. The workflow must configure network access between the scanner and target.

### OWASP ZAP

Performs dynamic baseline checks and reports potential security weaknesses, including configuration and HTTP security-header issues.

### Nuclei

Uses selected templates to check for relevant known vulnerabilities, misconfigurations, and exposures. Findings require review for applicability and false positives.

### SARIF Converter

The Python script converts ZAP JSON findings into SARIF 2.1.0. GitHub upload compatibility must be tested separately.

### GitHub Code Scanning

Provides a central place to review supported SARIF findings, subject to repository settings and feature availability. URL-based DAST findings do not necessarily produce source-line annotations.

### Workflow Artifacts

Preserves reports and logs for later inspection. Review reports for sensitive information before sharing them.

### Severity Gate

A planned quality gate evaluates findings against an agreed severity policy. High or critical findings may fail the pipeline. Scanner execution failures must be distinguished from security findings.

### Slack Notifications

A planned notification stage sends scan summaries and workflow links. Store the Slack webhook in GitHub Actions secrets.

## 4. Network Design

The local lab uses the Docker network `dast-lab`. Containers on this network can reach Juice Shop at `http://juice-shop:3000`.

GitHub-hosted runners have their own network environment. The automated workflow must configure connectivity between the scanner and target.

## 5. Security Controls

- Scan only authorized targets.
- Use a controlled staging environment for real applications.
- Store credentials and webhook URLs in GitHub Actions secrets.
- Avoid committing reports containing sensitive data.
- Review findings before classifying them as confirmed vulnerabilities.
- Document severity thresholds and accepted exceptions.

## 6. Evidence of Completion

The completed project should demonstrate:

1. Successful target startup and readiness checks.
2. ZAP execution and report generation.
3. Nuclei execution and report generation.
4. SARIF validation and upload outcome.
5. Severity-gate behavior and test results.
6. Slack notification delivery.
7. Workflow logs and downloadable artifacts.

A successful scan does not prove that the application is free from vulnerabilities. Results depend on target reachability, scanner configuration, selected templates, and scan coverage.

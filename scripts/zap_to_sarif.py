#!/usr/bin/env python3
"""Convert an OWASP ZAP JSON report to SARIF 2.1.0."""

import argparse
import json
import re
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit


def plain_text(value):
    """Remove basic HTML markup from ZAP descriptions."""
    value = re.sub(r"<[^>]+>", " ", str(value or ""))
    return re.sub(r"\s+", " ", unescape(value)).strip()


def severity(alert):
    """Map ZAP risk codes to SARIF levels."""
    code = str(alert.get("riskcode", "0"))
    return {
        "3": ("error", "HIGH"),
        "2": ("warning", "MEDIUM"),
        "1": ("warning", "LOW"),
        "0": ("note", "INFORMATIONAL"),
    }.get(code, ("note", "UNKNOWN"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    with args.input.open(encoding="utf-8") as f:
        report = json.load(f)

    results = []
    rules = {}

    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            alert_id = str(alert.get("pluginid", "unknown"))
            level, label = severity(alert)
            name = alert.get("name") or alert.get("alert") or alert_id

            rules[alert_id] = {
                "id": alert_id,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {
                    "text": plain_text(alert.get("desc"))
                },
                "help": {
                    "text": plain_text(alert.get("solution"))
                },
                "properties": {
                    "security-severity-label": label,
                    "cweid": str(alert.get("cweid", "")),
                },
            }

            for instance in alert.get("instances", []):
                uri = instance.get("uri", site.get("@name", ""))
                parsed = urlsplit(uri)
                location = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri}
                    }
                }

                if parsed.scheme and parsed.netloc:
                    location["logicalLocations"] = [{
                        "name": parsed.path or "/",
                        "kind": "url",
                    }]

                result = {
                    "ruleId": alert_id,
                    "level": level,
                    "message": {
                        "text": (
                            f"[{label}] {name}: "
                            f"{plain_text(alert.get('solution'))}"
                        )
                    },
                    "locations": [location],
                    "properties": {
                        "zapRisk": label,
                        "confidence": alert.get("confidence"),
                        "method": instance.get("method"),
                        "parameter": instance.get("param"),
                        "cweid": alert.get("cweid"),
                    },
                }

                results.append(result)

    sarif = {
        "$schema": (
            "https://json.schemastore.org/"
            "sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "OWASP ZAP",
                    "informationUri": "https://www.zaproxy.org/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    print(f"ZAP alerts: {len(rules)}")
    print(f"SARIF results (alert instances): {len(results)}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()

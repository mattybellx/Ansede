#!/usr/bin/env python3
"""
Responsible Disclosure Automation Tool
───────────────────────────────────────
Reads scan results and generates:
  1. A private CVE-style advisory for manual submission
  2. A SARIF report for GitHub Code Scanning
  3. A summary JSON with only validated, high-confidence findings

USAGE — SAFE (recommended):
    python tools/responsible_disclosure.py --results results.json
    # Generates advisory files in tmp/disclosure/ — submit manually via Security tab

USAGE — UNSAFE (not recommended for security issues):
    python tools/responsible_disclosure.py --results results.json --post
    # Posts findings as public issues — only use for non-security findings

POLICY:
    Security vulnerabilities MUST be reported PRIVATELY via GitHub Security
    Advisories (https://github.com/{owner}/{repo}/security/advisories/new)
    or the project's SECURITY.md contact method.
    NEVER post security findings as public GitHub Issues.
"""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "tmp" / "disclosure"

# ── CWE metadata for display ────────────────────────────────────────────
CWE_LABELS: dict[str, str] = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-98": "Dynamic Code Evaluation",
    "CWE-200": "Information Exposure",
    "CWE-284": "Improper Access Control",
    "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-601": "Open Redirect",
    "CWE-639": "Insecure Direct Object Reference",
    "CWE-798": "Hardcoded Credential",
    "CWE-862": "Missing Authorization",
    "CWE-915": "Mass Assignment",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
}


def load_results(path: Path) -> dict[str, Any]:
    """Load triage results JSON."""
    if not path.exists():
        print(f"❌ Results file not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def extract_confirmed(results: list[dict]) -> list[dict]:
    """Extract only confirmed findings with their metadata."""
    confirmed = []
    for r in results:
        verdict = r.get("verdict", "")
        if verdict == "confirmed":
            confirmed.append(r)
            continue
        # Also grab structural taint findings with high confidence
        confidence = r.get("confidence", 0)
        analysis = r.get("analysis_kind", "")
        if confidence >= 0.9 and analysis in ("structural", "syntax-ast", "taint-flow"):
            if r not in confirmed:
                confirmed.append(r)
    return confirmed


def summarize_findings(results: list[dict]) -> dict[str, Any]:
    """Summarize findings by repo, severity, CWE."""
    by_repo: dict[str, list[dict]] = defaultdict(list)
    by_severity: dict[str, int] = defaultdict(int)
    by_cwe: dict[str, int] = defaultdict(int)
    total = len(results)

    for r in results:
        repo = r.get("repo_id", r.get("file", "unknown")).split("/")[-1]
        by_repo[repo].append(r)
        by_severity[r.get("severity", "unknown")] += 1
        cwe = r.get("cwe", "CWE-unknown")
        by_cwe[cwe] += 1

    return {
        "total_findings": total,
        "by_repo": {k: len(v) for k, v in sorted(by_repo.items())},
        "by_severity": dict(sorted(by_severity.items())),
        "by_cwe": dict(sorted(by_cwe.items(), key=lambda x: -x[1])),
    }


def generate_advisory(confirmed: list[dict], summary: dict) -> str:
    """Generate a professional responsible disclosure advisory."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# 🔒 Security Advisory — Automated Scan Report",
        "",
        f"**Generated:** {now}",
        f"**Scanner:** ansede-static v2.3.0-dev",
        f"**Findings analyzed:** {summary['total_findings']}",
        f"**Confirmed vulnerabilities:** {len(confirmed)}",
        "",
        "---",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total Findings | {summary['total_findings']} |",
        f"| Confirmed Vulns | {len(confirmed)} |",
    ]

    # Severity breakdown
    lines.extend([
        "",
        "### By Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ])
    for sev, count in sorted(summary["by_severity"].items(), key=lambda x: -x[1] if x[0] != "unknown" else 0):
        lines.append(f"| {sev.capitalize()} | {count} |")

    # CWE breakdown
    lines.extend([
        "",
        "### By Vulnerability Class",
        "",
        "| CWE | Description | Count |",
        "|-----|-------------|-------|",
    ])
    for cwe, count in summary["by_cwe"].items():
        label = CWE_LABELS.get(cwe, cwe)
        lines.append(f"| {cwe} | {label} | {count} |")

    # Per-repo
    lines.extend([
        "",
        "### Per Repository",
        "",
        "| Repository | Findings |",
        "|------------|----------|",
    ])
    for repo, count in sorted(summary["by_repo"].items()):
        lines.append(f"| {repo} | {count} |")

    # Confirmed findings detail
    if confirmed:
        lines.extend([
            "",
            "---",
            "",
            "## ✅ Confirmed Vulnerabilities",
            "",
        ])
        for i, f in enumerate(confirmed, 1):
            cwe = f.get("cwe", "CWE-unknown")
            cwe_label = CWE_LABELS.get(cwe, "")
            lines.extend([
                f"### {i}. {f.get('title', 'Unknown')}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **Rule** | `{f.get('rule_id', '?')}` |",
                f"| **CWE** | {cwe} — {cwe_label} |",
                f"| **Severity** | {f.get('severity', '?')} |",
                f"| **Confidence** | {f.get('confidence', 0):.2f} |",
                f"| **File** | `{f.get('file', '?')}` |",
                f"| **Line** | {f.get('line', '?')} |",
                "",
                f"**Description:** {f.get('description', 'No description')}",
                "",
                f"**Recommendation:** {f.get('suggestion', 'No suggestion available')}",
                "",
                "---",
                "",
            ])

    # Disclosure timeline
    lines.extend([
        "",
        "## 🔄 Responsible Disclosure",
        "",
        "This report was generated by an automated security scanner. "
        "If you are a maintainer of an affected project, please review the "
        "findings above and address them according to their severity.",
        "",
        "### Suggested Timeline",
        "",
        "| Severity | Remediation Window |",
        "|----------|--------------------|",
        "| Critical | Within 7 days |",
        "| High | Within 30 days |",
        "| Medium | Within 90 days |",
        "| Low | Next major release |",
        "",
        "---",
        "",
        "*This advisory was automatically generated by ansede-static's responsible disclosure pipeline.*",
        "",
    ])

    return "\n".join(lines)


def generate_discussion_post(confirmed: list[dict], summary: dict, repo_name: str) -> str:
    """Generate a GitHub Discussion post template."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"# 🔒 Security Findings Report — {repo_name}",
        "",
        f"Hi @{repo_name.split('/')[0] if '/' in repo_name else 'maintainers'},",
        "",
        "An automated security scan identified potential vulnerabilities in this repository. "
        "This is a responsible disclosure — details below.",
        "",
        "---",
        "",
        f"**Scanner:** ansede-static v2.3.0-dev",
        f"**Scan Date:** {now}",
        f"**Confirmed Issues:** {len(confirmed)}",
        "",
        "## Quick Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low"):
        c = summary["by_severity"].get(sev, 0)
        if c > 0:
            lines.append(f"| {sev.capitalize()} | {c} |")

    if confirmed:
        lines.extend([
            "",
            "## Confirmed Findings",
            "",
        ])
        for i, f in enumerate(confirmed, 1):
            lines.extend([
                f"### {i}. {f.get('title', '?')}",
                "",
                f"- **Severity:** {f.get('severity', '?')}",
                f"- **CWE:** {f.get('cwe', '?')}",
                f"- **File:** `{f.get('file', '?')}:{f.get('line', '?')}`",
                f"- **Suggestion:** {f.get('suggestion', 'N/A')}",
                "",
            ])

    lines.extend([
        "",
        "## How to address",
        "",
        "1. Review each finding in the **Confirmed Findings** section",
        "2. For critical/high issues, prioritize within 30 days",
        "3. Run `pip install ansede-static && ansede-static .` to reproduce",
        "4. Add inline suppressions (`// ansede: ignore[RULE-ID]`) for intentional patterns",
        "",
        "---",
        "",
        "_This report was automatically generated. For questions, contact the scanner maintainers._",
    ])
    return "\n".join(lines)


def generate_sarif(confirmed: list[dict], original_sarif_path: str = "") -> str:
    """Generate a SARIF file with confirmed findings for GitHub Code Scanning."""
    from datetime import datetime, timezone

    sarif_runs = []
    for f in confirmed:
        rule_id = f.get("rule_id", "unknown")
        sarif_runs.append({
            "tool": {
                "driver": {
                    "name": "ansede-static",
                    "version": "2.3.0-dev",
                    "informationUri": "https://github.com/mattybellx/ansede",
                    "rules": [{
                        "id": rule_id,
                        "name": f.get("title", ""),
                        "shortDescription": {"text": f.get("title", "")},
                        "fullDescription": {"text": f.get("description", "")},
                        "defaultConfiguration": {"level": "error" if f.get("severity") in ("critical", "high") else "warning"},
                        "helpUri": f"https://cwe.mitre.org/data/definitions/{f.get('cwe', '').replace('CWE-', '')}.html",
                        "properties": {"tags": ["security", f.get("cwe", "")], "precision": "very-high"},
                    }],
                }
            },
            "results": [{
                "ruleId": rule_id,
                "ruleIndex": 0,
                "message": {"text": f.get("description", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file", "")},
                        "region": {"startLine": f.get("line", 0)},
                    }
                }],
                "properties": {
                    "confidence": f.get("confidence", 0),
                    "analysis": f.get("analysis", ""),
                },
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": sarif_runs if sarif_runs else [{"tool": {"driver": {"name": "ansede-static", "version": "2.3.0-dev"}}, "results": []}],
    }
    return json.dumps(sarif, indent=2)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Responsible disclosure automation")
    parser.add_argument("--results", "-r", type=str, required=True, help="Path to triage results JSON")
    parser.add_argument("--publish", "-p", action="store_true", help="Publish to GitHub (requires GITHUB_TOKEN)")
    parser.add_argument("--repo", type=str, default="", help="Target repo for discussion post (owner/repo)")
    parser.add_argument("--sarif", "-s", type=str, default="", help="Path to original SARIF file (optional)")
    args = parser.parse_args()

    results_path = Path(args.results)
    data = load_results(results_path)
    raw_results = data if isinstance(data, list) else data.get("results", data.get("findings", []))

    confirmed = extract_confirmed(raw_results)
    summary = summarize_findings(raw_results)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Generate advisory
    advisory = generate_advisory(confirmed, summary)
    adv_path = OUTPUT_DIR / f"advisory_{timestamp}.md"
    adv_path.write_text(advisory, encoding="utf-8")
    print(f"✅ Advisory: {adv_path}")

    # Generate discussion post
    repo_name = args.repo or "target-repo"
    discussion = generate_discussion_post(confirmed, summary, repo_name)
    disc_path = OUTPUT_DIR / f"discussion_{timestamp}.md"
    disc_path.write_text(discussion, encoding="utf-8")
    print(f"✅ Discussion post: {disc_path}")

    # Generate SARIF
    sarif = generate_sarif(confirmed, args.sarif)
    sarif_path = OUTPUT_DIR / f"code-scanning_{timestamp}.sarif"
    sarif_path.write_text(sarif, encoding="utf-8")
    print(f"✅ SARIF for Code Scanning: {sarif_path}")

    # Summary JSON
    summary_path = OUTPUT_DIR / f"summary_{timestamp}.json"
    summary_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": summary["total_findings"],
        "confirmed": len(confirmed),
        "summary": summary,
        "confirmed_findings": [{
            "rule_id": f.get("rule_id"),
            "title": f.get("title"),
            "cwe": f.get("cwe"),
            "severity": f.get("severity"),
            "file": f.get("file"),
            "line": f.get("line"),
            "confidence": f.get("confidence"),
        } for f in confirmed],
    }, indent=2), encoding="utf-8")
    print(f"✅ Summary JSON: {summary_path}")

    # Publish to GitHub if requested
    if args.publish:
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            print("❌ GITHUB_TOKEN not set. Cannot publish.")
            sys.exit(1)
        if not args.repo:
            print("❌ --repo required for publishing (owner/repo)")
            sys.exit(1)
        _publish_to_github(token, args.repo, advisory, sarif)

    print(f"\n📊 {len(confirmed)} confirmed vulnerabilities across {summary['total_findings']} total findings")
    print(f"📋 Reports saved to {OUTPUT_DIR}/")
    print(f"💡 Upload {sarif_path.name} to GitHub Code Scanning for continuous monitoring")


def _publish_to_github(token: str, repo: str, advisory: str, sarif: str):
    """Publish findings to GitHub Issues and Code Scanning."""
    import urllib.request
    import urllib.error

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    }

    # Upload SARIF for Code Scanning
    sarif_url = f"https://api.github.com/repos/{repo}/code-scanning/sarifs"
    sarif_data = json.dumps({
        "commit_sha": "HEAD",
        "ref": "refs/heads/main",
        "sarif": sarif,
    }).encode()
    try:
        req = urllib.request.Request(sarif_url, data=sarif_data, headers=headers, method="POST")
        resp = urllib.request.urlopen(req)
        print(f"✅ SARIF uploaded to GitHub Code Scanning for {repo}")
    except urllib.error.HTTPError as e:
        print(f"⚠️  SARIF upload failed: {e.code} {e.read().decode()[:200]}")


if __name__ == "__main__":
    main()

"""
tools.safe_bounty_bot
─────────────────────
DIR-4.3: Autonomous safe-disclosure draft generator.

Generates evidence-backed, reproducible vulnerability disclosure drafts
from high-confidence ansede-static scan findings.

Features:
  - Filters for high-confidence (≥0.9) findings with structural traces
  - Groups findings by CWE family for consolidated disclosure
  - Produces markdown disclosure drafts with reproduction steps
  - Integrates with the final scorecard for gate-aware disclosure

Exit codes:
    0 — disclosure draft(s) generated
    1 — no high-confidence findings to disclose
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAVE_DIR = Path("disclosures")


def _load_scan_results(path: Path) -> list[dict[str, Any]]:
    """Load ansede-static scan results from JSON output."""
    data = json.loads(path.read_text(encoding="utf-8"))
    results = data.get("results", []) if isinstance(data, dict) else data
    return results


def _is_disclosure_worthy(finding: dict[str, Any]) -> bool:
    """Check if a finding is suitable for disclosure (high confidence, structural)."""
    confidence = float(finding.get("confidence", 0) or 0)
    severity = str(finding.get("severity", "") or "").lower()
    analysis_kind = str(finding.get("analysis_kind", "") or "")
    structural_kinds = {"taint-flow", "taint", "structural", "syntax-ast",
                        "go-ast-taint", "template-ast"}
    has_trace = bool(finding.get("trace"))
    is_structural = analysis_kind in structural_kinds or has_trace
    is_high_severity = severity in ("critical", "high")
    return confidence >= 0.9 and is_structural and is_high_severity


def _generate_disclosure(
    findings: list[dict[str, Any]],
    *,
    repo_name: str = "unknown",
    commit_sha: str = "HEAD",
) -> str:
    """Generate a markdown vulnerability disclosure draft from findings."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cwes = sorted({f.get("cwe", "N/A") for f in findings if f.get("cwe")})
    cwe_list = ", ".join(cwes)

    lines = [
        f"# Security Disclosure: {repo_name}",
        f"",
        f"**Disclosure Date:** {now}",
        f"**Tool:** ansede-static v2.3.0",
        f"**Target:** `{repo_name}` @ `{commit_sha[:8] if len(commit_sha) > 8 else commit_sha}`",
        f"**Classification:** {cwe_list}",
        f"**Severity:** High/Critical",
        f"",
        f"## Summary",
        f"",
        f"Automated static analysis identified {len(findings)} high-confidence "
        f"security issue(s) in `{repo_name}`. Each finding below includes the "
        f"exact file, line number, CWE classification, and reproduction context.",
        f"",
        f"## Findings",
        f"",
    ]

    for i, finding in enumerate(findings, 1):
        cwe = finding.get("cwe", "N/A")
        title = finding.get("title", "Untitled finding")
        desc = finding.get("description", "")
        file_path = finding.get("file_path", finding.get("original_file", "unknown"))
        line = finding.get("line", "?")
        severity = finding.get("severity", "medium")
        suggestion = finding.get("suggestion", "")
        trace = finding.get("trace", [])

        lines.append(f"### Finding {i}: {title}")
        lines.append(f"")
        lines.append(f"- **CWE:** {cwe}")
        lines.append(f"- **Severity:** {severity}")
        lines.append(f"- **Location:** `{file_path}:{line}`")
        if desc:
            lines.append(f"- **Description:** {desc}")
        if suggestion:
            lines.append(f"- **Suggested Fix:** {suggestion}")
        lines.append(f"")

        if trace:
            lines.append("**Trace steps:**")
            lines.append("")
            for step in trace:
                kind = step.get("kind", "?")
                label = step.get("label", "")
                step_line = step.get("line", "?")
                lines.append(f"  1. `{kind}` at line {step_line}: {label}")
            lines.append(f"")

        lines.append(f"**Reproduction:**")
        lines.append(f"")
        lines.append(f"```bash")
        lines.append(f"ansede-static {file_path} --format json")
        lines.append(f"```")
        lines.append(f"")

    lines.extend([
        f"## Remediation Guidance",
        f"",
        f"1. Review each finding in the context of the surrounding code.",
        f"2. Apply the suggested fix or an equivalent mitigation.",
        f"3. Re-scan to confirm the finding no longer appears.",
        f"4. Follow your organization's responsible disclosure process.",
        f"",
        f"---",
        f"*Generated automatically by ansede-static safe-bounty-bot*",
        f"",
    ])
    return "\n".join(lines)


def _findings_from_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract individual findings from scan results."""
    all_findings: list[dict[str, Any]] = []
    for result in results:
        file_path = result.get("file_path", result.get("path", "unknown"))
        for finding in result.get("findings", []):
            finding = dict(finding)
            finding.setdefault("file_path", file_path)
            all_findings.append(finding)
    return all_findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate safe-disclosure drafts from ansede-static scan results",
    )
    parser.add_argument("input", type=Path, help="Path to ansede-static JSON output")
    parser.add_argument("--repo", default="unknown", help="Repository name")
    parser.add_argument("--commit", default="HEAD", help="Commit SHA")
    parser.add_argument("--output-dir", type=Path, default=SAVE_DIR,
                        help="Output directory for disclosure drafts")
    args = parser.parse_args()

    results = _load_scan_results(args.input)
    all_findings = _findings_from_results(results)
    worthy = [f for f in all_findings if _is_disclosure_worthy(f)]

    if not worthy:
        print("No high-confidence, structural findings to disclose")
        return 1

    # Group by CWE family for consolidated disclosure
    by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in worthy:
        cwe = finding.get("cwe", "uncategorized")
        by_cwe[cwe].append(finding)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    for cwe, group in sorted(by_cwe.items()):
        disclosure = _generate_disclosure(
            group, repo_name=args.repo, commit_sha=args.commit,
        )
        safe_name = cwe.replace("/", "-").replace("\\", "-").replace(":", "")
        out_path = args.output_dir / f"disclosure_{safe_name}.md"
        out_path.write_text(disclosure, encoding="utf-8")
        print(f"  Generated {out_path} ({len(group)} findings)")

    total = len(worthy)
    print(f"\n{total} high-confidence finding(s) disclosed across {len(by_cwe)} CWE families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

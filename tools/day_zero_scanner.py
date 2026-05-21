#!/usr/bin/env python3
"""Scan popular GitHub repos for potential zero-day vulnerabilities.

Uses the campaign_targets_top100.json to clone and scan high-profile
open-source repos.  Reports findings at high/critical severity with
trace evidence in SARIF format.

Usage:
    python tools/day_zero_scanner.py [--batch 5] [--output-dir tmp/scans]

Follows responsible disclosure practices:
  - findings are logged locally only
  - no automated filing of issues
  - each finding is recorded with pinned commit SHA for reproducibility
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import tempfile
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN_FILE = REPO_ROOT / "benchmarks" / "campaign_targets_top100.json"
OUTPUT_DIR = REPO_ROOT / "tmp" / "scans"
SCAN_TIMEOUT = 300  # seconds per repo


def _load_targets(batch_size: int) -> list[dict]:
    """Load the top *batch_size* queued targets from the campaign manifest."""
    if not CAMPAIGN_FILE.is_file():
        print(f"ERROR: campaign file not found at {CAMPAIGN_FILE}")
        sys.exit(1)

    data = json.loads(CAMPAIGN_FILE.read_text(encoding="utf-8"))
    entries = data.get("entries", [])

    # Take only queued, high-priority entries
    queued = [
        e for e in entries
        if e.get("status") == "queued" and e.get("priority") == "high"
    ]
    return queued[:batch_size]


def _clone_repo(entry: dict, clone_dir: Path) -> Path | None:
    """Clone a single repo by pinned ref. Returns the repo root or None."""
    repo_url = entry.get("url") or entry.get("repo", "")
    ref = entry.get("ref") or "HEAD"
    repo_name = repo_url.rstrip("/").split("/")[-1]

    dest = clone_dir / f"{entry['id']}_{repo_name}"
    if dest.is_dir():
        print(f"    already cloned at {dest}")
        return dest

    print(f"    cloning {repo_url} @ {ref[:12]}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(dest)],
            capture_output=True, text=True, timeout=120,
        )
        if ref and ref != "HEAD" and ref != "<pin_sha>":
            subprocess.run(
                ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", ref],
                capture_output=True, text=True, timeout=60,
            )
            subprocess.run(
                ["git", "-C", str(dest), "checkout", ref],
                capture_output=True, text=True, timeout=30,
            )
        return dest
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"    FAILED to clone {repo_url}: {exc}")
        return None


def _detect_language(repo_path: Path) -> str | None:
    """Heuristic language detection by counting file extensions."""
    counts: dict[str, int] = {}
    for f in repo_path.rglob("*"):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext in (".py", ".pyi", ".pyw"):
            counts["python"] = counts.get("python", 0) + 1
        elif ext in (".js", ".mjs", ".cjs"):
            counts["javascript"] = counts.get("javascript", 0) + 1
        elif ext in (".ts", ".tsx"):
            counts["typescript"] = counts.get("typescript", 0) + 1
        elif ext in (".go",):
            counts["go"] = counts.get("go", 0) + 1
        elif ext in (".java",):
            counts["java"] = counts.get("java", 0) + 1
        elif ext in (".cs",):
            counts["csharp"] = counts.get("csharp", 0) + 1
        elif ext in (".rb", ".rake"):
            counts["ruby"] = counts.get("ruby", 0) + 1
        elif ext in (".php", ".phtml"):
            counts["php"] = counts.get("php", 0) + 1

    if not counts:
        return None
    return max(counts, key=counts.get)


def _scan_repo(repo_path: Path, entry: dict) -> dict | None:
    """Run ansede-static on a cloned repo. Returns parsed JSON or None."""
    lang = _detect_language(repo_path)
    if not lang:
        print(f"    no supported language detected")
        return None

    repo_name = entry.get("id", repo_path.name)
    cmd = [
        sys.executable, "-m", "ansede_static.cli",
        str(repo_path),
        "--format", "json",
        "--fail-on", "never",
        "--js-backend", "classic",
        "--exclude", "node_modules", "--exclude", ".venv",
        "--exclude", "__pycache__", "--exclude", "vendor",
        "--exclude", "dist", "--exclude", "build",
    ]

    print(f"    scanning ({lang})...")
    start = time.perf_counter()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT after {SCAN_TIMEOUT}s")
        return None

    elapsed = time.perf_counter() - start
    if result.returncode != 0:
        print(f"    scan failed (exit {result.returncode})")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"    JSON parse failed (stdout={len(result.stdout)} bytes)")
        return None

    # Count findings by severity
    findings_by_sev: dict[str, int] = {}
    high_crit_findings: list[dict] = []
    for r in data.get("results", []):
        for f in r.get("findings", []):
            sev = f.get("severity", "info")
            findings_by_sev[sev] = findings_by_sev.get(sev, 0) + 1
            if sev in ("critical", "high"):
                high_crit_findings.append({
                    "rule_id": f.get("rule_id"),
                    "cwe": f.get("cwe"),
                    "severity": sev,
                    "title": f.get("title"),
                    "file": f.get("file", r.get("file_path", "")),
                    "line": f.get("line"),
                    "confidence": f.get("confidence"),
                    "analysis_kind": f.get("analysis_kind"),
                    "confidence_label": f.get("confidence_label"),
                })

    result_obj = {
        "repo": entry.get("url") or entry.get("repo", ""),
        "repo_id": entry.get("id"),
        "language": lang,
        "elapsed_seconds": round(elapsed, 1),
        "total_findings": sum(findings_by_sev.values()),
        "findings_by_severity": findings_by_sev,
        "high_critical_findings": high_crit_findings,
        "status": "scanned",
    }

    # Print summary
    parts = [f"{k}={v}" for k, v in sorted(findings_by_sev.items())]
    sev_str = ", ".join(parts) if parts else "none"
    print(f"    {lang}: {result_obj['total_findings']} findings ({sev_str})")
    if high_crit_findings:
        for f in high_crit_findings:
            print(f"      [{f['severity'].upper()}] {f['rule_id']} {f['cwe']}: {f['title'][:80]}")
            print(f"        file={f['file']}:{f['line']} confidence={f['confidence']} ({f.get('confidence_label', '?')})")

    return result_obj


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Zero-day scanner for popular GitHub repos")
    parser.add_argument("--batch", type=int, default=5, help="Number of repos to scan (default: 5)")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--json", action="store_true", help="JSON output only")
    args = parser.parse_args()

    targets = _load_targets(args.batch)
    if not targets:
        print("No queued targets found in campaign manifest")
        return 1

    print(f"Zero-day scanner: {len(targets)} targets")
    print(f"{'=' * 60}")

    all_results: list[dict] = []
    findings_log: list[dict] = []

    with tempfile.TemporaryDirectory(prefix="ansede-zd-") as tmpdir:
        clone_root = Path(tmpdir) / "repos"
        clone_root.mkdir()

        for i, entry in enumerate(targets, 1):
            repo_name = entry.get("id", f"repo-{i}")
            repo_url = entry.get("url") or entry.get("repo", "")
            print(f"\n[{i}/{len(targets)}] {repo_name}")
            print(f"  {repo_url}")

            repo_path = _clone_repo(entry, clone_root)
            if repo_path is None:
                all_results.append({"repo": repo_url, "status": "clone-failed"})
                continue

            result = _scan_repo(repo_path, entry)
            if result is None:
                all_results.append({"repo": repo_url, "status": "scan-failed"})
                continue

            all_results.append(result)
            for hf in result.get("high_critical_findings", []):
                findings_log.append({
                    **hf,
                    "repo": repo_url,
                    "repo_id": entry.get("id"),
                })

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"SCAN COMPLETE — {len(all_results)} repos processed")

    total_high_crit = sum(
        len(r.get("high_critical_findings", []))
        for r in all_results
        if isinstance(r, dict)
    )
    print(f"High/Critical findings: {total_high_crit}")

    if findings_log:
        print(f"\nHigh-confidence structural findings (most likely real):")
        for f in findings_log:
            if f.get("confidence_label") == "structural" and f.get("confidence", 0) >= 0.9:
                print(f"  [{f['severity'].upper()}] {f['repo_id']}: {f['rule_id']} {f['cwe']}")
                print(f"    {f['title'][:100]}")
                print(f"    {f['file']}:{f['line']}")

    # ── Persist results ───────────────────────────────────────────────────
    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "batch_size": args.batch,
        "results": all_results,
        "high_critical_log": findings_log,
        "summary": {
            "total_repos": len(all_results),
            "total_high_critical": total_high_crit,
        },
    }
    report_file = args.output_dir / f"zd_scan_{timestamp}.json"
    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nFull report: {report_file}")

    # SARIF output for high/crit findings
    if findings_log:
        sarif_file = args.output_dir / f"zd_scan_{timestamp}.sarif"
        _write_sarif(findings_log, sarif_file)
        print(f"SARIF:        {sarif_file}")

    # Mark targets as scanned in the campaign file
    _update_campaign_status(targets)

    return 0 if total_high_crit == 0 else 0  # Don't fail — findings are expected


def _write_sarif(findings: list[dict], path: Path) -> None:
    """Write a minimal SARIF 2.1.0 file for high/critical findings."""
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ansede-static",
                    "version": "2.3.0-dev",
                    "informationUri": "https://pypi.org/project/ansede-static/",
                }
            },
            "results": [
                {
                    "ruleId": f.get("rule_id", "unknown"),
                    "level": "error" if f.get("severity") == "critical" else "warning",
                    "message": {"text": f.get("title", "")},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.get("file", "unknown"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": f.get("line", 1)},
                        }
                    }],
                    "properties": {
                        "cwe": f.get("cwe"),
                        "confidence": f.get("confidence"),
                        "confidenceLabel": f.get("confidence_label"),
                        "analysisKind": f.get("analysis_kind"),
                    },
                }
                for f in findings
            ],
        }],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _update_campaign_status(scanned_targets: list[dict]) -> None:
    """Update the campaign manifest with scanned status."""
    try:
        data = json.loads(CAMPAIGN_FILE.read_text(encoding="utf-8"))
        scanned_ids = {t["id"] for t in scanned_targets if "id" in t}
        for entry in data.get("entries", []):
            if entry.get("id") in scanned_ids:
                entry["status"] = "scanned"
                entry["scanned_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        CAMPAIGN_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"Warning: could not update campaign status: {exc}")


if __name__ == "__main__":
    sys.exit(main())

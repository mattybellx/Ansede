#!/usr/bin/env python3
"""
Auto-Triage Scanning Pipeline
──────────────────────────────
Automatically pulls popular repos, scans them with ansede-static, then
triages each finding by reading source code context to determine whether
it's a genuine vulnerability or a false positive.

The results feed back into engine refinement — each triaged finding
becomes a test case for the rule registry.

Usage:
    python tools/auto_triage_pipeline.py [--batch 5] [--output-dir tmp/triage]
    python tools/auto_triage_pipeline.py --targets express,sendgrid,supabase
    python tools/auto_triage_pipeline.py --quick   # use already-cloned repos only

Output:
    tmp/triage/report_{timestamp}.md   — human-readable triage report
    tmp/triage/results_{timestamp}.json — machine-readable findings log
    tmp/triage/sarif_{timestamp}.sarif — SARIF of confirmed findings
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import textwrap
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import threading
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CLONES_DIR = REPO_ROOT / "tmp" / "clones"
OUTPUT_DIR = REPO_ROOT / "tmp" / "triage"
SCAN_TIMEOUT = 300
PARALLEL_WORKERS = 4  # scan up to 4 repos simultaneously

# ── Target discovery ─────────────────────────────────────────────────────────
# High-profile web application repos most likely to have detectable findings.
# Prioritised: real apps > libraries > test-heavy repos.
TARGETS: list[dict[str, Any]] = [
    # Production web apps (highest value)
    {"id": "supabase", "url": "https://github.com/supabase/supabase.git", "lang": "typescript"},
    {"id": "cal.com", "url": "https://github.com/calcom/cal.com.git", "lang": "typescript"},
    {"id": "appwrite", "url": "https://github.com/appwrite/appwrite.git", "lang": "typescript"},
    {"id": "directus", "url": "https://github.com/directus/directus.git", "lang": "typescript"},
    {"id": "n8n", "url": "https://github.com/n8n-io/n8n.git", "lang": "typescript"},
    {"id": "nocodb", "url": "https://github.com/nocodb/nocodb.git", "lang": "typescript"},
    {"id": "posthog", "url": "https://github.com/PostHog/posthog.git", "lang": "python"},
    {"id": "sentry", "url": "https://github.com/getsentry/sentry.git", "lang": "python"},
    {"id": "paperless-ngx", "url": "https://github.com/paperless-ngx/paperless-ngx.git", "lang": "python"},
    {"id": "shynet", "url": "https://github.com/milesmcc/shynet.git", "lang": "python"},
    # Framework apps with known vulnerability surfaces
    {"id": "nodegoat", "url": "https://github.com/OWASP/NodeGoat.git", "lang": "javascript"},
    {"id": "dvna", "url": "https://github.com/appsecco/dvna.git", "lang": "javascript"},
    {"id": "flask-app", "url": "https://github.com/swagatika/flask-vulnerable.git", "lang": "python"},
    # Popular API / backend frameworks
    {"id": "fastapi", "url": "https://github.com/fastapi/fastapi.git", "lang": "python"},
    {"id": "express", "url": "https://github.com/expressjs/express.git", "lang": "javascript"},
    # Real-world apps — 10 more from diverse ecosystems
    {"id": "matomo", "url": "https://github.com/matomo-org/matomo.git", "lang": "php"},
    {"id": "fossbilling", "url": "https://github.com/FOSSBilling/FOSSBilling.git", "lang": "php"},
    {"id": "listmonk", "url": "https://github.com/knadh/listmonk.git", "lang": "go"},
    {"id": "pocketbase", "url": "https://github.com/pocketbase/pocketbase.git", "lang": "go"},
    {"id": "docuseal", "url": "https://github.com/docusealco/docuseal.git", "lang": "ruby"},
    {"id": "twenty", "url": "https://github.com/twentyhq/twenty.git", "lang": "typescript"},
    {"id": "formbricks", "url": "https://github.com/formbricks/formbricks.git", "lang": "typescript"},
    {"id": "saleor", "url": "https://github.com/saleor/saleor.git", "lang": "python"},
    {"id": "plane", "url": "https://github.com/makeplane/plane.git", "lang": "typescript"},
    {"id": "triggerdev", "url": "https://github.com/triggerdotdev/trigger.dev.git", "lang": "typescript"},
    # Round 2 — 10 new popular production repos
    {"id": "strapi", "url": "https://github.com/strapi/strapi.git", "lang": "typescript"},
    {"id": "ghost", "url": "https://github.com/TryGhost/Ghost.git", "lang": "javascript"},
    {"id": "hoppscotch", "url": "https://github.com/hoppscotch/hoppscotch.git", "lang": "typescript"},
    {"id": "infisical", "url": "https://github.com/Infisical/infisical.git", "lang": "typescript"},
    {"id": "documenso", "url": "https://github.com/documenso/documenso.git", "lang": "typescript"},
    {"id": "lobe-chat", "url": "https://github.com/lobehub/lobe-chat.git", "lang": "typescript"},
    {"id": "stackedit", "url": "https://github.com/benweet/stackedit.git", "lang": "javascript"},
    {"id": "stirling-pdf", "url": "https://github.com/Stirling-Tools/Stirling-PDF.git", "lang": "java"},
    {"id": "appsmith", "url": "https://github.com/appsmithorg/appsmith.git", "lang": "typescript"},
    {"id": "mattermost", "url": "https://github.com/mattermost/mattermost.git", "lang": "typescript"},
    # Round 4 — 10 small repos guaranteed to complete in 300s
    {"id": "uptime-kuma", "url": "https://github.com/louislam/uptime-kuma.git", "lang": "javascript"},
    {"id": "linkding", "url": "https://github.com/sissbruecker/linkding.git", "lang": "python"},
    {"id": "dashy", "url": "https://github.com/Lissy93/dashy.git", "lang": "typescript"},
    {"id": "cachet", "url": "https://github.com/cachethq/cachet.git", "lang": "php"},
    {"id": "kanboard", "url": "https://github.com/kanboard/kanboard.git", "lang": "php"},
    {"id": "gogs", "url": "https://github.com/gogs/gogs.git", "lang": "go"},
    {"id": "searxng", "url": "https://github.com/searxng/searxng.git", "lang": "python"},
    {"id": "speedtest", "url": "https://github.com/librespeed/speedtest.git", "lang": "javascript"},
    {"id": "hedgedoc", "url": "https://github.com/hedgedoc/hedgedoc.git", "lang": "typescript"},
    {"id": "monica", "url": "https://github.com/monicahq/monica.git", "lang": "php"},
]

# Path patterns that indicate findings are in test/example/sample code
_TEST_PATH_PATTERNS = re.compile(
    r"(?:/test/|/tests/|/__tests__/|/spec/|/examples?/|/samples?/|/docs?/|/benchmark|/perf/)",
    re.IGNORECASE,
)

# Taint source keywords — findings mentioning these are more likely real
_TAINT_SOURCE_KEYWORDS = re.compile(
    r"\b(?:req\.|request\.|params|query|body|args|input|data|user|"
    r"attacker|untrusted|taint|source|sink)\b",
    re.IGNORECASE,
)

# ├─ Triage logic ─────────────────────────────────────────────────────────────

def _triage_finding(
    finding: dict,
    file_path: str,
    code_context: str,
    repo_id: str,
) -> dict:
    """
    Analyse a single finding and its source code context to determine
    whether it's a genuine vulnerability or a false positive.

    Returns a dict with triage fields:
      - verdict: "confirmed", "likely_fp", "needs_review"
      - reasoning: human-readable explanation
      - confidence_delta: suggested adjustment to the finding's confidence
    """
    rule_id = finding.get("rule_id", "")
    cwe = finding.get("cwe", "")
    title = finding.get("title", "")
    severity = finding.get("severity", "")
    confidence = finding.get("confidence", 0.5)
    analysis_kind = finding.get("analysis_kind", "")
    confidence_label = finding.get("confidence_label", "heuristic")
    line = finding.get("line", 0)

    reasons: list[str] = []
    verdict = "needs_review"
    confidence_delta = 0.0

    # ── Check 1: Is it in test/example code? ──────────────────────────
    if _TEST_PATH_PATTERNS.search(file_path):
        reasons.append("finding is in test/example/spec directory")
        verdict = "likely_fp"
        confidence_delta = -0.2
        # But don't dismiss structural findings in tests — they're still valid detections
        if confidence_label == "structural" and analysis_kind in ("taint-flow", "syntax-ast"):
            reasons.append("but it's a structural taint detection — still valid pattern")
            verdict = "needs_review"

    # ── Check 2: Does the code reference actual user input? ────────────
    code_lower = code_context.lower()
    has_taint_source = bool(_TAINT_SOURCE_KEYWORDS.search(code_lower))
    has_hardcoded = bool(re.search(
        r'["\'][^"\']{3,}["\']',  # string literal longer than 3 chars
        code_context,
    ))

    if not has_taint_source and not has_hardcoded:
        reasons.append("no taint source (req/params/input) or string literal nearby")
        if verdict == "needs_review":
            verdict = "likely_fp"
            confidence_delta = -0.15

    # ── Check 3: Structural findings with taint flow are more reliable ─
    if confidence_label == "structural":
        if analysis_kind in ("taint-flow",):
            reasons.append("structural taint-flow detection — high reliability")
            if verdict == "needs_review":
                verdict = "confirmed"
                confidence_delta = +0.05
        elif analysis_kind in ("syntax-ast", "incident-cluster"):
            reasons.append(f"structural {analysis_kind} detection")
            if verdict == "needs_review" and has_taint_source:
                verdict = "confirmed"
                confidence_delta = +0.02

    # ── Check 4: Heuristic-only with low confidence is likely FP ───────
    if confidence_label == "heuristic" and confidence < 0.8 and verdict == "needs_review":
        reasons.append("low-confidence heuristic pattern — likely false positive")
        verdict = "likely_fp"
        confidence_delta = -0.1

    # ── Check 5: CWEs that are often flagged in test code ──────────────
    fp_prone_cwes = {"CWE-862", "CWE-639", "CWE-352", "CWE-307"}
    if cwe in fp_prone_cwes and verdict == "likely_fp" and "test" in file_path.lower():
        reasons.append(f"{cwe} commonly fires in test route fixtures")
        confidence_delta = -0.1

    return {
        "verdict": verdict,
        "reasoning": "; ".join(reasons),
        "confidence_delta": round(confidence_delta, 2),
        "suggested_confidence": round(min(max(confidence + confidence_delta, 0.0), 1.0), 2),
    }


def _read_code_context(file_path: str, line: int, context_lines: int = 5) -> str:
    """Read source code around a finding's line for context."""
    if not file_path or not os.path.isfile(file_path):
        return ""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        start = max(0, line - 1 - context_lines)
        end = min(len(lines), line - 1 + context_lines + 1)
        return "".join(lines[start:end])
    except (OSError, UnicodeDecodeError):
        return ""


# ├─ Scan & Triage Pipeline ───────────────────────────────────────────────────

def _clone_repo(target: dict, clones_dir: Path) -> Path | None:
    """Clone a repo shallowly. Returns repo root or None."""
    repo_id = target["id"]
    dest = clones_dir / repo_id
    if dest.is_dir():
        # Already cloned — pull latest
        try:
            subprocess.run(
                ["git", "-C", str(dest), "pull", "--ff-only", "--depth", "1"],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            pass
        return dest

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", target["url"], str(dest)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0 and not dest.is_dir():
            print(f"    clone failed: {result.stderr[:200]}")
            return None
        return dest
    except subprocess.TimeoutExpired:
        return None


def _scan_repo(repo_path: Path, target: dict) -> dict | None:
    """Run ansede-static scan with performance optimizations."""
    lang = target.get("lang", "auto")
    cmd = [
        sys.executable, "-m", "ansede_static.cli",
        str(repo_path),
        "--format", "json",
        "--fail-on", "never",
        "--js-backend", "structural",
        "--exclude", "node_modules", "--exclude", ".venv",
        "--exclude", "__pycache__", "--exclude", "vendor",
        "--exclude", "dist", "--exclude", "build", "--exclude", ".git",
        "--exclude", "test", "--exclude", "tests", "--exclude", "__tests__",
        "--exclude", "spec", "--exclude", "examples", "--exclude", "docs",
        "--exclude", "benchmark", "--exclude", "perf",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "results": []}

    if result.returncode != 0 and not result.stdout.strip():
        return {"error": f"scan failed (exit {result.returncode})", "results": []}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "JSON parse failed", "results": []}


def _triage_all_findings(
    scan_data: dict,
    repo_path: Path,
    repo_id: str,
) -> list[dict]:
    """Triage every finding by reading source context."""
    triaged: list[dict] = []

    for res in scan_data.get("results", []):
        file_path = res.get("file_path", "")
        abs_path = str(repo_path / file_path) if file_path else ""

        for finding in res.get("findings", []):
            line = finding.get("line", 1)
            code = _read_code_context(abs_path, line)

            triage = _triage_finding(finding, file_path, code, repo_id)

            triaged.append({
                "repo_id": repo_id,
                "file": file_path,
                "line": line,
                "rule_id": finding.get("rule_id", ""),
                "cwe": finding.get("cwe", ""),
                "severity": finding.get("severity", ""),
                "title": finding.get("title", ""),
                "confidence": finding.get("confidence", 0),
                "analysis_kind": finding.get("analysis_kind", ""),
                "confidence_label": finding.get("confidence_label", "heuristic"),
                "code_snippet": code[:300],
                **triage,
            })

    return triaged


# ├─ Report Generation ────────────────────────────────────────────────────────

def _generate_report(all_triaged: list[dict], elapsed: float) -> str:
    """Generate a human-readable markdown triage report."""
    lines: list[str] = []
    lines.append(f"# Auto-Triage Scan Report")
    lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    lines.append(f"**Duration:** {elapsed:.0f}s")
    lines.append(f"**Total findings triaged:** {len(all_triaged)}")
    lines.append("")

    # Summary stats
    confirmed = [f for f in all_triaged if f["verdict"] == "confirmed"]
    likely_fp = [f for f in all_triaged if f["verdict"] == "likely_fp"]
    needs_review = [f for f in all_triaged if f["verdict"] == "needs_review"]

    lines.append("## Summary")
    lines.append(f"| Category | Count |")
    lines.append(f"|----------|-------|")
    lines.append(f"| **Confirmed** | {len(confirmed)} |")
    lines.append(f"| **Likely FP** | {len(likely_fp)} |")
    lines.append(f"| **Needs Review** | {len(needs_review)} |")
    lines.append("")

    # Per-repo breakdown
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for f in all_triaged:
        by_repo[f["repo_id"]].append(f)

    lines.append("## Per-Repo Breakdown")
    lines.append(f"| Repo | Total | Confirmed | FP | Review |")
    lines.append(f"|------|-------|-----------|----|--------|")
    for rid in sorted(by_repo):
        f_list = by_repo[rid]
        c = sum(1 for f in f_list if f["verdict"] == "confirmed")
        fp = sum(1 for f in f_list if f["verdict"] == "likely_fp")
        r = sum(1 for f in f_list if f["verdict"] == "needs_review")
        lines.append(f"| {rid} | {len(f_list)} | {c} | {fp} | {r} |")
    lines.append("")

    # Confirmed findings (most important)
    if confirmed:
        lines.append("## ✅ Confirmed Findings")
        lines.append("These are structural detections with user-input context — most likely real.")
        lines.append("")
        for f in confirmed:
            lines.append(f"### {f['rule_id']} {f['cwe']}: {f['title']}")
            lines.append(f"- **Repo:** {f['repo_id']}")
            lines.append(f"- **File:** `{f['file']}:{f['line']}`")
            lines.append(f"- **Severity:** {f['severity']}  |  **Confidence:** {f['confidence']} → {f['suggested_confidence']}")
            lines.append(f"- **Analysis:** {f['analysis_kind']}  |  **Label:** {f['confidence_label']}")
            lines.append(f"- **Triage:** {f['reasoning']}")
            if f["code_snippet"]:
                lines.append(f"- **Code context:**")
                lines.append("  ```")
                for cl in f["code_snippet"].split("\n")[:7]:
                    lines.append(f"  {cl}")
                lines.append("  ```")
            lines.append("")

    # Likely false positives
    if likely_fp:
        lines.append("## ❌ Likely False Positives")
        lines.append("Patterns that matched but context suggests they're not exploitable.")
        lines.append("")
        for f in likely_fp[:20]:  # limit to top 20
            lines.append(f"- **{f['repo_id']}** `{f['file']}:{f['line']}` — {f['rule_id']} {f['cwe']}: {f['title'][:60]}")
            lines.append(f"  *{f['reasoning']}*")
        if len(likely_fp) > 20:
            lines.append(f"  *...and {len(likely_fp) - 20} more*")
        lines.append("")

    # Needs review
    if needs_review:
        lines.append("## 🔍 Needs Manual Review")
        for f in needs_review:
            lines.append(f"- **{f['repo_id']}** `{f['file']}:{f['line']}` — {f['rule_id']} {f['cwe']}: {f['title'][:80]}")
        lines.append("")

    # Engine refinement suggestions
    lines.append("## 🔧 Engine Refinement Suggestions")
    fp_rules = defaultdict(int)
    for f in likely_fp:
        key = f"{f['rule_id']} ({f['confidence_label']})"
        fp_rules[key] += 1
    if fp_rules:
        lines.append("Rules producing the most false positives:")
        for rule, count in sorted(fp_rules.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"- **{rule}**: {count} FPs")
    lines.append("")

    return "\n".join(lines)


# ├─ Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Auto-triage scanning pipeline")
    parser.add_argument("--batch", type=int, default=3, help="Number of repos to scan")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--targets", type=str, default=None,
                        help="Comma-separated repo IDs to scan (default: top batch)")
    parser.add_argument("--quick", action="store_true",
                        help="Only scan already-cloned repos")
    parser.add_argument("--json", action="store_true", help="JSON output only")
    args = parser.parse_args()

    # Select targets
    if args.targets:
        target_ids = set(t.strip() for t in args.targets.split(","))
        targets = [t for t in TARGETS if t["id"] in target_ids]
    else:
        targets = TARGETS[:args.batch]

    if not targets:
        print("No targets selected")
        return 1

    print(f"Auto-triage pipeline: {len(targets)} targets (parallel={PARALLEL_WORKERS} workers)")
    print(f"Output: {args.output_dir}")
    print()

    all_triaged: list[dict] = []
    start_time = time.time()
    results_lock = threading.Lock()

    def _process_target(target: dict) -> list[dict]:
        repo_id = target["id"]
        repo_path = _clone_repo(target, CLONES_DIR)
        if repo_path is None:
            return []

        if args.quick and not CLONES_DIR.joinpath(repo_id).is_dir():
            return []

        scan_data = _scan_repo(repo_path, target)
        if scan_data is None or "error" in scan_data:
            return []

        total = sum(len(r.get("findings", [])) for r in scan_data.get("results", []))
        triaged = _triage_all_findings(scan_data, repo_path, repo_id)
        confirmed = sum(1 for f in triaged if f["verdict"] == "confirmed")
        fps = sum(1 for f in triaged if f["verdict"] == "likely_fp")

        print(f"  [{repo_id}] {total} findings → {confirmed} confirmed, {fps} FP, {len(triaged) - confirmed - fps} review")
        return triaged

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        futures = {executor.submit(_process_target, t): t for t in targets}
        for i, future in enumerate(as_completed(futures), 1):
            target = futures[future]
            try:
                triaged = future.result()
                all_triaged.extend(triaged)
            except Exception as exc:
                print(f"  [{target['id']}] ERROR: {exc}")

    elapsed = time.time() - start_time

    # ── Generate outputs ───────────────────────────────────────────────
    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    report_md = _generate_report(all_triaged, elapsed)
    report_file = args.output_dir / f"triage_report_{timestamp}.md"
    report_file.write_text(report_md, encoding="utf-8")
    print(f"\nReport: {report_file}")

    # Machine-readable results
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed, 1),
        "targets_scanned": len(targets),
        "total_findings_triaged": len(all_triaged),
        "by_verdict": {
            "confirmed": sum(1 for f in all_triaged if f["verdict"] == "confirmed"),
            "likely_fp": sum(1 for f in all_triaged if f["verdict"] == "likely_fp"),
            "needs_review": sum(1 for f in all_triaged if f["verdict"] == "needs_review"),
        },
        "findings": all_triaged,
    }
    results_file = args.output_dir / f"triage_results_{timestamp}.json"
    results_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Results: {results_file}")

    # Print summary
    if not args.json:
        print()
        print(report_md.split("## Per-Repo")[0])  # just the summary section
        print(f"\nFull report: {report_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

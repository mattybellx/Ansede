#!/usr/bin/env python3
"""Scan NodeGoat (local) through the triage pipeline and show the report."""
import sys, json, subprocess, os, time, re
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
NODEGOAT = ROOT / "NodeGoat"
OUTPUT = ROOT / "tmp" / "triage"

_TEST_RE = re.compile(r"(?:/test/|/tests/|/__tests__/|/spec/|/examples?/)", re.I)
_TAINT_RE = re.compile(r"\b(?:req\.|request\.|params|query|body|args|input)\b", re.I)

def triage(finding, file_path, code):
    fid = finding.get("rule_id","")
    cwe = finding.get("cwe","")
    sev = finding.get("severity","")
    conf = finding.get("confidence",0.5)
    label = finding.get("confidence_label","heuristic")
    akind = finding.get("analysis_kind","")
    line = finding.get("line",1)
    title = finding.get("title","")

    reasons = []
    verdict = "needs_review"
    delta = 0.0

    if _TEST_RE.search(file_path):
        reasons.append("test/spec directory")
        if label != "structural":
            verdict = "likely_fp"; delta = -0.2
        else:
            verdict = "needs_review"; reasons.append("but structural taint")

    has_taint = bool(_TAINT_RE.search(code))
    if not has_taint and not re.search(r'["\'][^"\']{3,}["\']', code):
        reasons.append("no taint source nearby")
        if verdict == "needs_review":
            verdict = "likely_fp"; delta = -0.15

    if label == "structural" and akind in ("taint-flow",):
        reasons.append("structural taint-flow")
        if verdict != "likely_fp":
            verdict = "confirmed"; delta = +0.05

    if label == "heuristic" and conf < 0.8 and verdict == "needs_review":
        verdict = "likely_fp"; delta = -0.1

    return {"verdict": verdict, "reasoning": "; ".join(reasons), "confidence": round(min(max(conf+delta,0),1),2)}

# Scan NodeGoat
print("Scanning NodeGoat...")
r = subprocess.run([sys.executable, "-m", "ansede_static.cli", str(NODEGOAT),
    "--format", "json", "--fail-on", "never", "--js-backend", "structural",
    "--exclude", "node_modules"], capture_output=True, text=True, timeout=120)
data = json.loads(r.stdout)

# Triage
triaged = []
for res in data.get("results", []):
    fp = res.get("file_path", "")
    for f in res.get("findings", []):
        line = f.get("line", 1)
        code = ""
        afp = str(NODEGOAT / fp) if fp else ""
        if afp and os.path.isfile(afp):
            try:
                with open(afp, encoding="utf-8") as fh:
                    lines = fh.readlines()
                start = max(0, line-6); end = min(len(lines), line+5)
                code = "".join(lines[start:end])
            except: pass
        t = triage(f, fp, code)
        triaged.append({"repo": "NodeGoat", "file": fp, "line": line,
            "rule_id": f.get("rule_id",""), "cwe": f.get("cwe",""),
            "severity": f.get("severity",""), "title": f.get("title","")[:80],
            "confidence": f.get("confidence",0), "analysis_kind": f.get("analysis_kind",""),
            "confidence_label": f.get("confidence_label","heuristic"),
            "verdict": t["verdict"], "reasoning": t["reasoning"],
            "suggested_confidence": t["confidence"]})

# Report
OUTPUT.mkdir(parents=True, exist_ok=True)
ts = time.strftime("%Y%m%d_%H%M%S")
report = OUTPUT / f"triage_nodegoat_{ts}.md"
confirmed = [f for f in triaged if f["verdict"] == "confirmed"]
fp = [f for f in triaged if f["verdict"] == "likely_fp"]
review = [f for f in triaged if f["verdict"] == "needs_review"]

md = []
md.append("# Auto-Triage Report: NodeGoat")
md.append(f"**Total findings:** {len(triaged)}")
md.append(f"**Confirmed:** {len(confirmed)} | **Likely FP:** {len(fp)} | **Needs Review:** {len(review)}")
md.append("")

if confirmed:
    md.append("## ✅ Confirmed Findings")
    for f in confirmed:
        md.append(f"### {f['rule_id']} {f['cwe']}: {f['title']}")
        md.append(f"- **File:** `{f['file']}:{f['line']}`")
        md.append(f"- **Severity:** {f['severity']} | **Confidence:** {f['confidence']} → {f['suggested_confidence']}")
        md.append(f"- **Analysis:** {f['analysis_kind']} | **Label:** {f['confidence_label']}")
        md.append(f"- **Triage:** {f['reasoning']}")
        md.append("")

if fp:
    md.append("## ❌ Likely False Positives")
    for f in fp[:15]:
        md.append(f"- `{f['file']}:{f['line']}` — {f['rule_id']} {f['cwe']}: {f['title'][:60]}")
        md.append(f"  *{f['reasoning']}*")
    if len(fp) > 15:
        md.append(f"  *...and {len(fp)-15} more*")
    md.append("")

if review:
    md.append("## 🔍 Needs Manual Review")
    for f in review:
        md.append(f"- `{f['file']}:{f['line']}` — {f['rule_id']} {f['cwe']}: {f['title'][:70]}")
    md.append("")

# Suggestions
fp_rules = defaultdict(int)
for f in fp:
    fp_rules[f"{f['rule_id']} ({f['confidence_label']})"] += 1
if fp_rules:
    md.append("## 🔧 Engine Refinement")
    md.append("Rules with most false positives:")
    for rule, count in sorted(fp_rules.items(), key=lambda x: -x[1])[:8]:
        md.append(f"- **{rule}**: {count} FPs")

report.write_text("\n".join(md), encoding="utf-8")
print(f"\nReport: {report}")
print(f"\n{'='*60}")
print("\n".join(md[:8]))
print(f"\n{'='*60}")
if confirmed:
    print(f"\n--- Top confirmed findings ---")
    for f in confirmed[:5]:
        print(f"  [{f['severity'].upper()}] {f['rule_id']} {f['cwe']}: {f['title']}")
        print(f"    {f['file']}:{f['line']} | {f['reasoning']}")

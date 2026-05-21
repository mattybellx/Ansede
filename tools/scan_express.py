#!/usr/bin/env python3
"""Scan Express.js and show structural findings."""
import json, subprocess, sys
r = subprocess.run([sys.executable, "-m", "ansede_static.cli", "tmp/clones/express",
    "--format", "json", "--fail-on", "never", "--js-backend", "structural",
    "--exclude", "node_modules"], capture_output=True, text=True, timeout=120)
data = json.loads(r.stdout)
total = sum(len(res.get("findings",[])) for res in data.get("results",[]))
high_crit = 0
for res in data.get("results",[]):
    for f in res.get("findings",[]):
        sev = f.get("severity","")
        label = f.get("confidence_label","?")
        if sev in ("critical","high") or label == "structural":
            high_crit += 1
            print(f"  [{sev.upper()}] {f.get('rule_id','?')} {f.get('cwe','?')}: {f.get('title','?')[:80]}")
            print(f"         {f.get('file','?')}:{f.get('line','?')} conf={f.get('confidence','?')} kind={f.get('analysis_kind','?')} label={label}")
print(f"Total findings: {total}")
print(f"High/Critical/Structural: {high_crit}")

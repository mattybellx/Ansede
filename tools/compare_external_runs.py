from __future__ import annotations

import json
from pathlib import Path
from collections import Counter


def load_json(path: Path) -> dict:
    raw = path.read_bytes()
    for enc in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            return json.loads(raw.decode(enc))
        except Exception:
            continue
    raise ValueError(f"Unable to decode JSON: {path}")


def main() -> int:
    refresh_path = Path('.tmp/real_world_refresh.json')
    offline_path = Path('.tmp/real_world_offline.json')
    refresh = load_json(refresh_path)
    offline = load_json(offline_path)

    refresh_cases = {c['case_id']: c for c in refresh.get('cases', [])}
    offline_cases = {c['case_id']: c for c in offline.get('cases', [])}

    all_case_ids = sorted(set(refresh_cases) | set(offline_cases))
    deltas = []
    for cid in all_case_ids:
        rc = refresh_cases.get(cid, {})
        oc = offline_cases.get(cid, {})
        rf = int(rc.get('findings_count', 0))
        of = int(oc.get('findings_count', 0))
        if rf != of:
            deltas.append({'case_id': cid, 'refresh_findings': rf, 'offline_findings': of})

    # language hotspot summary from offline snapshot
    hotspots: dict[str, dict[str, float]] = {}
    for case in offline.get('cases', []):
        lang = case.get('language')
        if not lang:
            langs = case.get('languages') or []
            lang = '+'.join(langs) if langs else 'unknown'
        findings = float(case.get('findings_count', 0))
        lines = max(float(case.get('lines_scanned', 0)), 1.0)
        bucket = hotspots.setdefault(lang, {'cases': 0.0, 'findings': 0.0, 'lines': 0.0})
        bucket['cases'] += 1
        bucket['findings'] += findings
        bucket['lines'] += lines

    by_lang = []
    for lang, vals in hotspots.items():
        noise_per_kloc = (vals['findings'] / vals['lines']) * 1000.0
        by_lang.append({
            'language': lang,
            'cases': int(vals['cases']),
            'findings': int(vals['findings']),
            'noise_per_kloc': round(noise_per_kloc, 4),
        })
    by_lang.sort(key=lambda x: x['noise_per_kloc'], reverse=True)

    # Per-repo/case hotspots
    by_case = []
    cwe_counter: Counter[str] = Counter()
    for case in offline.get('cases', []):
        findings = case.get('findings', [])
        for finding in findings:
            cwe = finding.get('cwe')
            if cwe:
                cwe_counter[cwe] += 1
        by_case.append({
            'case_id': case.get('case_id'),
            'language': case.get('language') or ('+'.join(case.get('languages') or []) or 'unknown'),
            'findings': int(case.get('findings_count', 0)),
            'lines_scanned': int(case.get('lines_scanned', 0)),
            'noise_per_kloc': round(float(case.get('raw_noise_quotient', 0.0)), 4),
        })
    by_case.sort(key=lambda x: x['noise_per_kloc'], reverse=True)

    recurring_cwes = [
        {'cwe': cwe, 'count': count}
        for cwe, count in cwe_counter.most_common(10)
    ]

    summary = {
        'refresh_score': refresh.get('summary', {}).get('score_pct'),
        'offline_score': offline.get('summary', {}).get('score_pct'),
        'case_count_refresh': len(refresh_cases),
        'case_count_offline': len(offline_cases),
        'drift_case_count': len(deltas),
        'drift_cases': deltas,
        'language_hotspots': by_lang,
        'case_hotspots': by_case,
        'top_recurring_cwes': recurring_cwes,
    }

    out_json = Path('.tmp/real_world_drift_summary.json')
    out_json.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')

    lines = [
        '# Real-world Corpus Drift Summary (refresh vs offline)',
        '',
        f"- Refresh score: {summary['refresh_score']}",
        f"- Offline score: {summary['offline_score']}",
        f"- Drift cases: {summary['drift_case_count']}",
        '',
        '## Language hotspots (offline)',
        '',
        '| Language | Cases | Findings | Noise / kLOC |',
        '|---|---:|---:|---:|',
    ]
    for row in by_lang:
        lines.append(f"| {row['language']} | {row['cases']} | {row['findings']} | {row['noise_per_kloc']} |")

    lines.extend(['', '## Per-case hotspots (offline)', '', '| Case | Language | Findings | Noise / kLOC |', '|---|---|---:|---:|'])
    for row in by_case:
        lines.append(f"| {row['case_id']} | {row['language']} | {row['findings']} | {row['noise_per_kloc']} |")

    lines.extend(['', '## Top recurring CWEs (offline findings)', '', '| CWE | Count |', '|---|---:|'])
    for row in recurring_cwes:
        lines.append(f"| {row['cwe']} | {row['count']} |")

    if deltas:
        lines.extend(['', '## Drift cases', '', '| Case | Refresh findings | Offline findings |', '|---|---:|---:|'])
        for d in deltas:
            lines.append(f"| {d['case_id']} | {d['refresh_findings']} | {d['offline_findings']} |")

    out_md = Path('.tmp/real_world_drift_summary.md')
    out_md.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    print(f'Wrote {out_json} and {out_md}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

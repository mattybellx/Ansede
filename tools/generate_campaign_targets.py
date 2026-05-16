"""Generate a top-repo campaign target list for Track 1.

Uses GitHub search API (unauthenticated by default) and writes a pinned-target template.
"""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict

API = "https://api.github.com/search/repositories"


@dataclass
class Target:
    id: str
    repo: str
    url: str
    language: str
    ref: str
    priority: str
    scan_profile: dict
    status: str


def fetch_top(language: str, count: int = 34) -> list[dict]:
    q = urllib.parse.quote(f"language:{language} stars:>1000 archived:false")
    url = f"{API}?q={q}&sort=stars&order=desc&per_page={count}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "ansede-static"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.load(resp)
    return data.get("items", [])


def build() -> dict:
    desired = [("python", 34), ("javascript", 33), ("typescript", 33)]
    entries: list[Target] = []

    for lang, n in desired:
        for item in fetch_top(lang, n):
            full_name = item["full_name"]
            entries.append(Target(
                id=f"{lang[:2]}-{item['name'].lower().replace('.', '-')}"
                   f"-{item['id']}",
                repo=full_name,
                url=item["html_url"],
                language=lang,
                ref="<pin_sha>",
                priority="high" if item.get("stargazers_count", 0) > 10000 else "medium",
                scan_profile={
                    "severity_min": "high",
                    "js_backend": "structural",
                    "focus_cwes": ["CWE-862", "CWE-639"],
                },
                status="queued",
            ))

    return {
        "version": "1.0",
        "updated": "2026-05-16",
        "selection": {
            "goal": "Top OSS repos for real-world CWE-862/CWE-639 campaign",
            "languages": ["python", "javascript", "typescript"],
            "target_count": len(entries),
            "source": "GitHub API search",
        },
        "entries": [asdict(e) for e in entries[:100]],
    }


def main() -> int:
    out_path = "benchmarks/campaign_targets_top100.json"
    data = build()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"Wrote {len(data['entries'])} targets to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

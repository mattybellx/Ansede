"""Track scan performance across commits for local v3 profiling work."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HISTORY_FILE = Path.home() / ".ansede" / "perf_history.json"


def _load_history() -> list[dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return []
    try:
        with open(HISTORY_FILE, encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return []


def record_scan(profile_json: dict[str, Any], repo: str, commit: str) -> list[dict[str, Any]]:
    """Record one profile payload in local history and emit regressions if found."""
    history = _load_history()
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    history.append({
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repo": repo,
        "commit": commit[:8],
        "total_ms": float(profile_json.get("total_ms", 0) or 0),
        "files_per_second": float(profile_json.get("files_per_second", 0) or 0),
        "findings": int(profile_json.get("findings_total", 0) or 0),
        "phases": profile_json.get("phases", {}),
    })
    history = history[-100:]
    with open(HISTORY_FILE, "w", encoding="utf-8") as handle:
        json.dump(history, handle, indent=2)

    if len(history) >= 3:
        baseline = history[-3:-1]
        baseline_avg = sum(item["total_ms"] for item in baseline) / len(baseline)
        latest = history[-1]
        if baseline_avg > 0 and latest["total_ms"] > baseline_avg * 1.2:
            print(
                "⚠️  PERFORMANCE REGRESSION: "
                f"{latest['total_ms']:.0f}ms vs avg {baseline_avg:.0f}ms (>20%)"
            )
    return history


def show_dashboard() -> None:
    """Print the last ten recorded scans."""
    history = _load_history()
    if not history:
        print("No performance history yet. Run scans with --profile first.")
        return

    print(f"{'Date':<20} {'Repo':<20} {'Commit':<10} {'Time(ms)':<10} {'Files/s':<10}")
    print("-" * 74)
    for item in history[-10:]:
        print(
            f"{item['timestamp'][:16]:<20} "
            f"{str(item['repo'])[:18]:<20} "
            f"{item['commit']:<10} "
            f"{item['total_ms']:<10.0f} "
            f"{item['files_per_second']:<10.1f}"
        )


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if args and args[0] == "record":
        if len(args) < 3:
            print("Usage: python -m benchmarks.perf_dashboard record <repo> <commit>", file=sys.stderr)
            return 2
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except json.JSONDecodeError as exc:
            print(f"Invalid profile JSON: {exc}", file=sys.stderr)
            return 2
        record_scan(payload, args[1], args[2])
        return 0

    show_dashboard()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
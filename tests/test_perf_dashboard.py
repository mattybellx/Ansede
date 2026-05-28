from __future__ import annotations

import json

from benchmarks import perf_dashboard


def test_record_scan_writes_history_and_caps_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(perf_dashboard, "HISTORY_FILE", tmp_path / "perf_history.json")

    for index in range(105):
        perf_dashboard.record_scan({"total_ms": index + 1, "files_per_second": 2.5, "findings_total": 3}, "repo", f"commit{index}")

    history = json.loads((tmp_path / "perf_history.json").read_text(encoding="utf-8"))
    assert len(history) == 100
    assert history[-1]["commit"] == "commit10"


def test_main_record_mode_accepts_stdin(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(perf_dashboard, "HISTORY_FILE", tmp_path / "perf_history.json")
    monkeypatch.setattr("sys.stdin.read", lambda: '{"total_ms": 42, "files_per_second": 1.5, "findings_total": 2}')

    exit_code = perf_dashboard.main(["record", "repo", "abcdef123"])

    assert exit_code == 0
    payload = json.loads((tmp_path / "perf_history.json").read_text(encoding="utf-8"))
    assert payload[0]["repo"] == "repo"
    assert payload[0]["commit"] == "abcdef12"


def test_show_dashboard_handles_empty_history(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(perf_dashboard, "HISTORY_FILE", tmp_path / "perf_history.json")

    perf_dashboard.show_dashboard()

    captured = capsys.readouterr()
    assert "No performance history yet" in captured.out
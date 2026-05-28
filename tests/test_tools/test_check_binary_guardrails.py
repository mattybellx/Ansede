"""Tests for the DIR-5.3 binary guardrail checker."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def test_binary_guardrails_pass():
    """The guardrail tool must exit 0 with no failures."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/check_binary_guardrails.py"), "--json"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )

    assert result.returncode == 0, f"Guardrails failed:\n{result.stderr}\n{result.stdout}"
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["failures"] == []
    assert payload["kind"] == "ansede-binary-guardrails"


def test_binary_guardrails_detects_dependency_violation(monkeypatch, tmp_path):
    """If a fake dependency is injected, the tool must fail."""
    fake_pyproject = tmp_path / "pyproject.toml"
    fake_pyproject.write_text(
        '[project]\ndependencies = ["requests>=2.0"]\n',
        encoding="utf-8",
    )

    import tools.check_binary_guardrails as guardrails
    monkeypatch.setattr(guardrails, "PYPROJECT", fake_pyproject)

    failures = guardrails._check_dependencies()
    assert len(failures) > 0
    assert "requests" in failures[0]

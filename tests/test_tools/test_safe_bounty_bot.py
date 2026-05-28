"""Tests for the safe-disclosure draft generator (DIR-4.3)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from tools.safe_bounty_bot import (
    _is_disclosure_worthy,
    _generate_disclosure,
    _findings_from_results,
    SAVE_DIR,
)


def test_high_confidence_structural_finding_is_worthy():
    finding = {
        "confidence": 0.95,
        "severity": "high",
        "analysis_kind": "taint-flow",
        "trace": [{"kind": "source", "label": "request.args", "line": 5}],
        "cwe": "CWE-89",
        "title": "SQL injection",
    }
    assert _is_disclosure_worthy(finding) is True


def test_low_confidence_finding_not_worthy():
    finding = {
        "confidence": 0.5,
        "severity": "high",
        "analysis_kind": "pattern",
        "trace": [],
        "cwe": "CWE-89",
    }
    assert _is_disclosure_worthy(finding) is False


def test_low_severity_finding_not_worthy():
    finding = {
        "confidence": 0.95,
        "severity": "low",
        "analysis_kind": "taint-flow",
        "trace": [{"kind": "sink", "label": "execute", "line": 10}],
        "cwe": "CWE-89",
    }
    assert _is_disclosure_worthy(finding) is False


def test_generate_disclosure_includes_cwes_and_locations():
    findings = [
        {
            "cwe": "CWE-89",
            "title": "SQL Injection in login",
            "description": "User input flows to execute()",
            "file_path": "app/login.py",
            "line": 42,
            "severity": "critical",
            "suggestion": "Use parameterized queries",
            "trace": [{"kind": "source", "label": "request.form", "line": 10}],
        }
    ]
    disclosure = _generate_disclosure(findings, repo_name="test/app", commit_sha="abc123")
    assert "CWE-89" in disclosure
    assert "app/login.py" in disclosure
    assert "42" in disclosure
    assert "SQL Injection" in disclosure
    assert "Reproduction" in disclosure
    assert "ansede-static" in disclosure


def test_findings_from_results_extracts_nested_findings():
    results = [
        {
            "file_path": "app.py",
            "findings": [{"cwe": "CWE-78", "severity": "high", "title": "Command injection"}],
        }
    ]
    extracted = _findings_from_results(results)
    assert len(extracted) == 1
    assert extracted[0]["file_path"] == "app.py"
    assert extracted[0]["cwe"] == "CWE-78"

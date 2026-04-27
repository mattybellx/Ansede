"""
ansede_static.ir
────────────────
Lightweight intermediate representation for security findings.
"""
from ansede_static.ir.issues import (
    IssueLocation,
    IssueRecord,
    IssueTraceFrame,
    build_issue_records,
)


__all__ = [
    "IssueLocation",
    "IssueRecord",
    "IssueTraceFrame",
    "build_issue_records",
]
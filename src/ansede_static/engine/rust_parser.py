"""ansede_static.engine.rust_parser — Bridge to native Rust/Tree-sitter parsing.

When the `ansede_rust_core` native module is built and available, uses
Tree-sitter (via PyO3) for 10-100x faster AST parsing. Falls back to
Python stdlib `ast.parse` otherwise.

Usage:
    from ansede_static.engine.rust_parser import parse_to_dsl, fast_parse
    ast_node = parse_to_dsl(code, language="python")
    flat_table = fast_parse(code, "javascript")  # returns dict with flat node list
"""
from __future__ import annotations

import logging
from typing import Any

_log = logging.getLogger(__name__)

# ── Native module detection ─────────────────────────────────────────

try:
    from ansede_rust_core import is_available as _native_available, parse_code_dict as _native_parse
    HAS_RUST_CORE = _native_available()
except ImportError:
    HAS_RUST_CORE = False

# Try flat table API (new in 0.1.0+)
_FLAT_TABLE = None
if HAS_RUST_CORE:
    try:
        from ansede_rust_core._core import parse_flat_table as _flat_table
        _FLAT_TABLE = _flat_table
    except ImportError:
        pass


_FILE_EXT_LANG: dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".jv": "java",
    ".go": "go", ".golang": "go",
    ".cs": "csharp",
}


def detect_language(filename: str) -> str | None:
    """Detect the programming language from a file extension."""
    import os
    ext = os.path.splitext(filename)[1].lower()
    return _FILE_EXT_LANG.get(ext)


def fast_parse(code: str, language: str, filename: str = "") -> dict[str, Any] | None:
    """Fast parsing using Rust Tree-sitter with flat node table output.
    Returns dict with 'nodes' (flat list), 'node_count', 'lines_scanned'.
    Returns None if unavailable."""
    if _FLAT_TABLE is None:
        return None
    try:
        return _FLAT_TABLE(code, language, filename)
    except Exception as exc:
        _log.debug("fast_parse failed: %s", exc)
        return None


def native_parse_to_dict(code: str, language: str, filename: str = "") -> dict[str, Any] | None:
    """Parse code using the Rust native core, returning a dict with 'nodes' key.
    Returns None if the native module is unavailable."""
    if not HAS_RUST_CORE:
        return None
    try:
        return _native_parse(code, language, filename)
    except Exception as exc:
        _log.debug("Rust parse fallback: %s", exc)
        return None


def flat_table_to_dsl(flat_nodes: list[dict]) -> Any | None:
    """Convert a flat node table to a DSL ASTNode tree.
    Fast single-pass tree construction using parent_id references."""
    if not flat_nodes:
        return None
    from ansede_static.dsl.engine import ASTNode

    lookup: dict[int, ASTNode] = {}
    for n in flat_nodes:
        lookup[n["id"]] = ASTNode(
            id=n["id"], kind=n["kind"], text=n.get("text", ""),
            start_line=n.get("start_line", 1), start_col=n.get("start_col", 0),
            children=[],
        )
    root: ASTNode | None = None
    for n in flat_nodes:
        node = lookup[n["id"]]
        parent_id = n.get("parent_id", 0)
        if parent_id == 0 or parent_id not in lookup:
            root = node
        elif parent_id in lookup:
            lookup[parent_id].children.append(node)
    return root or lookup[flat_nodes[0]["id"]]


def parse_to_dsl(code: str, language: str = "python", filename: str = "") -> Any:
    """Parse code and return DSL ASTNode structure.
    Uses Rust native core when available, falls back to Python ast.parse."""
    # Try flat table first (fastest)
    raw = fast_parse(code, language, filename)
    if raw and raw.get("nodes"):
        tree = flat_table_to_dsl(raw["nodes"])
        if tree:
            return tree

    # Fallback: old tree dict from Rust
    if HAS_RUST_CORE:
        try:
            raw = _native_parse(code, language, filename)
            if raw and raw.get("nodes"):
                return _rust_nodes_to_dsl(raw["nodes"])
        except Exception as exc:
            _log.debug("Rust parse_to_dsl fallback failed: %s", exc)

    # Python stdlib fallback
    if language in ("python",):
        from ansede_static.dsl.bridge import parse_python_to_dsl
        return parse_python_to_dsl(code)

    return _generic_text_tree(code, language)
    if language in ("python",):
        from ansede_static.dsl.bridge import parse_python_to_dsl
        return parse_python_to_dsl(code)

    return _generic_text_tree(code, language)


def _rust_nodes_to_dsl(nodes: list[dict[str, Any]]) -> Any:
    """Convert Rust-native AST node dicts to the DSL ASTNode tree."""
    from ansede_static.dsl.engine import ASTNode

    def convert(n: dict[str, Any]) -> ASTNode:
        children = [convert(c) for c in n.get("children", [])]
        return ASTNode(
            id=n["id"],
            kind=n["kind"],
            text=n.get("text", ""),
            start_line=n.get("start_line", 1),
            start_col=n.get("start_col", 0),
            children=children,
        )

    if not nodes:
        return None
    # Return the root wrapper if single root, else a synthetic root
    if len(nodes) == 1:
        return convert(nodes[0])
    from ansede_static.dsl.engine import ASTNode as AN
    return AN(id=0, kind="root", text="", start_line=1, start_col=0,
              children=[convert(n) for n in nodes])


def _generic_text_tree(code: str, language: str) -> Any:
    """Build a minimal ASTNode tree when no parser is available for the language."""
    from ansede_static.dsl.engine import ASTNode
    lines = code.splitlines()
    return ASTNode(
        id=0,
        kind="root",
        text=code[:200],
        start_line=1,
        start_col=0,
        children=[ASTNode(id=i + 1, kind="line", text=line, start_line=i + 1, start_col=0)
                  for i, line in enumerate(lines[:100])],
    )


def benchmark_vs_python(code: str, iterations: int = 100) -> dict[str, float]:
    """Benchmark Rust native vs Python stdlib parsing speed."""
    import time

    # Warmup
    if HAS_RUST_CORE:
        for _ in range(3):
            _native_parse(code, "python", "bench.py")

    # Rust timing
    rust_times: list[float] = []
    if HAS_RUST_CORE:
        for _ in range(iterations):
            t0 = time.perf_counter()
            _native_parse(code, "python", "bench.py")
            rust_times.append(time.perf_counter() - t0)

    # Python timing
    import ast
    py_times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        ast.parse(code)
        py_times.append(time.perf_counter() - t0)

    result: dict[str, float] = {}
    if rust_times:
        rust_avg = sum(rust_times) / len(rust_times)
        result["rust_avg_ms"] = round(rust_avg * 1000, 4)
        result["rust_min_ms"] = round(min(rust_times) * 1000, 4)
    py_avg = sum(py_times) / len(py_times)
    result["py_avg_ms"] = round(py_avg * 1000, 4)
    result["py_min_ms"] = round(min(py_times) * 1000, 4)
    if rust_times:
        result["speedup"] = round(py_avg / (sum(rust_times) / len(rust_times)), 2)
    return result


__all__ = [
    "HAS_RUST_CORE", "detect_language", "native_parse_to_dict",
    "parse_to_dsl", "benchmark_vs_python",
]

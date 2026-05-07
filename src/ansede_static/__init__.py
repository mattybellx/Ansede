"""
ansede_static
─────────────
Zero-dependency SAST security scanner for Python, JavaScript/TypeScript,
Go, Java, and C#.

Quick start:
    from ansede_static import scan_file, scan_code

    result = scan_file("myapp.py")
    for finding in result.sorted_findings():
        print(finding.severity.value, finding.title, finding.line)
"""
from __future__ import annotations

from ansede_static._types import AnalysisResult, Finding, Severity
from ansede_static.config import AnsedeConfig, apply_config_to_results, temporary_analyzer_config
from ansede_static.engine_version import SCHEMA_VERSION, get_engine_version
from ansede_static.python_analyzer import analyze_python, analyze_file as _py_file
from ansede_static.js_engine.backends import list_js_backends, run_js_analysis
from ansede_static import yaml_rules as _yaml_rules

from pathlib import Path


__all__ = [
    "scan_file",
    "scan_code",
    "AnalysisResult",
    "AnsedeConfig",
    "Finding",
    "Severity",
    "SCHEMA_VERSION",
    "list_js_backends",
]

__version__ = get_engine_version()


_PYTHON_EXTS = frozenset({".py", ".pyi", ".pyw"})
_JS_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
_GO_EXTS = frozenset({".go"})
_JAVA_EXTS = frozenset({".java"})
_CSHARP_EXTS = frozenset({".cs"})


def scan_file(path: str | Path, config: AnsedeConfig | None = None, *, js_backend: str = "auto") -> AnalysisResult:
    """
    Scan a file and return an AnalysisResult.

    Language is detected from the file extension.
    Raises ValueError for unsupported file types.
    """
    p = Path(path)
    ext = p.suffix.lower()
    runtime_rules = _yaml_rules.load_runtime_rules(config=config, workspace_root=Path.cwd())

    # Create a shared GlobalGraph for IFDS-based interprocedural taint transfer.
    # Both Python and JS analyzers feed summaries into it and query it during
    # helper-call resolution, giving JS the same IDE-lattice-powered cross-file
    # taint tracking that Python already uses.
    try:
        from ansede_static.ir.global_graph import GlobalGraph  # noqa: PLC0415
        shared_graph = GlobalGraph()
    except Exception:
        shared_graph = None

    with temporary_analyzer_config(config):
        if ext in _PYTHON_EXTS:
            result = _py_file(p, global_graph=shared_graph)
        elif ext in _JS_EXTS:
            code = p.read_text(encoding="utf-8", errors="replace")
            result, _ = run_js_analysis(code, filename=str(p), requested_backend=js_backend, global_graph=shared_graph)
        elif ext in _GO_EXTS:
            from ansede_static.go_engine.go_analyzer import run_go_analysis
            code = p.read_text(encoding="utf-8", errors="replace")
            result = run_go_analysis(code, filename=str(p))
        elif ext in _JAVA_EXTS:
            from ansede_static.java_analyzer import analyze_java
            code = p.read_text(encoding="utf-8", errors="replace")
            result = analyze_java(code, filename=str(p))
        elif ext in _CSHARP_EXTS:
            from ansede_static.csharp_analyzer import analyze_csharp
            code = p.read_text(encoding="utf-8", errors="replace")
            result = analyze_csharp(code, filename=str(p))
        else:
            raise ValueError(
                f"Unsupported file extension: {ext!r}. Supported: .py, .js, .ts, .go, .java, .cs (and variants)."
            )
    if runtime_rules and result.language:
        try:
            runtime_code = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            runtime_code = ""
        if runtime_code:
            result.findings.extend(
                _yaml_rules.apply_custom_rules(runtime_code, str(p), result.language, runtime_rules)
            )
    apply_config_to_results([result], config)
    return result


def scan_code(
    code: str,
    language: str,
    filename: str = "",
    config: AnsedeConfig | None = None,
    *,
    js_backend: str = "auto",
) -> AnalysisResult:
    """
    Scan source code provided as a string.

    Args:
        code:     Source code.
        language: "python", "javascript", "go", "java", or "csharp".
        filename: Optional file name for error messages.

    Raises:
        ValueError: if language is not supported.
    """
    runtime_rules = _yaml_rules.load_runtime_rules(config=config, workspace_root=Path.cwd())
    with temporary_analyzer_config(config):
        if language == "python":
            result = analyze_python(code, filename=filename)
        elif language in ("javascript", "typescript", "js", "ts"):
            result, _ = run_js_analysis(code, filename=filename, requested_backend=js_backend)
        elif language == "go":
            from ansede_static.go_engine.go_analyzer import run_go_analysis
            result = run_go_analysis(code, filename=filename)
        elif language == "java":
            from ansede_static.java_analyzer import analyze_java
            result = analyze_java(code, filename=filename)
        elif language in ("csharp", "cs", "c#"):
            from ansede_static.csharp_analyzer import analyze_csharp
            result = analyze_csharp(code, filename=filename)
        else:
            raise ValueError(
                f"Unsupported language: {language!r}. Must be 'python', 'javascript', 'go', 'java', or 'csharp'."
            )
    if runtime_rules and result.language:
        result.findings.extend(
            _yaml_rules.apply_custom_rules(code, filename or "<stdin>", result.language, runtime_rules)
        )
    apply_config_to_results([result], config)
    return result

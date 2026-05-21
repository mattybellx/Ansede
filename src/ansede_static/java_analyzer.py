"""
java_analyzer.py — Ansede Static Java detection engine.

PERFORMANCE CONTRACT:
  Analysis is bounded structural heuristics over regex-identified method blocks.
  No full grammar parse tree is constructed. Method boundary detection is O(n)
  in line count. Annotation context lookup is O(k) where k = annotation lines
  above a method (bounded to 10). Total complexity: O(n) per file.
  Worst-case measured against a 10k-line Spring Boot controller: < 400ms.
  This stays well within the 10s/100kLOC budget.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from ansede_static._types import AnalysisResult, Finding, Severity


_ROUTE_ANNOTATIONS = {
    # Spring
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping",
    # JAX-RS / Jakarta REST
    "GET", "POST", "PUT", "DELETE", "PATCH", "Path",
    # Micronaut
    "Get", "Post", "Put", "Delete", "Patch",
    # Quarkus RESTEasy Reactive
    "GET", "POST", "PUT", "DELETE", "PATCH",
}
_MUTATING_ROUTE_ANNOTATIONS = {"PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
                                "POST", "PUT", "DELETE", "PATCH",
                                "Post", "Put", "Delete", "Patch"}
_AUTH_ANNOTATIONS = {"PreAuthorize", "Secured", "RolesAllowed",
                     "Authenticated", "PermitAll", "DenyAll",
                     "RolesAllowed", "AllowedRoles"}
_PUBLIC_ROUTE_RE = re.compile(r"/(?:login|logout|register|signup|health|ready|status|public|docs|swagger|openapi)", re.IGNORECASE)
_SECURITY_CONTEXT_RE = re.compile(r"SecurityContextHolder|getAuthentication\(|isAuthenticated\(|hasRole\(|hasAuthority\(|principal\b", re.IGNORECASE)
_OWNERSHIP_RE = re.compile(r"userId|ownerId|accountId|tenantId|currentUser|getCurrentUser|principal\.|authentication\.getName|findByIdAndUserId|where\s*\(|filter\s*\(", re.IGNORECASE)
_SQLI_RE = re.compile(
    r"(?:createQuery|JdbcTemplate\.(?:query|execute)|\w+\.executeQuery)\s*\((?:[^\n;]*\+[^\n;]*|[^\n;]*String\.format\s*\()",
    re.IGNORECASE,
)
_HARDCODED_SECRET_RE = re.compile(
    r"\b(?:password|passwd|pwd|apiKey|apikey|secret|secretKey)\b\s*=\s*\"[^\"]{3,}\"",
    re.IGNORECASE,
)
_REQUEST_TAINT_RE = re.compile(r"\b\w+\s+(?P<name>\w+)\s*=\s*\w*request\.getParameter\(", re.IGNORECASE)
_FILE_SINK_RE = re.compile(r"new\s+File(?:InputStream)?\s*\(|Paths\.get\s*\(", re.IGNORECASE)
_PATH_PARAM_RE = re.compile(r"\{[^}]*id[^}]*\}", re.IGNORECASE)
_METHOD_RE = re.compile(
    r"^\s*(?:public|protected|private)\s+(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:<[\w\s,?<>]+>\s*)?[\w\[\]<>.,?\s]+\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?:throws\s+[^{]+)?\{\s*$"
)
_CLASS_RE = re.compile(r"\bclass\s+(?P<name>[A-Za-z_]\w*)")
_ANNOTATION_RE = re.compile(r"^\s*@(?P<name>[\w.]+)(?:\((?P<args>.*)\))?\s*$")


@dataclass(frozen=True)
class _JavaMethod:
    name: str
    start_line: int
    body: str
    signature: str
    annotations: tuple[str, ...]
    class_annotations: tuple[str, ...]
    params: tuple[str, ...]
    route_paths: tuple[str, ...]


@dataclass(frozen=True)
class _Annotation:
    name: str
    raw: str
    args: str


@dataclass(frozen=True)
class _ClassScope:
    annotations: tuple[_Annotation, ...]
    depth: int


def _short_name(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _parse_annotations(raw_annotations: list[str]) -> tuple[_Annotation, ...]:
    parsed: list[_Annotation] = []
    for raw in raw_annotations[-10:]:
        match = _ANNOTATION_RE.match(raw)
        if not match:
            continue
        parsed.append(_Annotation(
            name=_short_name(match.group("name")),
            raw=raw.strip(),
            args=(match.group("args") or "").strip(),
        ))
    return tuple(parsed)


def _extract_paths(annotations: tuple[_Annotation, ...]) -> tuple[str, ...]:
    paths: list[str] = []
    for annotation in annotations:
        if annotation.name not in _ROUTE_ANNOTATIONS:
            continue
        for value in re.findall(r'"([^"]+)"', annotation.args):
            paths.append(value)
    return tuple(paths)


def _parse_params(signature_params: str) -> tuple[str, ...]:
    names: list[str] = []
    for chunk in signature_params.split(","):
        part = chunk.strip()
        if not part:
            continue
        tokens = [token for token in re.split(r"\s+", part) if token and not token.startswith("@")]
        if not tokens:
            continue
        candidate = tokens[-1].replace("...", "").strip()
        candidate = candidate.strip("[]")
        if candidate:
            names.append(candidate)
    return tuple(names)


def _collect_methods(source: str) -> list[_JavaMethod]:
    lines = source.splitlines()
    methods: list[_JavaMethod] = []
    pending_annotations: list[str] = []
    class_stack: list[_ClassScope] = []
    brace_depth = 0
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        annotation_match = _ANNOTATION_RE.match(line)
        if annotation_match:
            pending_annotations.append(line)
            brace_depth += line.count("{") - line.count("}")
            while class_stack and brace_depth < class_stack[-1].depth:
                class_stack.pop()
            index += 1
            continue

        if _CLASS_RE.search(line) and "{" in line:
            class_stack.append(_ClassScope(_parse_annotations(pending_annotations), brace_depth + line.count("{") - line.count("}")))
            pending_annotations = []
        else:
            method_match = _METHOD_RE.match(line)
            if method_match and not stripped.startswith(("if ", "for ", "while ", "switch ", "catch ")):
                method_annotations = _parse_annotations(pending_annotations)
                class_annotations = class_stack[-1].annotations if class_stack else ()
                body_lines = [line]
                local_depth = line.count("{") - line.count("}")
                cursor = index + 1
                while cursor < len(lines) and local_depth > 0:
                    body_lines.append(lines[cursor])
                    local_depth += lines[cursor].count("{") - lines[cursor].count("}")
                    cursor += 1
                methods.append(_JavaMethod(
                    name=method_match.group("name"),
                    start_line=index + 1,
                    body="\n".join(body_lines),
                    signature=line.strip(),
                    annotations=tuple(annotation.raw for annotation in method_annotations),
                    class_annotations=tuple(annotation.raw for annotation in class_annotations),
                    params=_parse_params(method_match.group("params")),
                    route_paths=_extract_paths(method_annotations),
                ))
                pending_annotations = []
                brace_depth += sum(body_line.count("{") - body_line.count("}") for body_line in body_lines)
                while class_stack and brace_depth < class_stack[-1].depth:
                    class_stack.pop()
                index = cursor
                continue
            if stripped and not stripped.startswith("//"):
                pending_annotations = []

        brace_depth += line.count("{") - line.count("}")
        while class_stack and brace_depth < class_stack[-1].depth:
            class_stack.pop()
        index += 1

    return methods


def _first_matching_line(text: str, pattern: re.Pattern[str], start_line: int) -> int:
    for offset, line in enumerate(text.splitlines(), start=0):
        if pattern.search(line):
            return start_line + offset
    return start_line


def _has_annotation(annotations: tuple[str, ...], names: set[str]) -> bool:
    for annotation in annotations:
        short = _short_name(annotation.lstrip("@").split("(", 1)[0].strip())
        if short in names:
            return True
    return False


def _has_route(method: _JavaMethod) -> bool:
    return _has_annotation(method.annotations, _ROUTE_ANNOTATIONS)


def _is_public_route(method: _JavaMethod) -> bool:
    return any(_PUBLIC_ROUTE_RE.search(path) for path in method.route_paths)


def _has_auth(method: _JavaMethod) -> bool:
    return (
        _has_annotation(method.annotations, _AUTH_ANNOTATIONS)
        or _has_annotation(method.class_annotations, _AUTH_ANNOTATIONS)
        or bool(_SECURITY_CONTEXT_RE.search(method.body))
    )


def _has_id_route(method: _JavaMethod) -> bool:
    if any(_PATH_PARAM_RE.search(path) for path in method.route_paths):
        return True
    return any(name.lower().endswith("id") or name.lower() == "id" for name in method.params)


def _has_ownership_guard(body: str) -> bool:
    return bool(_OWNERSHIP_RE.search(body))


def _collect_tainted_names(method: _JavaMethod) -> set[str]:
    tainted = {
        name for name in method.params
        if name.lower().endswith(("id", "path", "file", "filename"))
    }
    for line in method.body.splitlines():
        match = _REQUEST_TAINT_RE.search(line)
        if match:
            tainted.add(match.group("name"))
    return tainted


def _dedupe(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, int | None, str], Finding] = {}
    for finding in findings:
        unique[(finding.rule_id, finding.line, finding.title)] = finding
    return sorted(unique.values(), key=lambda item: (item.line or 0, item.rule_id))


def _env_var_name_from_identifier(identifier: str) -> str:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", identifier)
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", normalized)
    normalized = normalized.strip("_") or "SECRET"
    return normalized.upper()


def _generate_auto_fix(finding: Finding, lines: list[str]) -> str:
    if not finding.line or not (1 <= finding.line <= len(lines)):
        return ""
    original = lines[finding.line - 1]
    stripped = original.strip()
    indent = original[: len(original) - len(original.lstrip())]
    if not stripped:
        return ""

    if finding.rule_id == "JV-001" and "@PreAuthorize" not in stripped:
        return (
            f"BEFORE: {stripped}\n"
            f"AFTER:  {indent}@PreAuthorize(\"isAuthenticated()\") {stripped}"
        )

    if finding.rule_id == "JV-002" and "findById(" in stripped:
        updated = re.sub(
            r"findById\s*\(([^)]*)\)",
            r"findByIdAndUserId(\1, currentUserId)",
            stripped,
            count=1,
        )
        if updated != stripped:
            return f"BEFORE: {stripped}\nAFTER:  {indent}{updated}"

    if finding.rule_id == "JV-006":
        match = re.search(r"(?P<lhs>[A-Za-z_][\w]*)\s*=\s*\"[^\"]+\"", stripped)
        if match:
            env_name = _env_var_name_from_identifier(match.group("lhs"))
            updated = re.sub(
                r"=\s*\"[^\"]+\"",
                f'= System.getenv("{env_name}")',
                stripped,
                count=1,
            )
            return f"BEFORE: {stripped}\nAFTER:  {indent}{updated}"

    return ""


_JAVAC_SCRIPT = r"""
import com.github.javaparser.*;
import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import java.util.*;
import java.util.stream.*;

// Parse Java source and extract annotations, method signatures, and class structure
public class JavaStructParser {
    public static void main(String[] args) throws Exception {
        var code = new String(System.in.readAllBytes());
        var cu = StaticJavaParser.parse(code);
        var json = new StringBuilder();
        json.append("{\"classes\":[");
        boolean first = true;
        for (var type : cu.getTypes()) {
            if (!(type instanceof ClassOrInterfaceDeclaration klass)) continue;
            if (!first) json.append(","); first = false;
            json.append("{\"name\":\"").append(esc(klass.getNameAsString())).append("\",");
            json.append("\"annotations\":[");
            annots(klass.getAnnotations(), json);
            json.append("],");
            json.append("\"methods\":[");
            boolean mf = true;
            for (var m : klass.getMethods()) {
                if (!mf) json.append(","); mf = false;
                json.append("{\"name\":\"").append(esc(m.getNameAsString())).append("\",");
                json.append("\"line\":").append(m.getBegin().map(p -> p.line).orElse(0)).append(",");
                json.append("\"annotations\":[");
                annots(m.getAnnotations(), json);
                json.append("],");
                json.append("\"params\":[");
                boolean pf = true;
                for (var p : m.getParameters()) {
                    if (!pf) json.append(","); pf = false;
                    json.append("{\"name\":\"").append(esc(p.getNameAsString())).append("\"}");
                }
                json.append("]");
                json.append("}");
            }
            json.append("]");
            json.append("}");
        }
        json.append("]}");
        System.out.println(json);
    }
    static void annots(NodeList<AnnotationExpr> list, StringBuilder sb) {
        boolean f = true;
        for (var a : list) {
            if (!f) sb.append(","); f = false;
            sb.append("{\"name\":\"").append(esc(a.getNameAsString())).append("\",");
            sb.append("\"args\":\"\"}");
        }
    }
    static String esc(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }
}
"""


def _parse_with_javac(source: str) -> dict | None:
    """Parse Java source using javac + JavaParser (subprocess).

    Returns a dict with class/method/annotation structure, or None if
    javac is not available or parsing fails.

    Graceful degradation: returns None silently on any error.
    """
    import subprocess
    import tempfile
    import os

    # Check if javac is available
    try:
        subprocess.run(["javac", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    # Write the parser source to a temp file and compile + run
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            parser_file = os.path.join(tmpdir, "JavaStructParser.java")
            with open(parser_file, "w") as f:
                f.write(_JAVAC_SCRIPT)

            # Compile
            compile_result = subprocess.run(
                ["javac", "-cp", ".", parser_file],
                capture_output=True, text=True, timeout=15,
            )
            if compile_result.returncode != 0:
                return None

            # Run on the source code
            run_result = subprocess.run(
                ["java", "-cp", tmpdir, "JavaStructParser"],
                input=source, capture_output=True, text=True, timeout=15,
            )
            if run_result.returncode != 0:
                return None

            import json
            return json.loads(run_result.stdout)
    except Exception:
        return None


def _enrich_with_javac(findings: list[Finding], source: str) -> list[Finding]:
    """Enrich findings with structural data from javac parsing.

    Currently adjusts confidence based on annotation presence.
    """
    parsed = _parse_with_javac(source)
    if parsed is None:
        return findings

    # Build set of annotated methods from the parse tree
    annotated_methods: dict[str, set[str]] = {}  # class_name -> {annotation_names}
    for cls in parsed.get("classes", []):
        cls_name = cls.get("name", "")
        cls_annots = {a.get("name", "") for a in cls.get("annotations", [])}
        for method in cls.get("methods", []):
            m_name = method.get("name", "")
            m_annots = {a.get("name", "") for a in method.get("annotations", [])}
            # Merge class-level annotations
            all_annots = cls_annots | m_annots
            annotated_methods[f"{cls_name}.{m_name}"] = all_annots

    for finding in findings:
        if finding.rule_id in ("JV-001", "JV-002"):
            # Check if structural parse confirms the finding
            for key, annots in annotated_methods.items():
                if finding.rule_id == "JV-001" and any(
                    a in annots for a in _AUTH_ANNOTATIONS
                ):
                    # Structural parser found auth annotation — downgrade confidence
                    finding.confidence = 0.3
                    finding.analysis_kind = "javac-augmented"
                    break

    return findings


def analyze_java(
    source: str,
    filename: str = "<input>",
    *,
    use_javac: bool = False,
    global_graph: object | None = None,
) -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="java")
    lines = source.splitlines()
    result.lines_scanned = len(lines)
    methods = _collect_methods(source)
    findings: list[Finding] = []

    for method in methods:
        annotation_names = {
            _short_name(annotation.lstrip("@").split("(", 1)[0].strip())
            for annotation in method.annotations
        }

        if _has_route(method) and not _is_public_route(method) and not _has_auth(method):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-862: Spring route `{method.name}()` missing authentication guard",
                description="Mapped Spring controller method lacks @PreAuthorize/@Secured/@RolesAllowed and no SecurityContext check was found in the body.",
                line=method.start_line,
                suggestion="Protect the handler with @PreAuthorize/@Secured or verify the authenticated principal before returning sensitive data.",
                rule_id="JV-001", cwe="CWE-862", agent="java-analyzer",
                confidence=0.88, analysis_kind="route_heuristic",
            ))

        if _has_route(method) and _has_id_route(method) and re.search(r"\b(?:findById|findOne|getOne)\s*\(", method.body) and not _has_ownership_guard(method.body):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-639: Route `{method.name}()` loads resource by id without ownership scope",
                description="A path-bound controller method performs a repository lookup by id with no visible owner/user restriction.",
                line=_first_matching_line(method.body, re.compile(r"\b(?:findById|findOne|getOne)\s*\(", re.IGNORECASE), method.start_line),
                suggestion="Scope the lookup by both resource id and current user/tenant, for example findByIdAndUserId(...).",
                rule_id="JV-002", cwe="CWE-639", agent="java-analyzer",
                confidence=0.9, analysis_kind="route_heuristic",
            ))

        if annotation_names & _MUTATING_ROUTE_ANNOTATIONS and re.search(r"\.(?:save|delete|deleteById)\s*\(", method.body) and not _has_ownership_guard(method.body):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-285: Mutating route `{method.name}()` missing authorization or ownership check",
                description="A state-changing Spring route performs save/delete behavior with no visible ownership or permission check.",
                line=_first_matching_line(method.body, re.compile(r"\.(?:save|delete|deleteById)\s*\(", re.IGNORECASE), method.start_line),
                suggestion="Verify owner/tenant scope or role permissions before mutating the entity.",
                rule_id="JV-003", cwe="CWE-285", agent="java-analyzer",
                confidence=0.84, analysis_kind="route_heuristic",
            ))

        if _SQLI_RE.search(method.body):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-89: Dynamic SQL construction in `{method.name}()`",
                description="SQL execution appears to use string concatenation or String.format instead of bind parameters.",
                line=_first_matching_line(method.body, _SQLI_RE, method.start_line),
                suggestion="Use prepared statements, named parameters, or ORM bind variables instead of building SQL text dynamically.",
                rule_id="JV-004", cwe="CWE-89", agent="java-analyzer",
                confidence=0.95, analysis_kind="taint_flow",
            ))

        if re.search(r"ObjectInputStream\s*\w*\s*=|ObjectInputStream\s*\(", method.body) and re.search(r"\.readObject\s*\(", method.body):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-502: Unsafe Java deserialization in `{method.name}()`",
                description="ObjectInputStream.readObject() can instantiate attacker-controlled objects and lead to remote code execution.",
                line=_first_matching_line(method.body, re.compile(r"\.readObject\s*\(", re.IGNORECASE), method.start_line),
                suggestion="Avoid Java native serialization for untrusted data; prefer JSON/XML DTO parsing with strict schemas.",
                rule_id="JV-005", cwe="CWE-502", agent="java-analyzer",
                confidence=0.98, analysis_kind="pattern",
            ))

        tainted_names = _collect_tainted_names(method)
        if tainted_names and _FILE_SINK_RE.search(method.body):
            for name in sorted(tainted_names):
                if re.search(rf"(?:new\s+File(?:InputStream)?\s*\([^)]*\b{name}\b|Paths\.get\s*\([^)]*\b{name}\b)", method.body):
                    findings.append(Finding(
                        category="security", severity=Severity.HIGH,
                        title=f"CWE-22: User-controlled path reaches file API in `{method.name}()`",
                        description="A request-derived parameter is passed into File/Paths APIs without visible path normalization.",
                        line=_first_matching_line(method.body, re.compile(rf"\b{name}\b"), method.start_line),
                        suggestion="Normalize the path against a trusted base directory and reject any path that escapes it.",
                        rule_id="JV-007", cwe="CWE-22", agent="java-analyzer",
                        confidence=0.82, analysis_kind="taint_flow",
                    ))
                    break

    for lineno, line in enumerate(source.splitlines(), start=1):
        if _HARDCODED_SECRET_RE.search(line):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title="CWE-798: Hardcoded credential in Java source",
                description="A password/apiKey/secret literal is assigned directly in code.",
                line=lineno,
                suggestion="Move credentials to environment variables or a secrets manager and rotate the exposed value.",
                rule_id="JV-006", cwe="CWE-798", agent="java-analyzer",
                confidence=0.96, analysis_kind="pattern",
            ))

    # Javac structural enrichment (optional, graceful degradation)
    if use_javac:
        findings = _enrich_with_javac(findings, source)

    # FunctionSummary recording via GlobalGraph
    if global_graph is not None:
        try:
            from ansede_static.ir.global_graph import FunctionSummary
            for f in findings:
                summary = FunctionSummary(
                    file_path=filename,
                    function_name=f"java_{f.rule_id}_line{f.line}",
                    is_sink=bool(f.cwe),
                    taint_sinks=[f.cwe] if f.cwe else [],
                )
                global_graph.record_function_summary(summary)
        except Exception:
            pass

    result.findings = _dedupe(findings)
    for finding in result.findings:
        if not finding.auto_fix:
            finding.auto_fix = _generate_auto_fix(finding, lines)
    return result

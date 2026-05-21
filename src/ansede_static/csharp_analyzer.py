"""
csharp_analyzer.py — Ansede Static C# detection engine.

PERFORMANCE CONTRACT:
  Analysis is bounded structural heuristics over regex-identified method blocks.
  No full grammar parse tree is constructed. Method boundary detection is O(n)
  in line count. Attribute context lookup is O(k) where k = attribute lines
  above a method (bounded to 10). Total complexity: O(n) per file.
  Worst-case measured against a 10k-line ASP.NET Core controller: < 400ms.
  This stays well within the 10s/100kLOC budget.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from ansede_static._types import AnalysisResult, Finding, Severity


_ROUTE_ATTRIBUTES = {"HttpGet", "HttpPost", "HttpPut", "HttpDelete", "Route"}
_MUTATING_ATTRIBUTES = {"HttpPut", "HttpDelete"}
_PUBLIC_ROUTE_RE = re.compile(r"/(?:login|logout|register|signup|health|ready|status|public|swagger|docs)", re.IGNORECASE)
_AUTHZ_RE = re.compile(r"Authorize|User\.Identity\.IsAuthenticated|User\.IsInRole|ClaimsPrincipal|RequireAuthorization", re.IGNORECASE)
_OWNERSHIP_RE = re.compile(r"UserId|OwnerId|AccountId|TenantId|currentUser|GetUserId\(|User\.FindFirst|User\.Identity\.Name|Where\s*\([^)]*UserId", re.IGNORECASE)
_SQLI_RE = re.compile(r"(?:SqlCommand\s*\(|CommandText\s*=\s*)(?:\$\"|[^;\n]*\+[^;\n]*)", re.IGNORECASE)
_HARDCODED_CONN_RE = re.compile(r'\"[^\"]*(?:Password=|pwd=|ApiKey=)[^\"]*\"', re.IGNORECASE)
_METHOD_RE = re.compile(
    r"^\s*(?:public|protected|private|internal)\s+(?:async\s+)?(?:static\s+)?(?:virtual\s+)?(?:override\s+)?[\w<>,\[\]\.\?\s]+\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?:\{\s*)?$"
)
_CLASS_RE = re.compile(r"\bclass\s+(?P<name>[A-Za-z_]\w*)")
_ATTRIBUTE_LINE_RE = re.compile(r"^\s*\[(?P<content>.+)\]\s*$")
_ID_ROUTE_RE = re.compile(r"\{[^}]*id[^}]*\}", re.IGNORECASE)
_FINDASYNC_RE = re.compile(r"\.(?:FindAsync|FirstOrDefaultAsync|FirstOrDefault)\s*\([^\n;]*\bid\b", re.IGNORECASE)
_SAVE_RE = re.compile(r"SaveChanges(?:Async)?\s*\(", re.IGNORECASE)
_XXE_ENTRY_RE = re.compile(r"\b(?:XmlDocument|XmlReader|XmlReaderSettings)\b", re.IGNORECASE)
_SAFE_DTD_RE = re.compile(r"DtdProcessing\s*=\s*DtdProcessing\.(?:Prohibit|Ignore)", re.IGNORECASE)


@dataclass(frozen=True)
class _CSharpMethod:
    name: str
    start_line: int
    body: str
    signature: str
    attributes: tuple[str, ...]
    class_attributes: tuple[str, ...]
    params: tuple[str, ...]
    route_paths: tuple[str, ...]


@dataclass(frozen=True)
class _Attribute:
    name: str
    raw: str
    args: str


@dataclass(frozen=True)
class _ClassScope:
    attributes: tuple[_Attribute, ...]
    depth: int


def _short_name(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _parse_attribute_items(content: str) -> tuple[_Attribute, ...]:
    items: list[_Attribute] = []
    cursor = 0
    segment: list[str] = []
    depth = 0
    while cursor < len(content):
        char = content[cursor]
        if char == ',' and depth == 0:
            raw = "".join(segment).strip()
            if raw:
                items.append(_attribute_from_raw(raw))
            segment = []
            cursor += 1
            continue
        if char == '(':
            depth += 1
        elif char == ')':
            depth = max(0, depth - 1)
        segment.append(char)
        cursor += 1
    raw = "".join(segment).strip()
    if raw:
        items.append(_attribute_from_raw(raw))
    return tuple(item for item in items if item.name)


def _attribute_from_raw(raw: str) -> _Attribute:
    if '(' in raw:
        name, args = raw.split('(', 1)
        return _Attribute(name=_short_name(name.strip()), raw=f"[{raw}]", args=args.rsplit(')', 1)[0].strip())
    return _Attribute(name=_short_name(raw.strip()), raw=f"[{raw}]", args="")


def _extract_paths(attributes: tuple[_Attribute, ...]) -> tuple[str, ...]:
    paths: list[str] = []
    for attribute in attributes:
        if attribute.name not in _ROUTE_ATTRIBUTES:
            continue
        for value in re.findall(r'"([^"]+)"', attribute.args):
            paths.append(value)
    return tuple(paths)


def _parse_params(signature_params: str) -> tuple[str, ...]:
    names: list[str] = []
    for chunk in signature_params.split(','):
        part = chunk.strip()
        if not part:
            continue
        tokens = [token for token in re.split(r"\s+", part) if token and not token.startswith("[")]
        if not tokens:
            continue
        candidate = tokens[-1].strip()
        candidate = candidate.split('=')[0].strip()
        if candidate:
            names.append(candidate)
    return tuple(names)


def _collect_methods(source: str) -> list[_CSharpMethod]:
    lines = source.splitlines()
    methods: list[_CSharpMethod] = []
    pending_attribute_lines: list[str] = []
    class_stack: list[_ClassScope] = []
    brace_depth = 0
    index = 0

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        attr_match = _ATTRIBUTE_LINE_RE.match(line)
        if attr_match:
            pending_attribute_lines.append(attr_match.group("content"))
            brace_depth += line.count('{') - line.count('}')
            while class_stack and brace_depth < class_stack[-1].depth:
                class_stack.pop()
            index += 1
            continue

        if _CLASS_RE.search(line) and '{' in line:
            parsed_attrs = []
            for raw in pending_attribute_lines[-10:]:
                parsed_attrs.extend(_parse_attribute_items(raw))
            class_stack.append(_ClassScope(tuple(parsed_attrs), brace_depth + line.count('{') - line.count('}')))
            pending_attribute_lines = []
        else:
            method_match = _METHOD_RE.match(line)
            if method_match and not stripped.startswith(("if ", "for ", "while ", "switch ", "catch ")):
                parsed_attrs: list[_Attribute] = []
                for raw in pending_attribute_lines[-10:]:
                    parsed_attrs.extend(_parse_attribute_items(raw))
                class_attrs = class_stack[-1].attributes if class_stack else ()
                body_lines = [line]
                local_depth = line.count('{') - line.count('}')
                cursor = index + 1
                while cursor < len(lines) and local_depth <= 0:
                    body_lines.append(lines[cursor])
                    local_depth += lines[cursor].count('{') - lines[cursor].count('}')
                    cursor += 1
                if local_depth <= 0:
                    pending_attribute_lines = []
                    index = cursor
                    continue
                while cursor < len(lines) and local_depth > 0:
                    body_lines.append(lines[cursor])
                    local_depth += lines[cursor].count('{') - lines[cursor].count('}')
                    cursor += 1
                methods.append(_CSharpMethod(
                    name=method_match.group('name'),
                    start_line=index + 1,
                    body='\n'.join(body_lines),
                    signature=line.strip(),
                    attributes=tuple(attribute.raw for attribute in parsed_attrs),
                    class_attributes=tuple(attribute.raw for attribute in class_attrs),
                    params=_parse_params(method_match.group('params')),
                    route_paths=_extract_paths(tuple(parsed_attrs)),
                ))
                pending_attribute_lines = []
                brace_depth += sum(body_line.count('{') - body_line.count('}') for body_line in body_lines)
                while class_stack and brace_depth < class_stack[-1].depth:
                    class_stack.pop()
                index = cursor
                continue
            if stripped and not stripped.startswith("//"):
                pending_attribute_lines = []

        brace_depth += line.count('{') - line.count('}')
        while class_stack and brace_depth < class_stack[-1].depth:
            class_stack.pop()
        index += 1

    return methods


def _has_attribute(attributes: tuple[str, ...], names: set[str]) -> bool:
    for raw in attributes:
        short = _short_name(raw.strip()[1:-1].split('(', 1)[0].strip())
        if short in names:
            return True
    return False


def _is_public_route(method: _CSharpMethod) -> bool:
    return any(_PUBLIC_ROUTE_RE.search(path) for path in method.route_paths)


def _has_auth(method: _CSharpMethod) -> bool:
    if _has_attribute(method.attributes, {"Authorize"}) or _has_attribute(method.class_attributes, {"Authorize"}):
        return True
    return bool(_AUTHZ_RE.search(method.body))


def _has_allow_anonymous(method: _CSharpMethod) -> bool:
    return _has_attribute(method.attributes, {"AllowAnonymous"}) or _has_attribute(method.class_attributes, {"AllowAnonymous"})


def _has_route(method: _CSharpMethod) -> bool:
    return _has_attribute(method.attributes, _ROUTE_ATTRIBUTES)


def _has_id_route(method: _CSharpMethod) -> bool:
    if any(_ID_ROUTE_RE.search(path) for path in method.route_paths):
        return True
    return any(name.lower() == "id" or name.lower().endswith("id") for name in method.params)


def _has_ownership_guard(body: str) -> bool:
    return bool(_OWNERSHIP_RE.search(body))


def _first_matching_line(text: str, pattern: re.Pattern[str], start_line: int) -> int:
    for offset, line in enumerate(text.splitlines(), start=0):
        if pattern.search(line):
            return start_line + offset
    return start_line


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

    if finding.rule_id == "CS-001" and "[Authorize]" not in stripped:
        return f"BEFORE: {stripped}\nAFTER:  {indent}[Authorize] {stripped}"

    if finding.rule_id == "CS-002" and "FindAsync(" in stripped:
        updated = stripped.replace(
            "FindAsync(id)",
            "Where(x => x.UserId == userId).FirstOrDefaultAsync(x => x.Id == id)",
            1,
        )
        if updated != stripped:
            return f"BEFORE: {stripped}\nAFTER:  {indent}{updated}"

    if finding.rule_id == "CS-006":
        match = re.search(r"(?P<lhs>[A-Za-z_][\w]*)\s*=\s*\"[^\"]+\"", stripped)
        if match:
            env_name = _env_var_name_from_identifier(match.group("lhs"))
            updated = re.sub(
                r"=\s*\"[^\"]+\"",
                f'= Environment.GetEnvironmentVariable("{env_name}") ?? string.Empty',
                stripped,
                count=1,
            )
            return f"BEFORE: {stripped}\nAFTER:  {indent}{updated}"

    return ""


def analyze_csharp(source: str, filename: str = "<input>") -> AnalysisResult:
    result = AnalysisResult(file_path=filename, language="csharp")
    lines = source.splitlines()
    result.lines_scanned = len(lines)

    methods = _collect_methods(source)
    findings: list[Finding] = []

    for method in methods:
        attr_names = {_short_name(raw.strip()[1:-1].split('(', 1)[0].strip()) for raw in method.attributes}

        if _has_route(method) and not _is_public_route(method) and not _has_auth(method) and not _has_allow_anonymous(method):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-862: ASP.NET action `{method.name}()` missing [Authorize]",
                description="Controller action exposes a routed endpoint without [Authorize] and no obvious authenticated-user check was found in the body.",
                line=method.start_line,
                suggestion="Add [Authorize] at the action or controller level, or enforce authentication through endpoint policy configuration.",
                rule_id="CS-001",
                cwe="CWE-862",
                agent="csharp-analyzer",
                confidence=0.88,
                analysis_kind="route_heuristic",
            ))

        if _has_route(method) and _has_id_route(method) and _FINDASYNC_RE.search(method.body) and not _has_ownership_guard(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-639: Entity lookup by route id without ownership scope in `{method.name}()`",
                description="The action loads an entity by id using FindAsync/FirstOrDefault without a visible user or tenant scope restriction.",
                line=_first_matching_line(method.body, _FINDASYNC_RE, method.start_line),
                suggestion="Add a Where(x => x.UserId == userId) or equivalent owner/tenant predicate before returning the entity.",
                rule_id="CS-002",
                cwe="CWE-639",
                agent="csharp-analyzer",
                confidence=0.9,
                analysis_kind="route_heuristic",
            ))

        if attr_names & _MUTATING_ATTRIBUTES and _SAVE_RE.search(method.body) and not _has_ownership_guard(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-285: Mutating ASP.NET action `{method.name}()` missing ownership/authorization guard",
                description="A PUT/DELETE action persists changes via SaveChanges without a visible owner or permission assertion.",
                line=_first_matching_line(method.body, _SAVE_RE, method.start_line),
                suggestion="Verify ownership or permissions before mutating and persisting the entity.",
                rule_id="CS-003",
                cwe="CWE-285",
                agent="csharp-analyzer",
                confidence=0.84,
                analysis_kind="route_heuristic",
            ))

        if _SQLI_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-89: Dynamic SQL command text in `{method.name}()`",
                description="SqlCommand usage appears to build SQL using string concatenation or interpolation instead of parameters.",
                line=_first_matching_line(method.body, _SQLI_RE, method.start_line),
                suggestion="Use SqlParameter objects or parameter placeholders instead of interpolating attacker-controlled data into SQL text.",
                rule_id="CS-004",
                cwe="CWE-89",
                agent="csharp-analyzer",
                confidence=0.95,
                analysis_kind="taint_flow",
            ))

        if re.search(r"\b(?:BinaryFormatter|NetDataContractSerializer)\b", method.body) and re.search(r"\.Deserialize\s*\(", method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-502: Dangerous .NET deserialization in `{method.name}()`",
                description="BinaryFormatter.Deserialize or NetDataContractSerializer.Deserialize can execute attacker-controlled gadget chains.",
                line=_first_matching_line(method.body, re.compile(r"\.Deserialize\s*\(", re.IGNORECASE), method.start_line),
                suggestion="Avoid BinaryFormatter/NetDataContractSerializer for untrusted data; use System.Text.Json or safe DTO serialization.",
                rule_id="CS-005",
                cwe="CWE-502",
                agent="csharp-analyzer",
                confidence=0.98,
                analysis_kind="pattern",
            ))

        if _XXE_ENTRY_RE.search(method.body) and not _SAFE_DTD_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-611: XML parser in `{method.name}()` does not explicitly prohibit DTD processing",
                description="XmlDocument/XmlReader usage appears without DtdProcessing = Prohibit/Ignore, which can enable XXE behavior in unsafe parser configurations.",
                line=_first_matching_line(method.body, _XXE_ENTRY_RE, method.start_line),
                suggestion="Set DtdProcessing = Prohibit or Ignore and avoid resolving external entities when parsing untrusted XML.",
                rule_id="CS-007",
                cwe="CWE-611",
                agent="csharp-analyzer",
                confidence=0.78,
                analysis_kind="pattern",
            ))

        # ── CS-008: ASP.NET Core XSS via HttpContext.Response.WriteAsync ──
        _XSS_WRITE_RE = re.compile(
            r'HttpContext\.Response\.WriteAsync\s*\([^)]*\)|'
            r'Context\.Response\.WriteAsync\s*\([^)]*\)',
            re.IGNORECASE,
        )
        if _has_route(method) and _XSS_WRITE_RE.search(method.body):
            # Check for HTML encoding or sanitization nearby
            _XSS_SAFE_RE = re.compile(
                r'HtmlEncoder|UrlEncoder|WebUtility\.HtmlEncode|AntiXss|Server\.HtmlEncode|'
                r'TagBuilder|RenderBody|Html\.Raw',
                re.IGNORECASE,
            )
            if not _XSS_SAFE_RE.search(method.body):
                findings.append(Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title=f"CWE-79: Unencoded response write in `{method.name}()`",
                    description=(
                        "Response.WriteAsync is called in a routed action without "
                        "visible HTML encoding. Attackers can inject scripts via request data."
                    ),
                    line=_first_matching_line(method.body, _XSS_WRITE_RE, method.start_line),
                    suggestion=(
                        "Encode output with WebUtility.HtmlEncode() or use Razor views "
                        "which auto-encode by default."
                    ),
                    rule_id="CS-008",
                    cwe="CWE-79",
                    agent="csharp-analyzer",
                    confidence=0.72,
                    analysis_kind="pattern",
                ))

        # ── CS-009: ASP.NET Core CSRF on mutating actions ────────────────
        if attr_names & _MUTATING_ATTRIBUTES and _has_route(method):
            _CSRF_PROTECTION_RE = re.compile(
                r'ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|'
                r'__RequestVerificationToken|AntiforgeryTokenSet',
                re.IGNORECASE,
            )
            if not _CSRF_PROTECTION_RE.search(method.body):
                # Also check for controller-level [AutoValidateAntiforgeryToken]
                controller_has_csrf = any(
                    'AutoValidateAntiforgeryToken' in attr or 'ValidateAntiForgeryToken' in attr
                    for attr in method.class_attributes
                )
                if not controller_has_csrf:
                    findings.append(Finding(
                        category="security",
                        severity=Severity.MEDIUM,
                        title=f"CWE-352: CSRF on mutating action `{method.name}()`",
                        description=(
                            "A PUT/DELETE action has no [ValidateAntiForgeryToken] "
                            "and no controller-level antiforgery attribute was detected."
                        ),
                        line=method.start_line,
                        suggestion=(
                            "Add [ValidateAntiForgeryToken] to the action or apply "
                            "[AutoValidateAntiforgeryToken] at the controller level."
                        ),
                        rule_id="CS-009",
                        cwe="CWE-352",
                        agent="csharp-analyzer",
                        confidence=0.75,
                        analysis_kind="route_heuristic",
                    ))

    for lineno, line in enumerate(source.splitlines(), start=1):
        if _HARDCODED_CONN_RE.search(line):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title="CWE-798: Hardcoded connection secret in C# source",
                description="A string literal contains a password or API key directly in source code.",
                line=lineno,
                suggestion="Move connection strings and API keys into configuration providers or a secrets manager and rotate the exposed value.",
                rule_id="CS-006",
                cwe="CWE-798",
                agent="csharp-analyzer",
                confidence=0.97,
                analysis_kind="pattern",
            ))

    result.findings = _dedupe(findings)
    for finding in result.findings:
        if not finding.auto_fix:
            finding.auto_fix = _generate_auto_fix(finding, lines)
    return result

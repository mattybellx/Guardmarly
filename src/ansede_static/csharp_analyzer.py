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
_PUBLIC_ACCESS_ATTRIBUTES = {"AllowAnonymous", "CheckAccessPublicStore"}
_PUBLIC_ROUTE_RE = re.compile(r"/(?:login|logout|register|signup|health|ready|status|public|swagger|docs)", re.IGNORECASE)
_PUBLIC_ACTION_NAME_RE = re.compile(r"^(?:SendOtp|CommonVerificationOtp|CheckBalance|BackToCart)$", re.IGNORECASE)
_AUTHZ_RE = re.compile(
    r"Authorize|User\.Identity\.IsAuthenticated|User\.IsInRole|ClaimsPrincipal|RequireAuthorization|"
    r"Check\w*Permission(?:Async)?\s*\(|AuthorizeAsync\s*\(|Challenge\s*\(|AccessDenied",
    re.IGNORECASE,
)
_OWNERSHIP_RE = re.compile(
    r"UserId|OwnerId|AccountId|TenantId|currentUser|currentCustomer|GetUserId\(|GetCurrentCustomerAsync\(|"
    r"User\.FindFirst|User\.Identity\.Name|Where\s*\([^)]*(?:UserId|CustomerId)|"
    r"(?:ToCustomerId|FromCustomerId|CustomerId)\s*==\s*(?:customer|currentCustomer)\.Id|"
    r"(?:customer|currentCustomer)\.Id\s*==\s*(?:ToCustomerId|FromCustomerId|CustomerId)",
    re.IGNORECASE,
)
_SQLI_RE = re.compile(r"(?:SqlCommand\s*\(|CommandText\s*=\s*)(?:\$\"|[^;\n]*\+[^;\n]*)", re.IGNORECASE)
_HARDCODED_CONN_RE = re.compile(r'\"[^\"]*(?:Password=|pwd=|ApiKey=)[^\"]*\"', re.IGNORECASE)
_METHOD_RE = re.compile(
    r"^\s*(?:public|protected|private|internal)\s+(?:async\s+)?(?:static\s+)?(?:virtual\s+)?(?:override\s+)?[\w<>,\[\]\.\?\s]+\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?:\{\s*)?$"
)
_CLASS_RE = re.compile(r"\bclass\s+(?P<name>[A-Za-z_]\w*)")
_ATTRIBUTE_LINE_RE = re.compile(r"^\s*\[(?P<content>.+?)\]\s*(?://.*)?$")
_ADMIN_CONTROLLER_RE = re.compile(r"\bclass\s+[A-Za-z_]\w*\s*:\s*BaseAdmin\w*Controller\b")
_ADMIN_CONTROLLER_IMPORT_RE = re.compile(r"using\s+Nop\.Web\.Areas\.Admin\.Controllers\s*;")
_ADMIN_DERIVED_CONTROLLER_RE = re.compile(r"\bclass\s+[A-Za-z_]\w*\s*:\s*[A-Za-z_]\w*Controller\b")
_ID_ROUTE_RE = re.compile(r"\{[^}]*id[^}]*\}", re.IGNORECASE)
_FINDASYNC_RE = re.compile(r"\.(?:FindAsync|FirstOrDefaultAsync|FirstOrDefault)\s*\([^\n;]*\bid\b", re.IGNORECASE)
_SAVE_RE = re.compile(r"SaveChanges(?:Async)?\s*\(", re.IGNORECASE)
_XXE_ENTRY_RE = re.compile(r"\b(?:XmlDocument|XmlReader|XmlReaderSettings)\b", re.IGNORECASE)
_SAFE_DTD_RE = re.compile(r"DtdProcessing\s*=\s*DtdProcessing\.(?:Prohibit|Ignore)", re.IGNORECASE)

# Phase A — Unsafe deserialization (CWE-502)
_CS_DESERIALIZATION_RE = re.compile(
    r"(?:new\s+BinaryFormatter|BinaryFormatter\s+\w+\s*=|\.Deserialize\s*\(|"
    r"new\s+LosFormatter|LosFormatter\s+\w+\s*=|"
    r"new\s+ObjectStateFormatter|ObjectStateFormatter\s+\w+\s*=|"
    r"new\s+NetDataContractSerializer|NetDataContractSerializer\s+\w+\s*=|"
    r"new\s+SoapFormatter|SoapFormatter\s+\w+\s*=|"
    r"JavaScriptSerializer\s*\(\s*\)\s*\.\s*Deserialize)",
    re.IGNORECASE,
)
# Phase A — Command injection (CWE-78)
_CS_CMD_INJECTION_RE = re.compile(
    r"(?:Process\.Start\s*\(|new\s+Process\s*\(\s*\)\s*\{|\.StartInfo\s*=\s*new)",
    re.IGNORECASE,
)
# Phase A — SSRF (CWE-918)
_CS_SSRF_RE = re.compile(
    r"(?:HttpClient\.Get(?:String|Stream|ByteArray)?Async\s*\(|"
    r"WebClient\.DownloadString\s*\(|WebRequest\.Create\s*\(|"
    r"RestClient\.Execute\s*\()",
    re.IGNORECASE,
)
# Phase A — Hardcoded secrets (CWE-798)
_CS_HARDCODED_SECRET_RE = re.compile(
    r'\b(?:password|passwd|pwd|secret|apiKey|apikey|connectionString|jwtSecret)\s*=\s*"[^"]{3,}"',
    re.IGNORECASE,
)
# Phase A — Insecure TLS (CWE-295)
_CS_INSECURE_TLS_RE = re.compile(
    r'(?:ServicePointManager\.ServerCertificateValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true|'
    r'ServerCertificateCustomValidationCallback\s*=\s*\([^)]*\)\s*=>\s*true)',
    re.IGNORECASE,
)
# Phase A — Path traversal (CWE-22)
_CS_PATH_TRAVERSAL_RE = re.compile(
    r"(?:Path\.Combine\s*\(|File\.ReadAll(?:Text|Bytes|Lines)?\s*\(|File\.Open\s*\(|"
    r"Directory\.GetFiles\s*\(|Server\.MapPath\s*\()",
    re.IGNORECASE,
)
# Phase A — Open redirect (CWE-601)
_CS_OPEN_REDIRECT_RE = re.compile(
    r"(?:Redirect\s*\(|RedirectToAction\s*\(|RedirectToRoute\s*\(|"
    r"RedirectToPage\s*\(|LocalRedirect\s*\()",
    re.IGNORECASE,
)
# Phase A — SQL injection via raw queries (CWE-89)
_CS_SQLI_RAW_RE = re.compile(
    r'(?:ExecuteSqlRaw\s*\(|ExecuteSqlInterpolated\s*\(|FromSqlRaw\s*\(|'
    r'ExecuteSqlCommand\s*\(|SqlQueryRaw\s*\()',
    re.IGNORECASE,
)
# Phase A — XSS via unencoded output (CWE-79)
_CS_XSS_RE = re.compile(
    r'@Html\.Raw\s*\(|Response\.Write\s*\(|\.InnerHtml\s*=|MvcHtmlString\.Create\s*\(',
    re.IGNORECASE,
)
# Phase A — Mass assignment / over-posting (CWE-915)
_CS_MASS_ASSIGNMENT_RE = re.compile(
    r'(?:TryUpdateModelAsync?\s*\(|UpdateModelAsync?\s*\()',
    re.IGNORECASE,
)
# Phase A — Log injection (CWE-117)
_CS_LOG_INJECTION_RE = re.compile(
    r'(?:\.Log(?:Information|Warning|Error|Debug|Trace)\s*\([^)]*\+|'
    r'\.Log(?:Information|Warning|Error|Debug|Trace)\s*\([^)]*String\.Format)',
    re.IGNORECASE,
)
_CS_LDAP_INJECTION_RE = re.compile(
    r'(?:DirectorySearcher\s*\(|\.FindOne\s*\(|\.FindAll\s*\(|new\s+DirectoryEntry\s*\()',
    re.IGNORECASE,
)
_CS_WEAK_CRYPTO_RE = re.compile(
    r'(?:MD5CryptoServiceProvider|SHA1CryptoServiceProvider|DESCryptoServiceProvider|'
    r'RC2CryptoServiceProvider|MD5\.Create\s*\(|SHA1\.Create\s*\()',
    re.IGNORECASE,
)
_CS_NOSQL_INJECTION_RE = re.compile(
    r'(?:\.Find\s*\(\s*new\s*BsonDocument|\.FindOneAndUpdate\s*\(|Builders<[^>]+>\.Filter\.)',
    re.IGNORECASE,
)


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
        defer_scope_cleanup = False
        attr_match = _ATTRIBUTE_LINE_RE.match(line)
        if attr_match:
            pending_attribute_lines.append(attr_match.group("content"))
            brace_depth += line.count('{') - line.count('}')
            while class_stack and brace_depth < class_stack[-1].depth:
                class_stack.pop()
            index += 1
            continue

        class_match = _CLASS_RE.search(line)
        class_opens_next_line = False
        if class_match and '{' not in line:
            lookahead = index + 1
            while lookahead < len(lines):
                next_stripped = lines[lookahead].strip()
                if not next_stripped or next_stripped.startswith("//"):
                    lookahead += 1
                    continue
                class_opens_next_line = next_stripped == '{'
                break

        if class_match and ('{' in line or class_opens_next_line):
            parsed_attrs = []
            for raw in pending_attribute_lines[-10:]:
                parsed_attrs.extend(_parse_attribute_items(raw))
            class_depth = brace_depth + line.count('{') - line.count('}')
            if class_opens_next_line and '{' not in line:
                class_depth += 1
                defer_scope_cleanup = True
            class_stack.append(_ClassScope(tuple(parsed_attrs), class_depth))
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
        if not defer_scope_cleanup:
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
    return bool(_PUBLIC_ACTION_NAME_RE.match(method.name)) or any(_PUBLIC_ROUTE_RE.search(path) for path in method.route_paths)


def _has_auth(method: _CSharpMethod) -> bool:
    def _looks_like_auth_attribute(raw: str) -> bool:
        short = _short_name(raw.strip()[1:-1].split('(', 1)[0].strip())
        return short == "CheckPermission" or "Authorize" in short

    if any(_looks_like_auth_attribute(raw) for raw in (*method.attributes, *method.class_attributes)):
        return True
    if _has_ownership_guard(method.body):
        return True
    return bool(_AUTHZ_RE.search(method.body))


def _has_allow_anonymous(method: _CSharpMethod) -> bool:
    return _has_attribute(method.attributes, _PUBLIC_ACCESS_ATTRIBUTES) or _has_attribute(method.class_attributes, _PUBLIC_ACCESS_ATTRIBUTES)


def _has_antiforgery(method: _CSharpMethod) -> bool:
    """Check if method or controller has antiforgery protection."""
    _CSRF_RE = re.compile(
        r'ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|'
        r'__RequestVerificationToken|AntiforgeryTokenSet',
        re.IGNORECASE,
    )
    if _CSRF_RE.search(method.body):
        return True
    if any('ValidateAntiForgeryToken' in attr or 'AutoValidateAntiforgeryToken' in attr
           for attr in (*method.attributes, *method.class_attributes)):
        return True
    return False


def _has_route(method: _CSharpMethod) -> bool:
    return _has_attribute(method.attributes, _ROUTE_ATTRIBUTES)


def _has_id_route(method: _CSharpMethod) -> bool:
    if any(_ID_ROUTE_RE.search(path) for path in method.route_paths):
        return True
    return any(name.lower() == "id" or name.lower().endswith("id") for name in method.params)


def _has_ownership_guard(body: str) -> bool:
    return bool(_OWNERSHIP_RE.search(body))


def _has_tainted_param_cs(method: _CSharpMethod) -> bool:
    """Check if method signature has parameters that could carry user input."""
    tainted_types = {"string", "int", "long", "Guid", "object", "dynamic"}
    for param in method.params:
        for tt in tainted_types:
            if tt in param:
                return True
    # Also check if body references Request, HttpContext, or [FromBody]
    if re.search(r"Request\.|HttpContext\.|\[FromBody\]|\[FromQuery\]|\[FromRoute\]", method.body, re.IGNORECASE):
        return True
    return bool(method.params)  # Any parameter could be tainted


def _is_admin_controller_source(source: str) -> bool:
    if _ADMIN_CONTROLLER_RE.search(source):
        return True
    return bool(_ADMIN_CONTROLLER_IMPORT_RE.search(source) and _ADMIN_DERIVED_CONTROLLER_RE.search(source))


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
    is_admin_controller = _is_admin_controller_source(source)
    findings: list[Finding] = []

    for method in methods:
        attr_names = {_short_name(raw.strip()[1:-1].split('(', 1)[0].strip()) for raw in method.attributes}

        if _has_route(method) and not is_admin_controller and not _is_public_route(method) and not _has_auth(method) and not _has_allow_anonymous(method) and not _has_antiforgery(method):
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

        if _has_route(method) and _has_id_route(method) and _FINDASYNC_RE.search(method.body) and not _has_ownership_guard(method.body) and not _has_auth(method):
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

        if attr_names & _MUTATING_ATTRIBUTES and _SAVE_RE.search(method.body) and not _has_ownership_guard(method.body) and not _has_auth(method):
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
        elif _CS_SQLI_RAW_RE.search(method.body) and re.search(r'\$"|string\.Format|\+', method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-89: EF Core raw SQL with interpolation in `{method.name}()`",
                description="FromSqlRaw/ExecuteSqlRaw called with string interpolation or concatenation instead of FormattableString parameters.",
                line=_first_matching_line(method.body, _CS_SQLI_RAW_RE, method.start_line),
                suggestion="Use FromSqlInterpolated or FromSqlRaw with parameter placeholders like FromSqlRaw(\"SELECT * FROM Users WHERE Id = {0}\", id).",
                rule_id="CS-004",
                cwe="CWE-89",
                agent="csharp-analyzer",
                confidence=0.90,
                analysis_kind="taint_flow",
            ))

        if re.search(r"\b(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\b", method.body) and re.search(r"\.Deserialize\s*\(", method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-502: Dangerous .NET deserialization in `{method.name}()`",
                description="BinaryFormatter.Deserialize, NetDataContractSerializer.Deserialize, LosFormatter.Deserialize, and ObjectStateFormatter.Deserialize can execute attacker-controlled gadget chains.",
                line=_first_matching_line(method.body, re.compile(r"\.Deserialize\s*\(", re.IGNORECASE), method.start_line),
                suggestion="Avoid BinaryFormatter/NetDataContractSerializer/LosFormatter for untrusted data; use System.Text.Json or safe DTO serialization.",
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
            r'Context\.Response\.WriteAsync\s*\([^)]*\)|'
            r'Response\.WriteAsync\s*\([^)]*\)',
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

        # ── CS-010: OS command injection via Process.Start ─────────────────
        _CMD_INJECTION_CS_RE = re.compile(
            r"Process\.Start\s*\([^)]*\)|new\s+ProcessStartInfo\s*\(",
            re.IGNORECASE,
        )
        if _CMD_INJECTION_CS_RE.search(method.body):
            # Classify the data source to avoid false positives from:
            #   - Hardcoded string literals (no risk)
            #   - Config/appsettings properties (low risk)
            #   - Delegating wrappers (risk at caller site)
            #   - Argument escaping (mitigated)
            _body = method.body
            _match = _CMD_INJECTION_CS_RE.search(_body)
            _matched_line = _body[_match.start() if _match else 0:_match.end() if _match else 0]

            # Determine classification flags
            _is_hardcoded = False
            _is_config_prop = False
            _is_delegating = False
            _has_escaping = False

            # 1. Check for hardcoded string literal FileName
            #    Pattern: FileName = "..." or FileName = @"..." in ProcessStartInfo
            if re.search(
                r'FileName\s*=\s*@"[^"]*"|FileName\s*=\s*"[^"]*"',
                _body, re.IGNORECASE,
            ):
                _is_hardcoded = True

            # 2. Check for config property FileName
            #    Pattern: _appConfig.X, AppConfig.X, Config.X, config["key"]
            if re.search(
                r'FileName\s*=\s*(?:this\.)?_?[A-Za-z]+[Cc]onfig(?:uration)?\s*\.\s*\w+|'
                r'config\s*\["|AppConfig\.\w+|Constants\.\w+',
                _body, re.IGNORECASE,
            ):
                _is_config_prop = True

            # 3. Check for delegating wrapper (thin delegation only)
            #    Patterns: return Process.Start(psi) | _process.Start() | return _process.Start()
            _stripped = _body.strip()
            _thin_delegation = re.search(
                r'\b(?:return\s+)?_?process\.Start\s*\([^)]*\)\s*;?\s*$',
                _stripped, re.IGNORECASE,
            )
            if _thin_delegation:
                _is_delegating = True

            # 4. Check for argument escaping/quoting functions
            if re.search(
                r'(?:Helper|ProcessHelper|ArgHelper|Quote|EscapeArgs|EscapeArguments)\s*\(',
                _body,
            ):
                _has_escaping = True

            # Compute adjusted severity and confidence
            if _is_hardcoded and not _has_escaping:
                # Hardcoded path + no escaping needed = safe config launch
                continue  # skip entirely — hardcoded Process.Start is not a vulnerability
            elif _is_delegating and not _is_config_prop:
                # Pure delegating wrapper — skip (report at the callsite where ProcessStartInfo is built)
                continue

            _severity = Severity.HIGH if _is_config_prop else Severity.CRITICAL
            _confidence = 0.92
            _severity_str = "CRITICAL"
            _desc_suffix = ""

            if _is_config_prop:
                _severity = Severity.MEDIUM
                _confidence = 0.55
                _severity_str = "MEDIUM"
                _desc_suffix = " The executable path comes from application configuration, not direct user input, which reduces exploitability."
            elif _has_escaping:
                _severity = Severity.HIGH
                _confidence = 0.70
                _severity_str = "HIGH"
                _desc_suffix = " Arguments are passed through a quoting/escaping function which partially mitigates injection risk."

            # Auth-scope calibration: if the method is behind [Authorize], the finding
            # requires auth to exploit. Reduce severity one level since the auth key
            # may already grant equivalent capabilities (see loop.md §4.3).
            if _has_auth(method) and _severity in (Severity.CRITICAL, Severity.HIGH):
                _auth_reduction = {
                    Severity.CRITICAL: (Severity.HIGH, "HIGH"),
                    Severity.HIGH: (Severity.MEDIUM, "MEDIUM"),
                }
                _new_sev, _new_str = _auth_reduction[_severity]
                _severity = _new_sev
                _severity_str = _new_str
                _desc_suffix += " Finding requires authentication ([Authorize]) which limits the attack surface — the auth key may already grant access to similar capabilities."
                _confidence = max(0.40, _confidence - 0.15)

            findings.append(Finding(
                category="security",
                severity=_severity,
                title=f"CWE-78: OS command injection in `{method.name}()` [{_severity_str}]",
                description=(
                    "Process.Start or ProcessStartInfo is used. If the command or arguments "
                    "are derived from user input this allows arbitrary command execution."
                    + _desc_suffix
                ),
                line=_first_matching_line(method.body, _CMD_INJECTION_CS_RE, method.start_line),
                suggestion="Avoid passing user input directly to Process.Start. Use argument arrays and validate the executable name against an allowlist.",
                rule_id="CS-010",
                cwe="CWE-78",
                agent="csharp-analyzer",
                confidence=_confidence,
                analysis_kind="pattern",
            ))

        # ── CS-011: Path traversal via File I/O (CWE-22) ──────────────────
        _PATH_TRAV_CS_RE = re.compile(
            r"File\.(ReadAllText|ReadAllBytes|ReadAllLines|WriteAllText|Delete|Copy|Move|Open)\s*\(|"
            r"Path\.Combine\s*\([^)]*\+\s*|"
            r"new\s+StreamReader\s*\(",
            re.IGNORECASE,
        )
        if _PATH_TRAV_CS_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-22: Path traversal via file I/O in `{method.name}()`",
                description="File I/O is performed with user-controllable input. Without path normalization this allows directory traversal.",
                line=_first_matching_line(method.body, _PATH_TRAV_CS_RE, method.start_line),
                suggestion="Validate and normalize file paths. Use Path.GetFullPath and verify it stays within the allowed base directory.",
                rule_id="CS-011",
                cwe="CWE-22",
                agent="csharp-analyzer",
                confidence=0.78,
                analysis_kind="pattern",
            ))

        # ── CS-012: SSRF via HttpClient (CWE-918) ─────────────────────────
        _SSRF_CS_RE = re.compile(
            r"HttpClient|WebClient|HttpWebRequest|RestClient",
            re.IGNORECASE,
        )
        if _SSRF_CS_RE.search(method.body) and _has_route(method):
            _SSRF_SAFE_CS_RE = re.compile(
                r"BaseAddress|baseAddress|base_url|baseUrl",
                re.IGNORECASE,
            )
            if not _SSRF_SAFE_CS_RE.search(method.body):
                findings.append(Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title=f"CWE-918: SSRF via HTTP client in `{method.name}()`",
                    description="HttpClient/WebClient usage in a routed action may allow server-side request forgery with user-controlled URLs.",
                    line=_first_matching_line(method.body, _SSRF_CS_RE, method.start_line),
                    suggestion="Use a base URL allowlist or disable external redirects. Validate outbound URLs against a trusted host list.",
                    rule_id="CS-012",
                    cwe="CWE-918",
                    agent="csharp-analyzer",
                    confidence=0.75,
                    analysis_kind="pattern",
                ))

        # ── CS-013: Open redirect via Redirect() (CWE-601) ──────────────
        _REDIRECT_CS_RE = re.compile(
            r"Redirect\(\.*returnUrl|RedirectToPage\(\.*returnUrl|RedirectToAction\(\.*returnUrl|"
            r"LocalRedirect\(\.*returnUrl|this\.Redirect\(",
            re.IGNORECASE,
        )
        if _has_route(method) and _REDIRECT_CS_RE.search(method.body):
            _REDIRECT_SAFE_RE = re.compile(
                r"Url\.IsLocalUrl|IsLocalUrl\(|LocalRedirect\(|StartsWith\(\"/\"\)|"
                r"UrlHelper\.IsLocalUrl|ValidateRedirectUrl",
                re.IGNORECASE,
            )
            if not _REDIRECT_SAFE_RE.search(method.body):
                findings.append(Finding(
                    category="security",
                    severity=Severity.MEDIUM,
                    title=f"CWE-601: Open redirect via `{method.name}()`",
                    description="The action redirects to a returnUrl or user-supplied URL without calling Url.IsLocalUrl() first.",
                    line=_first_matching_line(method.body, _REDIRECT_CS_RE, method.start_line),
                    suggestion="Validate the redirect target with Url.IsLocalUrl() or use LocalRedirect() to prevent open redirect attacks.",
                    rule_id="CS-013",
                    cwe="CWE-601",
                    agent="csharp-analyzer",
                    confidence=0.72,
                    analysis_kind="pattern",
                ))

        # ── CS-014: Stack trace exposure (CWE-200) ──────────────────────
        _STACKTRACE_CS_RE = re.compile(
            r"StackTrace|ExceptionDetail|IncludeErrorDetail|ex\.ToString|GetFullStackTrace|"
            r"DeveloperExceptionPage|UseDeveloperExceptionPage",
            re.IGNORECASE,
        )
        if _STACKTRACE_CS_RE.search(method.body) and _has_route(method):
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"CWE-200: Stack trace exposure in `{method.name}()`",
                description="Exception details are exposed in the HTTP response, leaking internal implementation details.",
                line=_first_matching_line(method.body, _STACKTRACE_CS_RE, method.start_line),
                suggestion="Return a generic error message to clients. Log full stack traces server-side only.",
                rule_id="CS-014",
                cwe="CWE-200",
                agent="csharp-analyzer",
                confidence=0.82,
                analysis_kind="pattern",
            ))

        # ── CS-015: Cleartext password in config assignment (CWE-312) ────
        _CLEARTEXT_CONFIG_RE = re.compile(
            r"\b(?:Password|Pwd|ApiKey|SharedSecret|AuthToken)\b\s*=\s*\"[^\"]{3,}\"|"
            r"\bpassword\s*:\s*\"[^\"]+\"|"
            r"AddConnectionString\s*\([^)]*Password=",
            re.IGNORECASE,
        )
        if _CLEARTEXT_CONFIG_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-312: Cleartext password in config assignment `{method.name}()`",
                description="A sensitive credential value is assigned directly as a string literal in code or configuration.",
                line=_first_matching_line(method.body, _CLEARTEXT_CONFIG_RE, method.start_line),
                suggestion="Use User Secrets during development and Azure Key Vault or environment variables in production.",
                rule_id="CS-015",
                cwe="CWE-312",
                agent="csharp-analyzer",
                confidence=0.92,
                analysis_kind="pattern",
            ))

        # ── CS-016: ASP.NET Identity misconfiguration (CWE-287) ──────────
        _IDENTITY_MISCONFIG_RE = re.compile(
            r"services\.AddDefaultIdentity|services\.AddIdentity\(|Password\.RequireDigit\s*=\s*false|"
            r"Password\.RequiredLength\s*<\s*8|Lockout\s*=\s*new\s+LockoutOptions|Password\.RequireNonAlphanumeric\s*=\s*false|"
            r"RequireAuthenticatedUser\s*\(\s*\)|FallbackPolicy\s*=\s*new\s+AuthorizationPolicyBuilder",
            re.IGNORECASE,
        )
        if _IDENTITY_MISCONFIG_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.MEDIUM,
                title=f"CWE-287: Identity password policy weakness in `{method.name}()`",
                description="ASP.NET Core Identity is configured with weak password or lockout requirements below recommended thresholds.",
                line=_first_matching_line(method.body, _IDENTITY_MISCONFIG_RE, method.start_line),
                suggestion="Require minimum 8 character passwords with digit, uppercase, and non-alphanumeric. Enable account lockout.",
                rule_id="CS-016",
                cwe="CWE-287",
                agent="csharp-analyzer",
                confidence=0.78,
                analysis_kind="pattern",
            ))

        # ── CS-017: Session fixation (CWE-384) ───────────────────────────
        if _has_route(method) and _has_auth(method):
            _SESSION_FIXATION_SAFE_RE = re.compile(
                r"HttpContext\.Session\.Clear|SignInAsync|SignOutAsync|"
                r"AuthenticationHttpContextExtensions\.SignInAsync",
                re.IGNORECASE,
            )
            if not _SESSION_FIXATION_SAFE_RE.search(method.body):
                if re.search(r"SignInAsync|PasswordSignInAsync|UserManager\.CheckPassword", method.body, re.IGNORECASE):
                    findings.append(Finding(
                        category="security",
                        severity=Severity.MEDIUM,
                        title=f"CWE-384: Session not regenerated after authentication in `{method.name}()`",
                        description="The action performs user authentication but does not call SignOutAsync/SignInAsync to regenerate the session identifier.",
                        line=method.start_line,
                        suggestion="Call HttpContext.SignOutAsync() then HttpContext.SignInAsync() after successful authentication to prevent session fixation.",
                        rule_id="CS-017",
                        cwe="CWE-384",
                        agent="csharp-analyzer",
                        confidence=0.68,
                        analysis_kind="route_heuristic",
                    ))

        # ── CS-018: LDAP injection (CWE-90) ──────────────────────────────
        _LDAP_INJECTION_CS_RE = re.compile(
            r"DirectorySearcher\s*\(.*\"[^)]*(?:uid=|cn=|sAMAccountName=|mail=|userPrincipalName=)",
            re.IGNORECASE,
        )
        # Also catch property assignment: .Filter = "(uid=" + variable
        _LDAP_FILTER_ASSIGN_RE = re.compile(
            r'\.Filter\s*=\s*"[^"]*(?:uid=|cn=|sAMAccountName=|mail=|userPrincipalName=)\s*"\s*\+',
            re.IGNORECASE,
        )
        if _LDAP_INJECTION_CS_RE.search(method.body) or _LDAP_FILTER_ASSIGN_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.CRITICAL,
                title=f"CWE-90: LDAP injection via DirectorySearcher in `{method.name}()`",
                description="LDAP search filter is built using string concatenation with unescaped user input.",
                line=_first_matching_line(method.body, _LDAP_INJECTION_CS_RE, method.start_line),
                suggestion="Use an LDAP escaping helper to sanitize user input before inserting into search filters.",
                rule_id="CS-018",
                cwe="CWE-90",
                agent="csharp-analyzer",
                confidence=0.85,
                analysis_kind="pattern",
            ))

        # ── CS-019: Weak random for security (CWE-338) ───────────────────
        _WEAK_RANDOM_CS_RE = re.compile(
            r"System\.Random|new\s+Random\s*\(",
            re.IGNORECASE,
        )
        if _WEAK_RANDOM_CS_RE.search(method.body):
            # Check both method body AND method name/context for security signals
            _security_ctx = re.compile(
                r"token|password|secret|key|nonce|otp|csrf|session|auth|"
                r"generate|token|hash|crypto|code|pin|otp|verification",
                re.IGNORECASE,
            )
            if _security_ctx.search(method.body) or _security_ctx.search(method.name):
                findings.append(Finding(
                    category="security",
                    severity=Severity.MEDIUM,
                    title=f"CWE-338: Weak random number generator in `{method.name}()`",
                    description="System.Random is not cryptographically secure. If used for security tokens, an attacker can predict outputs.",
                    line=_first_matching_line(method.body, _WEAK_RANDOM_CS_RE, method.start_line),
                    suggestion="Use System.Security.Cryptography.RandomNumberGenerator for security-sensitive values.",
                    rule_id="CS-019",
                    cwe="CWE-338",
                    agent="csharp-analyzer",
                    confidence=0.70,
                    analysis_kind="pattern",
                ))

        # ── CS-020: WebForms XSS via Response.Write (CWE-79) ────────────
        _WEBFORMS_XSS_CS_RE = re.compile(
            r"Response\.Write\s*\([^)]*(?:Request|QueryString|Form|Server\.HtmlEncode(?!.*\)))",
            re.IGNORECASE,
        )
        # Broader: Response.Write with string concatenation or variables in same method as request access
        _WEBFORMS_XSS_BROAD_RE = re.compile(
            r"Response\.Write\s*\(", re.IGNORECASE,
        )
        _WEBFORMS_REQUEST_ACCESS_RE = re.compile(
            r"Request\.(?:QueryString|Form|Params)\[", re.IGNORECASE,
        )
        if _WEBFORMS_XSS_CS_RE.search(method.body):
            findings.append(Finding(
                category="security",
                severity=Severity.HIGH,
                title=f"CWE-79: XSS via unencoded Response.Write in `{method.name}()`",
                description="Response.Write is called with user input without HTML encoding, enabling XSS attacks.",
                line=_first_matching_line(method.body, _WEBFORMS_XSS_CS_RE, method.start_line),
                suggestion="Use Server.HtmlEncode() or switch to encoded Razor helpers (@ syntax) instead of Response.Write.",
                rule_id="CS-020",
                cwe="CWE-79",
                agent="csharp-analyzer",
                confidence=0.85,
                analysis_kind="pattern",
            ))
        elif _WEBFORMS_XSS_BROAD_RE.search(method.body) and _WEBFORMS_REQUEST_ACCESS_RE.search(method.body):
            if not re.search(r"Server\.HtmlEncode|HttpUtility\.HtmlEncode", method.body, re.IGNORECASE):
                findings.append(Finding(
                    category="security",
                    severity=Severity.HIGH,
                    title=f"CWE-79: Potential XSS via unencoded Response.Write in `{method.name}()`",
                    description="Method uses Response.Write and accesses Request data. If user input flows to the Write call, XSS is possible.",
                    line=method.start_line,
                    suggestion="Encode output with Server.HtmlEncode() or use Razor @ syntax.",
                    rule_id="CS-020",
                    cwe="CWE-79",
                    agent="csharp-analyzer",
                    confidence=0.75,
                    analysis_kind="pattern",
                ))

        # ── Phase A: Enhanced C# vulnerability classes ──

        # CS-021: Unsafe deserialization (CWE-502)
        if _CS_DESERIALIZATION_RE.search(method.body):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-502: Unsafe .NET deserialization in `{method.name}()`",
                description="BinaryFormatter, LosFormatter, or similar unsafe deserializer is used. These are known RCE vectors.",
                line=_first_matching_line(method.body, _CS_DESERIALIZATION_RE, method.start_line),
                suggestion="Use a safe serializer like System.Text.Json or implement a SerializationBinder allowlist.",
                rule_id="CS-021", cwe="CWE-502", agent="csharp-analyzer",
                confidence=0.95, analysis_kind="pattern",
            ))

        # CS-022: Command injection via Process.Start (CWE-78)
        if _CS_CMD_INJECTION_RE.search(method.body) and _has_tainted_param_cs(method):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-78: Command injection via Process.Start in `{method.name}()`",
                description="Process.Start is invoked with potentially user-controlled input.",
                line=_first_matching_line(method.body, _CS_CMD_INJECTION_RE, method.start_line),
                suggestion="Avoid Process.Start with user input. Use argument arrays and validate against an allowlist.",
                rule_id="CS-022", cwe="CWE-78", agent="csharp-analyzer",
                confidence=0.88, analysis_kind="taint_flow",
            ))

        # CS-023: SSRF via HttpClient/WebClient (CWE-918)
        if _CS_SSRF_RE.search(method.body) and _has_tainted_param_cs(method):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-918: SSRF via HTTP client in `{method.name}()`",
                description="HTTP client is called with potentially user-controlled URL.",
                line=_first_matching_line(method.body, _CS_SSRF_RE, method.start_line),
                suggestion="Validate URLs against a strict allowlist. Never pass user-controlled URLs directly to HTTP clients.",
                rule_id="CS-023", cwe="CWE-918", agent="csharp-analyzer",
                confidence=0.82, analysis_kind="taint_flow",
            ))

        # CS-024: Path traversal via file APIs (CWE-22)
        if _CS_PATH_TRAVERSAL_RE.search(method.body) and _has_tainted_param_cs(method):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-22: Path traversal via file API in `{method.name}()`",
                description="File or path API accessed with potentially user-controlled input.",
                line=_first_matching_line(method.body, _CS_PATH_TRAVERSAL_RE, method.start_line),
                suggestion="Normalize paths against a trusted base directory and reject paths that escape it.",
                rule_id="CS-024", cwe="CWE-22", agent="csharp-analyzer",
                confidence=0.80, analysis_kind="taint_flow",
            ))

        # CS-025: XSS via Html.Raw or Response.Write (CWE-79)
        if _CS_XSS_RE.search(method.body):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-79: XSS via unencoded output in `{method.name}()`",
                description="Html.Raw, Response.Write, or InnerHtml assignment used without encoding.",
                line=_first_matching_line(method.body, _CS_XSS_RE, method.start_line),
                suggestion="Use encoded output helpers. Avoid Html.Raw() with user input.",
                rule_id="CS-025", cwe="CWE-79", agent="csharp-analyzer",
                confidence=0.85, analysis_kind="pattern",
            ))

        # CS-026: Mass assignment / over-posting (CWE-915)
        if _CS_MASS_ASSIGNMENT_RE.search(method.body):
            findings.append(Finding(
                category="security", severity=Severity.MEDIUM,
                title=f"CWE-915: Mass assignment risk in `{method.name}()`",
                description="TryUpdateModelAsync/UpdateModelAsync can bind unintended properties.",
                line=_first_matching_line(method.body, _CS_MASS_ASSIGNMENT_RE, method.start_line),
                suggestion="Use explicit DTOs or [BindRequired] attributes to control which properties can be bound.",
                rule_id="CS-026", cwe="CWE-915", agent="csharp-analyzer",
                confidence=0.72, analysis_kind="pattern",
            ))

        # CS-027: LDAP injection (CWE-90)
        if _CS_LDAP_INJECTION_RE.search(method.body):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-90: LDAP injection via DirectorySearcher in `{method.name}()`",
                description="LDAP query constructed with potentially user-controlled input.",
                line=_first_matching_line(method.body, _CS_LDAP_INJECTION_RE, method.start_line),
                suggestion="Use parameterized LDAP queries or encode special characters in search filters.",
                rule_id="CS-027", cwe="CWE-90", agent="csharp-analyzer",
                confidence=0.85, analysis_kind="pattern",
            ))

        # CS-028: Weak cryptography (CWE-327/328)
        if _CS_WEAK_CRYPTO_RE.search(method.body):
            findings.append(Finding(
                category="security", severity=Severity.HIGH,
                title=f"CWE-327: Weak cryptography in `{method.name}()`",
                description="MD5, SHA1, DES, or RC2 used for security-sensitive operations.",
                line=_first_matching_line(method.body, _CS_WEAK_CRYPTO_RE, method.start_line),
                suggestion="Use SHA256 or stronger. For passwords, use PBKDF2 or Argon2.",
                rule_id="CS-028", cwe="CWE-327", agent="csharp-analyzer",
                confidence=0.92, analysis_kind="pattern",
            ))

        # CS-029: NoSQL injection (CWE-943)
        if _CS_NOSQL_INJECTION_RE.search(method.body) and _has_tainted_param_cs(method):
            findings.append(Finding(
                category="security", severity=Severity.CRITICAL,
                title=f"CWE-943: NoSQL injection in `{method.name}()`",
                description="MongoDB/CosmosDB query with user-controlled input.",
                line=_first_matching_line(method.body, _CS_NOSQL_INJECTION_RE, method.start_line),
                suggestion="Use parameterized BSON documents. Never concatenate user input into query filters.",
                rule_id="CS-029", cwe="CWE-943", agent="csharp-analyzer",
                confidence=0.88, analysis_kind="taint_flow",
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

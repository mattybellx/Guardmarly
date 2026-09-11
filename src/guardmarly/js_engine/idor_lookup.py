"""
js_engine.idor_lookup
─────────────────────
CWE-639 detection for *request-controlled resource lookups*.

The route-parameter rules elsewhere in the engine only fire when a route path
parameter is passed directly into an ORM call in the same function. Real
applications routinely break that assumption:

* the identifier arrives as ``req.query.id`` / ``req.body.id``;
* the lookup is an object literal — ``db.Product.find({ where: { id: req.query.id } })``;
* the query is issued through a model object whose name says nothing about
  being a DAO (``db.Product``, ``models.Invoice``).

This module detects the underlying invariant instead of the syntax:

    an identifier taken from the request is used as the *key* of a resource
    lookup, and nothing in scope constrains the lookup to the caller.

Deliberate false-positive guards (each one is covered by a test):

* the file must look like request-handling code (route registration or a
  ``(req, res)`` handler signature);
* the lookup argument must contain an identifier-shaped key (``id``, ``_id``,
  ``uuid``, ``pk``, ``*Id``, ``*_id``, ``slug``) — a search by ``req.query.name``
  is not an object reference;
* any ownership/tenancy token, ownership assertion call, or role check within
  the call or a small window around it suppresses the finding;
* findings are capped per file, and downgraded when no route is registered in
  the file (the handler is only *probably* a request handler).
"""
from __future__ import annotations

import re

from guardmarly._types import AnalysisResult, Finding, Severity, TraceFrame  # noqa: F401  (AnalysisResult re-exported for callers)

__all__ = ["detect_idor_lookups", "IDOR_LOOKUP_RULE_ID"]

IDOR_LOOKUP_RULE_ID = "JS-064"

# Identifier taken from the request: req.query.id, req.body['id'], req.params.id
_REQUEST_ID_RE = re.compile(
    r"""req\s*\.\s*(?P<bag>params|query|body)\s*
        (?:\.\s*(?P<attr>\w+)
          |\[\s*['"](?P<key>[^'"]+)['"]\s*\])""",
    re.VERBOSE | re.IGNORECASE,
)

# Lookup calls that fetch a resource. `find` is included because Sequelize and
# Mongoose use it with an object literal; the identifier-key guard below keeps
# broad names from firing on ordinary queries.
_LOOKUP_METHODS = (
    "findByPk", "findById", "findByID", "findOne", "findUnique", "findFirst",
    "findAll", "find", "findAndCountAll", "get", "first", "where", "query",
    "exec", "execQuery", "raw", "count",
)
_LOOKUP_RE = re.compile(
    r"(?P<callee>[A-Za-z_$][\w$.]*)\s*\.\s*(?P<method>" + "|".join(_LOOKUP_METHODS) + r")\s*\(",
    re.IGNORECASE,
)

# Identifier-shaped keys. A lookup keyed by one of these refers to a specific
# object; anything else (name, q, search, page…) is a filter, not a reference.
_IDENTIFIER_KEY_RE = re.compile(
    r"""(?:^|[\s,{(\[])(?:['"](?P<quoted>[^'"]+)['"]|(?P<bare>\w+))\s*:""",
    re.VERBOSE,
)
_IDENTIFIER_KEY_NAMES = {"id", "_id", "uuid", "pk", "key", "slug", "guid", "oid"}

# Anything that scopes the lookup to the caller.
_OWNERSHIP_TOKEN_RE = re.compile(
    r"""\b(?:owner|ownerId|owner_id|userId|user_id|createdBy|created_by|
             tenant|tenantId|tenant_id|accountId|account_id|orgId|org_id|
             req\.user|request\.user|currentUser|current_user|session\.
        )""",
    re.VERBOSE | re.IGNORECASE,
)
# Explicit authorisation helpers. The trailing paren is optional: middleware is
# usually passed as a reference (`router.post('/x', requireAdmin, handler)`),
# not invoked inline.
_GUARD_CALL_RE = re.compile(
    r"""\b(?:canAccess|assertOwner|checkOwnership|isOwner|owns|belongsToUser|
             authorize|authorise|hasPermission|hasRole|requireRole|requireAdmin|
             isAdmin|checkAccess|verifyOwnership|assertCanAccess|ensureAdmin|
             ensureRole|checkPermission)\b""",
    re.VERBOSE | re.IGNORECASE,
)
# The file handles requests.
_ROUTE_RE = re.compile(
    r"""(?:^|[^\w.])(?:app|router|server|route)\s*\.\s*
        (?:get|post|put|patch|delete|del|all|use|options)\s*\(""",
    re.VERBOSE | re.IGNORECASE,
)
_HANDLER_SIGNATURE_RE = re.compile(
    r"""(?:function\s*\([^)]*\breq\b[^)]*\bres\b
         |\(\s*req\s*,\s*res\s*\)
         |\breq\s*,\s*res\b)""",
    re.VERBOSE | re.IGNORECASE,
)

_MAX_FINDINGS_PER_FILE = 6
_CONTEXT_WINDOW = 12          # lines checked either side of the lookup
_MAX_ARGUMENT_SCAN = 600      # characters of call arguments to inspect

# Receivers that are web-framework routers or HTTP clients — `app.get('/x')`
# registers a route and `axios.get(url)` makes a request; neither is a resource
# lookup, and the first argument of both is a path/URL rather than a key.
_NOT_A_LOOKUP_RECEIVER_RE = re.compile(
    r"""^(?:app|router|server|route|fastify|express|
           axios|http|https|got|needle|superagent|request|fetch|ky|undici)$""",
    re.VERBOSE | re.IGNORECASE,
)
_ROUTE_VERB_METHODS = {"get", "post", "put", "patch", "delete", "del", "all", "use", "options"}


def _line_of(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def _call_arguments(code: str, open_paren: int) -> str:
    """Return the argument text of a call whose '(' is at *open_paren*."""
    depth = 0
    for i in range(open_paren, min(len(code), open_paren + _MAX_ARGUMENT_SCAN)):
        char = code[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return code[open_paren + 1:i]
    return code[open_paren + 1:open_paren + _MAX_ARGUMENT_SCAN]


def _has_identifier_key(argument_text: str) -> bool:
    for match in _IDENTIFIER_KEY_RE.finditer(argument_text):
        name = match.group("quoted") or match.group("bare") or ""
        if _is_identifier_name(name):
            return True
    return False


def _is_identifier_name(name: str) -> bool:
    """Is *name* shaped like a reference to one record, not a search filter?

    ``id``/``_id``/``uuid``/``pk`` are direct matches; ``invoiceId`` (camelCase)
    and ``invoice_id`` (snake_case) are accepted while look-alikes such as
    ``valid`` or ``grid`` are not.
    """
    if not name:
        return False
    if name.lower() in _IDENTIFIER_KEY_NAMES:
        return True
    if len(name) > 2 and (name.endswith("Id") or name.lower().endswith("_id")):
        return True
    return False


def _request_token_name(match: re.Match[str]) -> str:
    """The key name of a ``req.<bag>.<key>`` match (``attr`` or ``['key']``)."""
    return match.group("attr") or match.group("key") or ""


def _is_scoped(argument_text: str, window: str) -> bool:
    if _OWNERSHIP_TOKEN_RE.search(argument_text):
        return True
    if _OWNERSHIP_TOKEN_RE.search(window):
        return True
    return bool(_GUARD_CALL_RE.search(argument_text) or _GUARD_CALL_RE.search(window))


def detect_idor_lookups(code: str, filename: str = "") -> list[Finding]:
    """Return CWE-639 findings for request-controlled resource lookups."""
    if not code or not _HANDLER_SIGNATURE_RE.search(code):
        return []

    has_route = bool(_ROUTE_RE.search(code))
    lines = code.splitlines()
    findings: list[Finding] = []
    seen_lines: set[int] = set()

    for lookup in _LOOKUP_RE.finditer(code):
        if len(findings) >= _MAX_FINDINGS_PER_FILE:
            break

        arguments = _call_arguments(code, lookup.end() - 1)
        if not arguments:
            continue

        callee = lookup.group("callee")
        method = lookup.group("method")

        # `app.get('/invoices/:id', …)` is a route registration, not a lookup.
        receiver_leaf = callee.rsplit(".", 1)[-1] if "." in callee else ""
        if _NOT_A_LOOKUP_RECEIVER_RE.match(receiver_leaf):
            continue
        if method.lower() in _ROUTE_VERB_METHODS and arguments.lstrip()[:1] in ("'", '"'):
            continue

        request_ids = list(_REQUEST_ID_RE.finditer(arguments))
        if not request_ids:
            continue

        source = request_ids[0]
        request_token = source.group(0)
        # The token must *name* a record (`req.params.invoiceId`) or the call
        # must key an object literal by one (`{ where: { id: ... } }`).
        # Without the first test the canonical `Model.findById(req.params.id)`
        # shape — the whole point of this detector — was rejected.
        if not (
            _is_identifier_name(_request_token_name(source))
            or _has_identifier_key(arguments)
        ):
            continue

        line = _line_of(code, lookup.start())
        window = "\n".join(
            lines[max(0, line - 1 - _CONTEXT_WINDOW):line + _CONTEXT_WINDOW]
        )
        if _is_scoped(arguments, window):
            continue
        if line in seen_lines:
            continue

        seen_lines.add(line)
        findings.append(Finding(
            category="security",
            severity=Severity.HIGH if has_route else Severity.MEDIUM,
            title=f"CWE-639: IDOR — `{callee}.{method}()` at line {line} looks up a resource by a request-controlled id",
            description=(
                f"`{callee}.{method}()` at L{line} selects a resource using "
                f"`{request_token}`, which the caller controls, and no ownership or "
                "tenancy constraint is visible in scope. An authenticated user can "
                "read or modify other users' records by changing the identifier."
            ),
            line=line,
            suggestion=(
                "Scope the lookup to the caller — e.g. "
                "`findOne({ where: { id: req.params.id, owner: req.user.id } })` — "
                "or load the resource and assert ownership before acting on it."
            ),
            rule_id=IDOR_LOOKUP_RULE_ID,
            cwe="CWE-639",
            agent="js-idor",
            confidence=0.82 if has_route else 0.62,
            analysis_kind="route-heuristic" if has_route else "pattern",
            trace=(
                TraceFrame(kind="source", label=f"request id `{request_token}`", line=line),
                TraceFrame(
                    kind="sink",
                    label=f"resource lookup `{callee}.{method}(...)` without ownership scope",
                    line=line,
                ),
            ),
        ))

    return findings

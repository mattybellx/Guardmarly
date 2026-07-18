"""
guardmarly.js_engine.constants
──────────────────────────────────
Canonical regex patterns, callee sets, and shared constants for the JS engine.

ALL modules should import from here instead of defining their own copies.
When adding a new sink callee, sanitizer, or pattern — add it HERE once.
"""
from __future__ import annotations

import re

# ──────────────────────────────────────────────────────────────────────────────
# Callee sets — used by taint checks, route checks, project resolution
# ──────────────────────────────────────────────────────────────────────────────

DOCUMENT_WRITE_CALLEES: frozenset[str] = frozenset({"document.write", "document.writeln"})
TIMER_CALLEES: frozenset[str] = frozenset({"setTimeout", "setInterval"})
COMMAND_EXEC_CALLEES: frozenset[str] = frozenset({
    # NOTE: bare "exec" / "execSync" removed — they match RegExp.prototype.exec()
    # which is a string method, NOT child_process.exec(). Only qualified imports
    # (child_process.exec etc.) are actual command injection sinks.
    "child_process.exec", "child_process.execSync",
    "child_process.spawn", "child_process.spawnSync",
    "child_process.execFile", "child_process.execFileSync",
    "spawn", "spawnSync", "execFile", "execFileSync",
})
SHELL_TRUE_CALLEES: frozenset[str] = frozenset({
    "spawn", "execFile", "child_process.spawn", "child_process.execFile",
})
SQL_CALLEES: frozenset[str] = frozenset({
    "sequelize.query", "knex.raw",
    "db.query", "db.execute", "pool.query", "pool.execute",
    "connection.query", "connection.execute",
})
SSRF_CALLEES: frozenset[str] = frozenset({
    "fetch",
    "axios.get", "axios.post", "axios.put", "axios.delete", "axios.request",
    "request",
    "got", "got.get", "got.post", "got.stream",
    "needle", "needle.get", "needle.post", "needle.put", "needle.delete", "needle.request",
    "superagent.get", "superagent.post", "superagent.put", "superagent.delete", "superagent.request",
    "node-fetch",
    "http.get", "https.get",
})

PATH_CALLEE_PARTS: frozenset[str] = frozenset({
    "readFile", "readFileSync",
    "writeFile", "writeFileSync",
    "open", "openSync",
    "unlink", "unlinkSync",
    "stat", "statSync",
    "access", "accessSync",
    "createReadStream", "createWriteStream",
    "resolve", "join",
    "sendFile", "download", "sendfile",
})

LOOKUP_CALLEE_PARTS: frozenset[str] = frozenset({
    "findByPk", "findById", "findOne", "findUnique", "findFirst",
})

MUTATION_CALLEE_PARTS: frozenset[str] = frozenset({
    "destroy", "update", "deleteOne", "remove",
    "findByIdAndUpdate", "findByIdAndDelete",
    "findOneAndUpdate", "findOneAndDelete",
})

# ──────────────────────────────────────────────────────────────────────────────
# Compiled regex patterns — shared across routes / taint_checks / project
# ──────────────────────────────────────────────────────────────────────────────

AUTH_MIDDLEWARE_RE: re.Pattern[str] = re.compile(
    r'requireAuth|authMiddleware|isAuthenticated|isLoggedIn|passport\.authenticate|'
    r'verifyToken|checkAuth|ensureAuth|jwtAuth|requireLogin|'
    r'request\.jwtVerify|jwtVerify|fastify\.authenticate|koaJwt|koa-jwt|ctx\.isAuthenticated|'
    r'requireAdmin|adminOnly|adminRequired|ensureAdmin|staffOnly|staffRequired|'
    r'requireRole|hasRole|checkRole|requirePermission|checkPermission|hasPermission|'
    r'AuthGuard|JwtAuthGuard|SessionGuard|UseGuards|withAuth|requireSession|requireUser|getServerSession',
    re.IGNORECASE,
)

PRIVILEGE_MIDDLEWARE_RE: re.Pattern[str] = re.compile(
    r'requireAdmin|adminOnly|adminRequired|ensureAdmin|staffOnly|staffRequired|'
    r'superuserOnly|rootOnly|requireRole|hasRole|checkRole|requirePermission|'
    r'checkPermission|hasPermission|authorizeRole|permissionMiddleware|'
    r'RolesGuard|PermissionsGuard|ScopesGuard|RoleGuard|PermissionGuard|Roles\s*\(|Permissions\s*\(',
    re.IGNORECASE,
)

OWNERSHIP_KEY_RE: re.Pattern[str] = re.compile(
    r'ownerId|userId|accountId|tenantId|authorId|createdBy|organizationId|orgId',
    re.IGNORECASE,
)

PRINCIPAL_REF_RE: re.Pattern[str] = re.compile(
    r'(?:req|request)\.(?:user|auth)|res\.locals\.user|reply\.locals\.user|ctx\.state\.user|'
    r'context\.state\.user|event\.locals\.user|locals\.user|currentUser|session\.user|'
    r'(?:req|request)\.session\.(?:user|auth)|(?:req|request)\.session\[\s*["\']user(?:Id)?["\']\s*\]|'
    r'c\.get\(\s*["\']user["\']\s*\)',
    re.IGNORECASE,
)

VERIFICATION_CALL_RE: re.Pattern[str] = re.compile(
    r'jwt\.verify|verifyToken|checkAuth|validateToken|decodeToken|passport\.authenticate|'
    r'loadUser|findByToken|authenticate|authorize|requireRole|checkPermission|hasPermission|hasRole|'
    r'request\.jwtVerify|ctx\.isAuthenticated|ctx\.state\.user|'
    r'getServerSession|verifyIdToken|validateSession|lucia\.validateSession|supabase\.auth\.getUser|'
    r'auth\s*\(|requireSession|requireUser',
    re.IGNORECASE,
)

PRIVILEGE_KEY_RE: re.Pattern[str] = re.compile(
    r'admin|staff|superuser|root|role|permission|scope|acl|rbac',
    re.IGNORECASE,
)

LOOKUP_SINK_RE: re.Pattern[str] = re.compile(
    r'findByPk\s*\(|findById\s*\(|findOne\s*\(|findUnique\s*\(|findFirst\s*\(|'
    r'select\s+.+\bwhere\b',
    re.IGNORECASE,
)

DIRECT_MUTATION_SINK_RE: re.Pattern[str] = re.compile(
    r'destroy\s*\(|update\s*\(|deleteOne\s*\(|remove\s*\(|'
    r'findByIdAndUpdate\s*\(|findByIdAndDelete\s*\(|findOneAndUpdate\s*\(|'
    r'findOneAndDelete\s*\(|\bUPDATE\s+\w+\s+SET\b|\bDELETE\s+FROM\b',
    re.IGNORECASE,
)

INSTANCE_MUTATION_RE: re.Pattern[str] = re.compile(
    r'\b([A-Za-z_$][\w$]*)\s*\.\s*(destroy|save|remove|update)\s*\(',
    re.IGNORECASE,
)

CREDENTIAL_NAME_RE: re.Pattern[str] = re.compile(
    r'authoriz|auth|token|jwt|session|cookie|bearer|api[_-]?key|apikey|credential',
    re.IGNORECASE,
)

CREDENTIAL_SOURCE_RE: re.Pattern[str] = re.compile(
    r'\b(?:req|request)\.(?:headers|cookies|query|body)\b|request\.headers\.get\s*\([^)]*\)|ctx\.request\.(?:headers|body)',
    re.IGNORECASE,
)

REQUEST_OBJECT_ARG_RE: re.Pattern[str] = re.compile(
    r"^\s*(?:req|request|ctx|context|event|c)(?:\b|\s*$)",
    re.IGNORECASE,
)

# ──────────────────────────────────────────────────────────────────────────────
# Helper — callee matching with short-name fallback
# ──────────────────────────────────────────────────────────────────────────────


def callee_matches(callee: str, targets: frozenset[str]) -> bool:
    """Return True when *callee* matches a target, with dot-name fallback."""
    if callee in targets:
        return True
    short = callee.split(".")[-1]
    return short in targets

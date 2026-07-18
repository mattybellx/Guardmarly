"""
Express.js Framework Profile — Node.js/Express web framework.

Provides domain knowledge for JavaScript/TypeScript security scanning.
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ExpressProfile:
    """Semantic profile for Express.js applications."""

    GUARDS: dict[str, str] = field(default_factory=lambda: {
        "passport.authenticate": "auth-middleware",
        "req.isAuthenticated()": "auth-check",
        "req.user": "auth-user",
        "require('helmet')": "security-headers",
        "helmet()": "helmet-enabled",
        "cors(": "cors-config",
        "rateLimit(": "rate-limit",
        "express-jwt": "jwt-auth",
        "csrfProtection": "csrf-check",
        ".isAuthenticated": "auth-verify",
    })

    SINKS: dict[str, str] = field(default_factory=lambda: {
        "res.send(": "response-send",
        "res.json(": "response-json",
        "res.render(": "template-render",
        "res.redirect(": "open-redirect",
        "eval(": "code-eval",
        "child_process.exec(": "cmd-exec",
        "child_process.spawn(": "cmd-spawn",
        "require('request')": "ssrf-request",
        "axios.get(": "ssrf-axios",
        "axios.post(": "ssrf-axios",
        "fetch(": "ssrf-fetch",
        "fs.readFile(": "file-read",
        "fs.writeFile(": "file-write",
        "JSON.parse(": "json-deserialize",
        "new Function(": "dynamic-function",
        "vm.runInNewContext(": "sandbox-escape",
        "require('mysql')": "sql-mysql",
        "require('pg')": "sql-postgres",
    })

    SOURCES: dict[str, str] = field(default_factory=lambda: {
        "req.query": "query-params",
        "req.params": "route-params",
        "req.body": "request-body",
        "req.headers": "request-headers",
        "req.cookies": "request-cookies",
        "req.ip": "client-ip",
        "req.url": "request-url",
        "req.originalUrl": "original-url",
        "req.file": "file-upload",
        "req.files": "files-upload",
    })


EXPRESS = ExpressProfile()

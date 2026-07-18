"""
Gin Framework Profile — Go Gin web framework.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class GinProfile:
    GUARDS: dict[str, str] = field(default_factory=lambda: {
        "gin.BasicAuth(": "auth-middleware",
        "middleware.BasicAuth(": "auth-middleware",
        "AuthMiddleware": "auth-middleware",
        "c.Request.Header.Get(\"Authorization\")": "auth-header",
        "JWT": "jwt-auth",
        "CSRF": "csrf-check",
        "c.MustGet(\"user\")": "auth-user",
        "c.Get(\"user\")": "auth-user",
        "CORS": "cors-config",
        "RateLimiter": "rate-limit",
    })
    SINKS: dict[str, str] = field(default_factory=lambda: {
        "c.String(": "response-write",
        "c.JSON(": "response-json",
        "c.HTML(": "response-html",
        "c.Redirect(": "open-redirect",
        "c.File(": "file-serve",
        "c.FileAttachment(": "file-download",
        "sql.Open(": "sql-open",
        "db.Query(": "sql-query",
        "db.Exec(": "sql-exec",
        "db.Raw(": "sql-raw",
        "http.Get(": "ssrf",
        "http.Post(": "ssrf",
        "os.Open(": "file-open",
        "os.ReadFile(": "file-read",
        "os.WriteFile(": "file-write",
        "exec.Command(": "cmd-exec",
        "template.New(": "template-engine",
        "html/template": "template-safe",
        "text/template": "template-unsafe",
        "json.Unmarshal(": "json-deserialize",
        "xml.Unmarshal(": "xml-deserialize",
    })
    SOURCES: dict[str, str] = field(default_factory=lambda: {
        "c.Query(": "query-param",
        "c.Param(": "route-param",
        "c.PostForm(": "form-data",
        "c.Request.Body": "request-body",
        "c.Request.Header": "request-headers",
        "c.Request.URL": "request-url",
        "c.FormFile(": "file-upload",
        "c.Cookie(": "cookie-access",
    })

GIN = GinProfile()

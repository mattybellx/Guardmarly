"""
ASP.NET Core Framework Profile — ASP.NET MVC / Web API / Entity Framework.

Provides domain knowledge for:
  - Recognizing protected vs unprotected controller actions
  - Identifying framework-specific sinks (EF Core, HttpClient, file ops)
  - Detecting taint sources unique to ASP.NET (model binding, form data)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AspNetProfile:
    """Semantic profile for ASP.NET Core / MVC / Web API applications."""

    # ── Guards: patterns indicating a route/action is protected ──
    GUARDS: dict[str, str] = field(default_factory=lambda: {
        # Authorization attributes
        "[Authorize]": "auth-check",
        "[Authorize(Roles": "auth-role-check",
        "[Authorize(Policy": "auth-policy-check",
        "[AllowAnonymous]": "public-route",
        # Anti-forgery / CSRF
        "[ValidateAntiForgeryToken]": "csrf-check",
        "[AutoValidateAntiforgeryToken]": "csrf-auto",
        "[IgnoreAntiforgeryToken]": "csrf-skip",
        # Programmatic checks
        "User.Identity.IsAuthenticated": "auth-verify",
        "User.IsInRole(": "auth-role-check",
        "HttpContext.User": "auth-context",
        "SignInManager": "auth-manager",
        "IAuthorizationService": "auth-service",
        ".RequireAuthorization()": "auth-middleware",
        # Ownership/tenant scoping
        ".Where(u => u.UserId ==": "owner-scoped-query",
        "User.FindFirstValue(ClaimTypes.NameIdentifier)": "owner-id",
        "_userManager.GetUserId(User)": "owner-id-lookup",
        "[ProtectPersonalData]": "data-protection",
    })

    # ── Sinks: framework-specific security-sensitive sinks ──
    SINKS: dict[str, str] = field(default_factory=lambda: {
        # Entity Framework Core (SQL)
        ".FromSqlRaw(": "sql-raw",
        ".FromSqlInterpolated(": "sql-interpolated",
        ".ExecuteSqlRaw(": "sql-execute-raw",
        ".ExecuteSqlInterpolated(": "sql-execute-interp",
        "SqlCommand": "ado-sql",
        "SqlDataAdapter": "ado-adapter",
        "DbContext.Database.ExecuteSql": "ef-execute",
        # SSRF (HttpClient)
        "HttpClient.GetAsync": "ssrf",
        "HttpClient.GetStringAsync": "ssrf",
        "HttpClient.PostAsync": "ssrf",
        "HttpClient.SendAsync": "ssrf",
        "HttpClientFactory.CreateClient": "http-client-factory",
        "WebRequest.Create": "ssrf-legacy",
        # File operations
        "System.IO.File.ReadAllText": "file-read",
        "System.IO.File.ReadAllBytes": "file-read",
        "System.IO.File.WriteAllText": "file-write",
        "System.IO.File.Copy": "file-copy",
        "System.IO.File.Delete": "file-delete",
        "System.IO.File.OpenRead": "file-open",
        "Path.Combine(": "path-join",
        "Directory.GetFiles": "dir-list",
        "Directory.Delete": "dir-delete",
        # Template / Razor injection
        "RazorEngine": "razor-engine",
        "RazorLight": "razor-light",
        "Engine.Razor.RunCompile": "razor-compile",
        # Deserialization
        "JsonConvert.DeserializeObject": "json-deserialize",
        "JsonSerializer.Deserialize": "json-deserialize",
        "BinaryFormatter": "binary-deserialize",
        "JavaScriptSerializer": "js-deserialize",
        "XmlSerializer": "xml-deserialize",
        "DataContractSerializer": "dcs-deserialize",
        # XXE
        "XmlDocument.Load": "xxe-load",
        "XmlReader.Create": "xxe-reader",
        "XDocument.Load": "xxe-linq",
        # LDAP
        "DirectoryEntry": "ldap-entry",
        "DirectorySearcher": "ldap-search",
        "LdapConnection": "ldap-connection",
    })

    # ── Sources: patterns that introduce user-controlled data ──
    SOURCES: dict[str, str] = field(default_factory=lambda: {
        # Model binding
        "[FromBody]": "http-body",
        "[FromForm]": "http-form",
        "[FromQuery]": "http-query",
        "[FromRoute]": "http-route",
        "[FromHeader]": "http-header",
        "[FromServices]": "di-service",
        # Request properties
        "HttpContext.Request.Query": "query-string",
        "HttpContext.Request.Form": "form-data",
        "HttpContext.Request.Headers": "http-headers",
        "HttpContext.Request.Cookies": "http-cookies",
        "HttpContext.Request.RouteValues": "route-values",
        "HttpContext.Request.Body": "request-body",
        "Request.QueryString": "query-string-legacy",
        "Request.Form": "form-legacy",
        "Request.Headers": "headers-legacy",
        # File upload
        "IFormFile": "file-upload",
        "HttpPostedFile": "file-upload-legacy",
        # Cookies
        "Request.Cookies[": "cookie-access",
        "Response.Cookies.Append": "cookie-write",
    })

    # ── Route attributes (which attributes map HTTP routes) ──
    ROUTE_ATTRIBUTES: frozenset[str] = frozenset({
        "[HttpGet", "[HttpPost", "[HttpPut", "[HttpDelete",
        "[HttpPatch", "[Route(", "[ApiController]",
    })

    # ── Sensitive singleton services ──
    SENSITIVE_SERVICES: frozenset[str] = frozenset({
        "DbContext", "UserManager", "SignInManager",
        "RoleManager", "IAuthorizationService",
        "HttpClient", "IHttpClientFactory",
    })


# Singleton instance
ASPNET = AspNetProfile()

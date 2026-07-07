"""
Spring Framework Profile — Spring Boot / Spring MVC / Spring Security.

Provides domain knowledge for:
  - Recognizing protected vs unprotected controller methods
  - Identifying framework-specific sinks (SQL, SSRF, file operations)
  - Detecting taint sources unique to Spring (annotations, form binding)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SpringProfile:
    """Semantic profile for Spring Boot / MVC / Security applications."""

    # ── Guards: patterns indicating a route is protected ──
    GUARDS: dict[str, str] = field(default_factory=lambda: {
        # Spring Security annotations
        "@PreAuthorize": "auth-check",
        "@PostAuthorize": "auth-check",
        "@Secured": "auth-check",
        "@RolesAllowed": "auth-check",
        "@RoleAllowed": "auth-check",
        "@DenyAll": "auth-check",
        "@PermitAll": "auth-check",
        "@RunAs": "auth-check",
        # Programmatic security checks
        "SecurityContextHolder.getContext()": "auth-context",
        "SecurityContextHolder.getContext().getAuthentication()": "auth-context-access",
        "Authentication.getName()": "auth-principal",
        ".getPrincipal()": "auth-principal",
        ".isAuthenticated()": "auth-verify",
        ".hasRole(": "auth-role-check",
        ".hasAuthority(": "auth-role-check",
        ".hasPermission(": "auth-permission-check",
        # CSRF protection indicators
        "_csrf": "csrf-token",
        "@EnableWebSecurity": "security-config",
        "@EnableGlobalMethodSecurity": "security-config",
        "@EnableMethodSecurity": "security-config",
        # Owner/tenant scope filtering
        "findByUserId": "owner-scoped-query",
        "findByUserIdAnd": "owner-scoped-query",
        "getCurrentUserId()": "owner-id-lookup",
        "AuthenticationPrincipal": "principal-injection",
    })

    # ── Sinks: framework-specific security-sensitive sinks ──
    SINKS: dict[str, str] = field(default_factory=lambda: {
        # SQL / JDBC (Spring JDBC / JdbcTemplate)
        "jdbcTemplate.query": "sql-query",
        "jdbcTemplate.queryForObject": "sql-query",
        "jdbcTemplate.queryForList": "sql-query",
        "jdbcTemplate.queryForMap": "sql-query",
        "jdbcTemplate.queryForRowSet": "sql-query",
        "jdbcTemplate.update": "sql-update",
        "jdbcTemplate.batchUpdate": "sql-batch",
        "jdbcTemplate.execute": "sql-execute",
        "namedJdbcTemplate.query": "sql-query",
        "namedJdbcTemplate.queryForObject": "sql-query",
        "namedJdbcTemplate.update": "sql-update",
        # JPA / Hibernate
        "entityManager.createQuery": "jpa-query",
        "entityManager.createNativeQuery": "jpa-native-query",
        "entityManager.createNamedQuery": "jpa-named-query",
        "entityManager.find": "jpa-find",
        "entityManager.persist": "jpa-persist",
        "entityManager.merge": "jpa-merge",
        "entityManager.remove": "jpa-remove",
        "session.createQuery": "hibernate-query",
        "session.createSQLQuery": "hibernate-sql",
        "session.createCriteria": "hibernate-criteria",
        "query.getResultList": "jpa-execute",
        "query.getSingleResult": "jpa-execute",
        # SSRF (Spring REST)
        "restTemplate.getForObject": "ssrf",
        "restTemplate.getForEntity": "ssrf",
        "restTemplate.postForObject": "ssrf",
        "restTemplate.postForEntity": "ssrf",
        "restTemplate.exchange": "ssrf",
        "restTemplate.execute": "ssrf",
        "webClient.get()": "ssrf-reactive",
        "webClient.post()": "ssrf-reactive",
        # File operations (Spring Resource)
        "FileCopyUtils.copy": "file-read",
        "StreamUtils.copy": "file-read",
        "ResourceUtils.getFile": "file-access",
        "ClassPathResource": "file-classpath",
        # Template injection
        "templateEngine.process": "ssti",
        "Thymeleaf": "ssti-engine",
        "FreeMarker": "ssti-engine",
        "Velocity": "ssti-engine",
        # Deserialization
        "@RequestBody": "deserialization-entry",
        "ObjectMapper.readValue": "deserialization",
        "convertAndSend": "jms-send",
        # XXE
        "DocumentBuilderFactory": "xxe-parser",
        "SAXParserFactory": "xxe-parser",
        "XMLInputFactory": "xxe-parser",
        "SAXReader": "xxe-parser",
    })

    # ── Sources: patterns that introduce user-controlled data ──
    SOURCES: dict[str, str] = field(default_factory=lambda: {
        # HTTP request parameter annotations
        "@RequestParam": "http-param",
        "@PathVariable": "http-path",
        "@RequestBody": "http-body",
        "@RequestHeader": "http-header",
        "@RequestPart": "http-multipart",
        "@CookieValue": "http-cookie",
        "@MatrixVariable": "http-matrix",
        "@ModelAttribute": "http-model",
        "@SessionAttribute": "http-session",
        # Servlet API sources
        "HttpServletRequest.getParameter": "servlet-param",
        "HttpServletRequest.getHeader": "servlet-header",
        "HttpServletRequest.getCookies": "servlet-cookie",
        "HttpServletRequest.getQueryString": "servlet-query",
        "HttpServletRequest.getInputStream": "servlet-input",
        "HttpServletRequest.getReader": "servlet-reader",
        "HttpServletRequest.getRequestURI": "servlet-uri",
        "HttpServletRequest.getRequestURL": "servlet-url",
        "HttpServletRequest.getPathInfo": "servlet-path",
        "HttpServletRequest.getRemoteUser": "servlet-remote-user",
        # Form binding
        "@Valid": "form-binding",
        "@Validated": "form-binding",
        "BindingResult": "form-result",
    })

    # ── Route annotations (which annotations map HTTP routes) ──
    ROUTE_ANNOTATIONS: frozenset[str] = frozenset({
        "@RequestMapping", "@GetMapping", "@PostMapping",
        "@PutMapping", "@DeleteMapping", "@PatchMapping",
    })

    # ── Autowired/singleton classes that may hold sensitive state ──
    SENSITIVE_COMPONENTS: frozenset[str] = frozenset({
        "DataSource", "JdbcTemplate", "EntityManagerFactory",
        "PasswordEncoder", "TokenStore", "JwtDecoder",
        "RestTemplate", "WebClient",
    })


# Singleton instance for convenience
SPRING = SpringProfile()

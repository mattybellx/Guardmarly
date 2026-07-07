"""
Quarkus / Micronaut Framework Profile — JAX-RS based microservices.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class QuarkusProfile:
    GUARDS: dict[str, str] = field(default_factory=lambda: {
        "@RolesAllowed": "auth-check",
        "@Authenticated": "auth-check",
        "@PermitAll": "public-route",
        "@DenyAll": "deny-all",
        "SecurityIdentity": "auth-identity",
        "JsonWebToken": "jwt-auth",
        "@Inject SecurityIdentity": "auth-inject",
        "@RegisterForReflection": "reflection-reg",
        "quarkus.http.auth": "auth-config",
        "micronaut.security": "security-config",
    })
    SINKS: dict[str, str] = field(default_factory=lambda: {
        "PanacheEntity": "panache-entity",
        ".persist()": "jpa-persist",
        ".persistAndFlush()": "jpa-persist",
        "Mutiny.SessionFactory": "reactive-db",
        "RestClient": "rest-client",
        "@RegisterRestClient": "rest-client",
        "Vertx.eventBus()": "event-bus",
        "JsonObject.mapFrom(": "json-bind",
        "ObjectMapper.readValue(": "jackson-deser",
        "Qute.fmt(": "template-render",
        "TemplateInstance.render(": "template-render",
    })
    SOURCES: dict[str, str] = field(default_factory=lambda: {
        "@QueryParam": "query-param",
        "@PathParam": "path-param",
        "@HeaderParam": "header-param",
        "@FormParam": "form-param",
        "@CookieParam": "cookie-param",
        "@BeanParam": "bean-param",
        "@RestPath": "rest-path",
        "@Body": "request-body",
        "RoutingContext.request()": "vertx-request",
    })

QUARKUS = QuarkusProfile()

"""
guardmarly.registry.loader
──────────────────────────────
Lazy framework-aware rule pack loader.

Performance contract:
  - Framework detection via string search: O(n) in source size.
  - Pack loading is memoised per pack path; subsequent calls are O(1).
  - All packs for a language are loaded once per process (LRU-cached).
  - Rule application (taint_sink matching) is O(m*s) where m = matching rules
    and s = source lines — both bounded by the 30-second per-file timeout.

Zero dependencies: uses only stdlib re, json, and pathlib. YAML parsing
delegates to the existing zero-dependency parser in yaml_rules.py.
"""
from __future__ import annotations

import logging
import re
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any

_log = logging.getLogger(__name__)

_REGISTRY_DIR = Path(__file__).parent

# ── Framework detection patterns ─────────────────────────────────────────────
# Mapping: language -> list of (framework_id, [detection_strings])
_FRAMEWORK_MARKERS: dict[str, list[tuple[str, list[str]]]] = {
    "python": [
        ("django", ["from django", "import django", "django.db", "django.conf", "django.http"]),
        ("flask", ["from flask", "import flask", "Flask(", "@app.route", "@blueprint.route", "flask_login"]),
        ("fastapi", ["from fastapi", "import fastapi", "FastAPI(", "APIRouter(", "@router.", "Depends("]),
        ("ldap_py", ["import ldap", "from ldap", "import ldap3", "from ldap3", "Connection(", "search_filter="]),
        ("jwt_py", ["import jwt", "from jose import jwt", "jwt.decode(", "jwt.encode(", "get_unverified_header("]),
        ("graphql_py", ["import graphene", "from graphene", "import strawberry", "from strawberry", "import ariadne", "GraphQL("]),
        ("second_order_sql", ["RawSQL(", "cursor.execute(sql_", "cursor.execute(query_", "text(sql_", "text(query_", "cursor.mogrify(", ".raw(sql_", ".raw(query_", "text(f\"SELECT", "text(f'SELECT", "psycopg2", "executemany"]),
        ("cloud_security", ["import boto3", "from boto3", "service_account.Credentials", "DefaultEndpointsProtocol=https", "PubliclyAccessible=True"]),
        ("deserialization_py", ["import jsonpickle", "jsonpickle.decode(", "marshal.loads(", "dill.loads(", "joblib.load(", "numpy.load(", "np.load(", "msgpack.unpackb(", "torch.load("]),
        ("template_engines_py", ["import jinja2", "from jinja2", "Template(", "from_string(", "import mako", "import pystache", "render_template_string(", "markupsafe.Markup(", "django.template.Template("]),
        ("api_security", ["allow_origins=[\"*\"]", "allow_credentials=True", "supports_credentials=True", "@app.route(\"/api/login\"", "@app.route('/api/login'", "HTTPBasicAuth()", "API_KEY", "api_key", "SECRET_KEY", "secret_key", "CORS(", "cors(", "@cross_origin", "SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"]),
        ("race_condition_py", ["os.path.exists(", "os.access(", "tempfile.mktemp(", "os.rename(", "os.chmod(", "os.unlink(", "os.stat(", "os.lstat(", "os.path.isfile(", "os.open("]),
        ("supply_chain", ["__import__(", "importlib.import_module(", "pip.main(['install'", "exec(compile(", "git+https://", "pkg_resources.require(", "sys.path.insert(", "sys.path.append(", "importlib.resources.files(", "['pip', 'install'", "[\"pip\", \"install\""]),
        ("sqlalchemy", ["from sqlalchemy", "import sqlalchemy", "create_engine(", "declarative_base", "sessionmaker("]),
        ("django_rest", ["from rest_framework", "import rest_framework", "APIView", "ModelSerializer", "viewsets."]),
        ("aiohttp_web", ["from aiohttp", "import aiohttp", "web.Application(", "web.RouteTableDef", "orjson.loads", "aiohttp.web", "aiofiles", "web.FileResponse", "request.query", "aiohttp.web.FileResponse"]),
        ("celery", ["from celery", "import celery", "Celery(", "@app.task", "@celery.task", "shared_task", "dill", "pickle", "broker=", "broker_url", "redis://"]),
        ("boto3_aws", ["import boto3", "from boto3", "boto3.client(", "boto3.resource(", "boto3.Session("]),
        ("requests_lib", ["import requests", "from requests", "requests.get(", "requests.post(", "import httpx", "httpx.get("]),
        ("pymongo", ["import pymongo", "from pymongo", "MongoClient(", "gridfs.", "motor."]),
        ("redis_py", ["import redis", "from redis", "Redis(", "StrictRedis(", "from redis.client"]),
        ("cryptography_lib", ["from cryptography", "import cryptography", "from Crypto", "import Crypto", "import hashlib", "import hmac", "hmac.new("]),
        ("subprocess_lib", ["import subprocess", "from subprocess", "subprocess.run(", "subprocess.call(", "os.system(", "os.popen(", "import shutil", "from shutil", "shutil.copy(", "shutil.move(", "shutil.rmtree(", "os.remove(", "os.unlink("]),
        ("xml_parsers", ["import xml", "from xml", "ElementTree", "minidom", "from lxml", "import lxml", "import xmltodict", "from xmltodict", "import pulldom", "from pulldom"]),
        ("yaml_load", ["import yaml", "from yaml", "yaml.load(", "yaml.safe_load(", "ruamel", "import configparser", "from configparser", "json.loads(", "toml.load"]),
        ("tornado_web", ["import tornado", "from tornado", "RequestHandler", "tornado.web.Application", "self.render_string", "self.set_secure_cookie", "self.write(", "tornado.escape", "check_xsrf_cookie", "set_header(", "self.set_header", "os.remove"]),
        ("pydantic", ["from pydantic", "import pydantic", "BaseModel", "model_validator", "field_validator"]),
        ("socketio", ["import socketio", "from socketio", "socketio.Server(", "flask_socketio"]),
        ("archive_extraction_py", ["import tarfile", "import zipfile", "zipfile", "tarfile", "from tarfile", "from zipfile", "tarfile.open(", "zipfile.ZipFile(", "shutil.unpack_archive(", "zipimport", "patoolib", "py7zr", "rarfile", "bz2", "gzip", "lzma", ".namelist(", ".getmember(", ".extractall("]),
    ],
    "javascript": [
        ("express_js", ["require('express')", 'require("express")', "from 'express'", 'from "express"', "express()", "require('ejs')", "ejs.compile(", "ejs.render(", "require('nunjucks')", "nunjucks.compile(", "nunjucks.render(", "require('handlebars')", "handlebars.compile("]),
        ("hono_framework", ["from 'hono'", 'from "hono"', "new Hono(", "import { Hono }", "c.req.query", "c.req.param", "c.html(", "c.json("]),
        ("pug_js", ["require('pug')", 'require("pug")', "from 'pug'", 'from "pug"', "pug.compile(", "pug.render(", "pug.compileFile(", "ejs.compile(", "ejs.render(", "nunjucks.compile(", "nunjucks.render("] ),
        ("ldap_js", ["require('ldapjs')", 'require("ldapjs")', "from 'ldapts'", 'from "ldapts"', "search(baseDN", "search(filter)"]),
        ("jwt_js", ["require('jsonwebtoken')", 'require("jsonwebtoken")', "jwt.verify(", "jwt.sign(", "new SignJWT("]),
        ("react_frontend", ["from 'react'", 'from "react"', "React.Component", "useState(", "useEffect(", "jsx"]),
        ("nextjs_framework", ["from 'next/", 'from "next/', "getServerSideProps", "getStaticProps", "NextApiRequest"]),
        ("sequelize_orm", ["require('sequelize')", "Sequelize(", "DataTypes.", "Model.findAll", "sequelize.query"]),
        ("prisma_orm", ["PrismaClient", "prisma.$queryRaw", "@prisma/client", "prisma.$executeRaw"]),
        ("typeorm_js", ["require('typeorm')", "from 'typeorm'", "getRepository(", "getManager(", "createConnection("]),
        ("mongoose_js", ["require('mongoose')", "mongoose.connect", "mongoose.Schema", "mongoose.model("]),
        ("mysql2_js", ["require('mysql2')", "mysql2/promise", "createPool(", "pool.query(", "connection.query("]),
        ("pg_js", ["require('pg')", "new Pool(", "new Client(", "pg.Pool", "pg.Client"]),
        ("knex_js", ["require('knex')", "knex(", "knex.raw(", "queryBuilder", ".whereRaw("]),
        ("axios_js", ["require('axios')", "axios.get(", "axios.post(", "axios.put(", "axios.delete("]),
        ("nodejs_core", ["require('fs')", "require('child_process')", "require('path')", "require('crypto')", "require('http')", "require('https')", "require('net')", "require('vm')", "https.get(", "https.request(", "net.connect(", "net.createConnection(", "vm.run(", "vm.runInNewContext(", "fetch("]),
        ("prototype_pollution_js", ["Object.assign(", "_.merge(", "deepmerge(", "jQuery.extend(true", "$.extend(true", "require('lodash')", "require('deepmerge')", "for (", "...req.body", "...req.query", "qs.parse", "hoek.merge", "Hoek.merge", "immer.produce", "produce(", "klona", "mixin(", "json-merge-patch", "mergeDeep", "merge-deep", "obj[req.", "req.body.key"]),
        ("graphql_js", ["require('graphql')", "require('apollo-server')", "gql`", "makeExecutableSchema", "ApolloServer("]),
        ("nestjs_framework", ["@Controller(", "@Injectable()", "@Module(", "@Get(", "@UseGuards(", "NestFactory"]),
        ("angular_js", ["@Component(", "@NgModule(", "@Injectable()", "Angular", "ngModule"]),
        ("vue_js", ["createApp(", "defineComponent(", "Vue.component(", "v-html", "vue-router"]),
    ],
    "java": [
        ("spring_boot", ["@SpringBootApplication", "@RestController", "@Controller", "@Service", "@Repository", "jwt", "Jwt", "JWT", "SecretKey"]),
    ],
    "csharp": [
        ("aspnet_core", ["[ApiController]", "[HttpGet]", "[HttpPost]", "IActionResult", "ControllerBase", "Jwt", "JWT", "TokenValidationParameters"]),
    ],
}

# Which pack files belong to which language (stem -> language)
_PACK_LANGUAGE: dict[str, str] = {
    # Python
    "django": "python", "flask": "python", "fastapi": "python",
    "sqlalchemy": "python", "django_rest": "python", "aiohttp_web": "python",
    "celery": "python", "boto3_aws": "python", "requests_lib": "python",
    "pymongo": "python", "redis_py": "python", "cryptography_lib": "python",
    "subprocess_lib": "python", "xml_parsers": "python", "yaml_load": "python",
    "tornado_web": "python", "pydantic": "python", "socketio": "python",
    "ldap_py": "python", "jwt_py": "python", "graphql_py": "python",
    "second_order_sql": "python", "cloud_security": "python", "deserialization_py": "python",
    "api_security": "python", "race_condition_py": "python", "supply_chain": "python",
    "template_engines_py": "python", "archive_extraction_py": "python",
    # JavaScript
    "express_js": "javascript", "react_frontend": "javascript", "nextjs_framework": "javascript",
    "sequelize_orm": "javascript", "prisma_orm": "javascript", "typeorm_js": "javascript",
    "mongoose_js": "javascript", "mysql2_js": "javascript", "pg_js": "javascript",
    "knex_js": "javascript", "axios_js": "javascript", "nodejs_core": "javascript",
    "graphql_js": "javascript", "nestjs_framework": "javascript", "angular_js": "javascript",
    "vue_js": "javascript", "ldap_js": "javascript", "jwt_js": "javascript", "pug_js": "javascript",
        "prototype_pollution_js": "javascript",
    # Java
    "spring_boot": "java",
    # C#
    "aspnet_core": "csharp",
}

# Packs that REQUIRE framework detection — should NOT load on generic code.
# These rules are specific to web frameworks and produce false positives
# when applied to CLI tools, libraries, or non-web Python/JS code.
_FRAMEWORK_ONLY_PACKS: frozenset[str] = frozenset({
    # Python web frameworks
    "django", "django_rest", "flask", "fastapi", "aiohttp_web", "tornado_web",
    # JS web frameworks
    "express_js", "react_frontend", "nextjs_framework", "nestjs_framework",
    "angular_js", "vue_js", "pug_js", "hono_framework",
    # Java / C# frameworks
    "spring_boot", "aspnet_core",
})


def detect_frameworks(source: str, language: str) -> frozenset[str]:
    """Detect which frameworks are used in the given source code.

    Returns a frozenset of framework IDs (e.g., {'django', 'sqlalchemy'}).
    O(n * m) where n = source length and m = number of marker strings per language.
    """
    detected: set[str] = set()
    markers = _FRAMEWORK_MARKERS.get(language, [])
    for framework_id, patterns in markers:
        for pattern in patterns:
            if pattern in source:
                detected.add(framework_id)
                break
    return frozenset(detected)


def _parse_registry_pack(path: Path) -> list[Any]:
    """Parse a registry YAML pack file and return raw rule dicts.

    Uses the existing yaml_rules zero-dependency parser.
    """
    try:
        from guardmarly.yaml_rules import _load_yaml_or_json
        data = _load_yaml_or_json(path)
    except Exception as exc:
        _log.warning("Registry pack %s: parse error: %s", path.name, exc)
        return []

    if not isinstance(data, dict):
        _log.warning("Registry pack %s: expected a YAML mapping, got %s", path.name, type(data).__name__)
        return []

    rules_raw = data.get("rules", [])
    if not isinstance(rules_raw, list):
        return []
    return rules_raw


def _build_custom_rule_from_entry(
    entry: dict[str, Any],
    *,
    pack_path: Path,
    default_language: str,
) -> Any | None:
    """Convert a raw rule dict from a registry pack into a CustomRule.

    Returns None if the entry is invalid or incomplete.
    """
    from guardmarly.yaml_rules import CustomRule
    from guardmarly._types import Severity

    if not isinstance(entry, dict):
        return None

    rule_id = str(entry.get("id", "")).strip()
    if not rule_id:
        return None

    title = str(entry.get("title", "")).strip()
    if not title:
        return None

    cwe_raw = str(entry.get("cwe", "")).strip().upper()
    if not re.fullmatch(r"CWE-\d+", cwe_raw):
        return None

    severity_str = str(entry.get("severity", "medium")).strip().lower()
    if severity_str not in {"critical", "high", "medium", "low", "info"}:
        severity_str = "medium"

    language = str(entry.get("language", default_language)).strip().lower()
    # Normalise language aliases
    if language in ("js", "javascript", "jsx", "ts", "typescript", "tsx"):
        language = "javascript"
    elif language in ("py", "python"):
        language = "python"
    elif language in ("go", "golang"):
        language = "go"
    elif language in ("c#", "cs", "csharp"):
        language = "csharp"

    pattern_type = str(entry.get("pattern_type", "taint_sink")).strip().lower()

    sink_names: tuple[str, ...] = ()
    compiled_pattern = None
    raw_pattern = ""
    route_decorator = ""
    missing_decorators: tuple[str, ...] = ()

    if pattern_type == "taint_sink":
        raw_sinks = entry.get("sinks", entry.get("sink_names", []))
        if isinstance(raw_sinks, str):
            sink_names = (raw_sinks.strip(),) if raw_sinks.strip() else ()
        elif isinstance(raw_sinks, list):
            sink_names = tuple(str(s).strip() for s in raw_sinks if str(s).strip())
        if not sink_names:
            return None

    elif pattern_type == "regex":
        raw_pattern = str(entry.get("regex", entry.get("pattern", ""))).strip()
        if not raw_pattern:
            return None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                compiled_pattern = re.compile(raw_pattern)
        except re.error as exc:
            _log.warning("Registry rule %r: invalid regex: %s", rule_id, exc)
            return None

    elif pattern_type == "ast_structural":
        route_decorator = str(entry.get("route_decorator", "")).strip()
        raw_missing = entry.get("missing_decorators", entry.get("missing_decorator", []))
        missing_decorators = tuple(
            str(item).strip() for item in (raw_missing if isinstance(raw_missing, list) else [])
            if str(item).strip()
        )
        if not route_decorator:
            return None
    else:
        return None

    suggestion = str(entry.get("suggestion", "")).strip()
    description = str(entry.get("description", title)).strip()
    tags_raw = entry.get("tags", [])
    tags = tuple(
        str(t).strip() for t in (tags_raw if isinstance(tags_raw, list) else [])
        if str(t).strip()
    )
    # Optional per-rule confidence override; None means use default 0.7
    raw_confidence = entry.get("confidence")
    confidence: float | None = None
    if raw_confidence is not None:
        try:
            val = float(raw_confidence)
            if 0.0 <= val <= 1.0:
                confidence = val
        except (ValueError, TypeError):
            pass
    # Optional path exclusion regex
    raw_path_exclude = entry.get("path_exclude", "")
    path_exclude: re.Pattern[str] | None = None
    if isinstance(raw_path_exclude, str) and raw_path_exclude.strip():
        try:
            path_exclude = re.compile(raw_path_exclude.strip())
        except re.error:
            pass
    return CustomRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=Severity(severity_str),
        cwe=cwe_raw,
        category="security",
        languages=(language,) if language else (),
        pattern_type=pattern_type,
        pattern=compiled_pattern,
        raw_pattern=raw_pattern,
        route_decorator=route_decorator,
        missing_decorators=missing_decorators,
        sink_names=sink_names,
        suggestion=suggestion,
        maturity="stable",
        tags=tags,
        source_path=str(pack_path),
        is_community=False,
        confidence=confidence,
        path_exclude=path_exclude,
    )


@lru_cache(maxsize=64)
def _load_single_pack(pack_path_str: str) -> tuple[Any, ...]:
    """Load and cache a single registry pack file. Returns tuple of CustomRule."""
    path = Path(pack_path_str)
    if not path.is_file():
        return ()

    default_language = _PACK_LANGUAGE.get(path.stem, "")
    raw_rules = _parse_registry_pack(path)

    loaded: list[Any] = []
    for entry in raw_rules:
        rule = _build_custom_rule_from_entry(entry, pack_path=path, default_language=default_language)
        if rule is not None:
            loaded.append(rule)

    _log.debug("Loaded %d rules from registry pack %s", len(loaded), path.name)
    return tuple(loaded)


def load_packs_for_language(language: str) -> list[Any]:
    """Load all registry packs for a given language.

    This is the language-level lazy loading — only packs for the requested
    language are loaded into memory.
    """
    normalised = language.strip().lower()
    if normalised in ("js", "javascript", "jsx", "ts", "typescript", "tsx"):
        normalised = "javascript"
    elif normalised in ("py", "python"):
        normalised = "python"

    rules: list[Any] = []
    for stem, lang in _PACK_LANGUAGE.items():
        if lang != normalised:
            continue
        pack_path = _REGISTRY_DIR / f"{stem}.yaml"
        if pack_path.is_file():
            rules.extend(_load_single_pack(str(pack_path)))

    return rules


def load_packs_for_source(source: str, language: str) -> list[Any]:
    """Load registry packs filtered to frameworks detected in source.

    This is the full lazy loading — only packs whose framework is actually
    present in the source file are returned, reducing noise.
    """
    frameworks = detect_frameworks(source, language)
    if not frameworks:
        # No framework detected — only load generic/non-framework packs.
        # Framework-specific rules (Django, Flask, Express, etc.) produce
        # false positives on CLI tools, libraries, and non-web code.
        rules: list[Any] = []
        for stem, lang in _PACK_LANGUAGE.items():
            if lang != normalised:
                continue
            if stem in _FRAMEWORK_ONLY_PACKS:
                continue
            pack_path = _REGISTRY_DIR / f"{stem}.yaml"
            if pack_path.is_file():
                rules.extend(_load_single_pack(str(pack_path)))
        return rules

    rules: list[Any] = []
    for framework_id in frameworks:
        pack_path = _REGISTRY_DIR / f"{framework_id}.yaml"
        if pack_path.is_file():
            rules.extend(_load_single_pack(str(pack_path)))

    return rules


def load_all_registry_packs() -> list[Any]:
    """Load all registry packs regardless of language (used for --list-rules)."""
    rules: list[Any] = []
    for pack_path in sorted(_REGISTRY_DIR.glob("*.yaml")):
        rules.extend(_load_single_pack(str(pack_path)))
    return rules


def count_registry_rules() -> int:
    """Return total number of rules across all registry packs."""
    return len(load_all_registry_packs())


def list_registry_pack_names() -> list[str]:
    """Return sorted list of available pack names (without .yaml extension)."""
    return sorted(p.stem for p in _REGISTRY_DIR.glob("*.yaml"))

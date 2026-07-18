from __future__ import annotations

from guardmarly import scan_code


def _rule_ids(code: str, language: str, filename: str) -> set[str]:
    result = scan_code(
        code,
        language=language,
        filename=filename,
        include_registry_rules=True,
    )
    return {f.rule_id for f in result.findings}


def _has_rule(code: str, language: str, filename: str, rule_id: str) -> bool:
    return rule_id in _rule_ids(code, language, filename)


class TestPhase2PythonRegistryExpansion:
    def test_ldap3_search_filter_injection(self):
        code = """
from flask import request
from ldap3 import Connection

def find_user(conn: Connection):
    username = request.args.get('username')
    conn.search(search_filter=f"(uid={username})", search_base="dc=example,dc=com")
"""
        assert _has_rule(code, "python", "ldap_case.py", "registry/python/ldap/ldap3-search-filter")

    def test_jwt_none_algorithm_python(self):
        code = """
import jwt

def verify(token, key):
    return jwt.decode(token, key, algorithms=['none'])
"""
        assert _has_rule(code, "python", "jwt_none.py", "registry/python/jwt/algorithm-none")

    def test_second_order_sql_cursor_execute_stored(self):
        code = """
from flask import request

def run(cursor):
    stored_username = request.args.get('username')
    query_ = f"SELECT * FROM users WHERE name = '{stored_username}'"
    cursor.execute(query_)
"""
        assert _has_rule(code, "python", "second_order.py", "registry/python/second-order-sql/cursor-execute-stored")

    def test_cloud_s3_public_acl(self):
        code = """
import boto3

s3 = boto3.client('s3')

def create_bucket(name):
    s3.create_bucket(Bucket=name, ACL='public-read')
"""
        assert _has_rule(code, "python", "cloud_acl.py", "registry/python/cloud/s3-public-acl")

    def test_deserialization_jsonpickle_decode_user_input(self):
        code = """
import jsonpickle
from flask import request

def parse():
    data = request.get_json().get('payload')
    return jsonpickle.decode(data)
"""
        assert _has_rule(code, "python", "deser_jsonpickle.py", "registry/python/deser/jsonpickle-user")

    def test_api_security_hardcoded_key(self):
        code = """
API_KEY = 'api_key_hardcoded_example_123456'
"""
        assert _has_rule(code, "python", "api_key.py", "registry/python/api/hardcoded-api-key")

    def test_race_condition_mktemp(self):
        code = """
import tempfile

def write(data):
    path = tempfile.mktemp(suffix='.tmp')
    with open(path, 'w') as f:
        f.write(data)
"""
        assert _has_rule(code, "python", "race_tmp.py", "registry/python/toctou/tempfile-mktemp")

    def test_supply_chain_dynamic_import(self):
        code = """
from flask import request

def load_plugin():
    user_module = request.args.get('module')
    return __import__(user_module)
"""
        assert _has_rule(code, "python", "supply_import.py", "registry/python/supply-chain/code-exec-import")

    def test_template_engine_jinja_from_string_user_input(self):
        code = """
from flask import request
from jinja2 import Environment

def render_user_template():
    env = Environment()
    tmpl = env.from_string(request.args.get('template'))
    return tmpl.render(user='alice')
"""
        assert _has_rule(
            code,
            "python",
            "jinja_template.py",
            "registry/python/template/jinja2-from-string-user",
        )

    def test_template_engine_jinja_template_tainted_variable(self):
        code = """
import jinja2
from flask import request

def render_user_template():
    template = request.args.get('template')
    t = jinja2.Template(template)
    return t.render(name='alice')
"""
        assert _has_rule(
            code,
            "python",
            "jinja_template_var.py",
            "registry/python/template/jinja2-template-tainted-var",
        )

    def test_template_engine_django_engine_from_string_user_input(self):
        code = """
from django.http import HttpRequest
from django.template import Engine

def render(request: HttpRequest):
    engine = Engine()
    template = request.GET.get('template')
    t = engine.from_string(template)
    return t.render()
"""
        assert _has_rule(
            code,
            "python",
            "django_engine_template.py",
            "registry/python/template/django-engine-from-string-user",
        )

    def test_template_engine_django_template_tainted_variable(self):
        code = """
from django.template import Template
from django.http import HttpRequest

def render(request: HttpRequest):
    template = request.GET.get('template')
    t = Template(template)
    return t.render()
"""
        assert _has_rule(
            code,
            "python",
            "django_template_var.py",
            "registry/python/template/django-template-tainted-var",
        )

    def test_template_engine_mako_template_tainted_variable(self):
        code = """
import mako.template
from flask import request

def render_user_template():
    template = request.args.get('template')
    t = mako.template.Template(template)
    return t.render(name='alice')
"""
        assert _has_rule(
            code,
            "python",
            "mako_template_var.py",
            "registry/python/template/mako-template-tainted-var",
        )

    def test_template_engine_tornado_template_tainted_variable(self):
        code = """
import tornado.template

def render_user_template(request):
    template = request.get_argument('template')
    t = tornado.template.Template(template)
    return t.generate(name='alice')
"""
        assert _has_rule(
            code,
            "python",
            "tornado_template_var.py",
            "registry/python/template/tornado-template-tainted-var",
        )


class TestPhase2JavaScriptRegistryExpansion:
    def test_handlebars_compile_user_template(self):
        code = """
const express = require('express');
const Handlebars = require('handlebars');

app.post('/render', (req, res) => {
  const tmpl = Handlebars.compile(req.body.template);
  res.send(tmpl({ user: req.body.name }));
});
"""
        assert _has_rule(code, "javascript", "handlebars_case.js", "registry/express/handlebars/compile-user-template")

    def test_ejs_renderfile_user_template_name(self):
        code = """
const express = require('express');
const ejs = require('ejs');

app.get('/profile', (req, res) => {
  const templateName = req.query.template;
  ejs.renderFile(templateName, { user: req.user }, (err, html) => {
    res.send(html);
  });
});
"""
        assert _has_rule(code, "javascript", "ejs_case.js", "registry/express/ejs/renderfile-user-template")

    def test_ejs_compile_user_template(self):
        code = """
    const ejs = require('ejs');

    const template = req.body.template;
    const compiled = ejs.compile(template);
    res.send(compiled({ user: req.user }));
    """
        assert _has_rule(code, "javascript", "ejs_compile_case.js", "registry/express/ejs/compile-user-template")

    def test_jwt_none_algorithm_javascript(self):
        code = """
const jwt = require('jsonwebtoken');

function verify(token, secret) {
  return jwt.verify(token, secret, { algorithms: ['none'] });
}
"""
        assert _has_rule(code, "javascript", "jwt_none_case.js", "registry/js/jwt/algorithm-none")

    def test_nunjucks_renderstring_user_template(self):
        code = """
const express = require('express');
const nunjucks = require('nunjucks');

app.get('/preview', (req, res) => {
  const template = req.body.template;
  const html = nunjucks.renderString(template, { user: req.user });
  res.send(html);
});
"""
        assert _has_rule(code, "javascript", "nunjucks_case.js", "registry/express/nunjucks/renderstring-user-template")

    def test_nunjucks_compile_user_template(self):
        code = """
const nunjucks = require('nunjucks');

const template = req.body.template;
const t = nunjucks.compile(template);
res.send(t.render({ user: req.user }));
"""
        assert _has_rule(code, "javascript", "nunjucks_compile_case.js", "registry/express/nunjucks/compile-user-template")

    def test_pug_compile_user_template(self):
        code = """
const pug = require('pug');

const template = req.body.template;
const fn = pug.compile(template);
res.send(fn({ user: req.user }));
"""
        assert _has_rule(code, "javascript", "pug_case.js", "registry/express/pug/compile-user-template")

    def test_pug_render_user_template(self):
        code = """
const pug = require('pug');

const template = req.query.template;
const html = pug.render(template, { user: req.user });
res.send(html);
"""
        assert _has_rule(code, "javascript", "pug_case.js", "registry/express/pug/render-user-template")

    def test_pug_compilefile_user_path(self):
        code = """
const pug = require('pug');

const viewPath = req.params.view;
const fn = pug.compileFile(viewPath);
res.send(fn({ user: req.user }));
"""
        assert _has_rule(code, "javascript", "pug_case.js", "registry/express/pug/compilefile-user-path")

    def test_pug_compileclient_user_template(self):
        code = """
const pug = require('pug');

const template = req.body.template;
const clientFn = pug.compileClient(template);
res.send(clientFn);
"""
        assert _has_rule(code, "javascript", "pug_compileclient_case.js", "registry/express/pug/compileclient-user-template")

    def test_prisma_second_order_queryrawunsafe(self):
        code = """
async function run(prisma, req) {
  const stored_sql = req.body.sql;
  return prisma.$queryRawUnsafe(stored_sql);
}
"""
        assert _has_rule(code, "javascript", "prisma_second_order.js", "registry/prisma/second-order/queryrawunsafe-stored")


class TestPhase4JavaAndCSharpRegistryExpansion:
    def test_spring_open_redirect(self):
        code = """
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.RestController;

@RestController
class Controller {
  public String jump(HttpServletRequest request) {
    return "redirect:" + request.getParameter("next");
  }
}
"""
        assert _has_rule(code, "java", "spring_redirect.java", "registry/spring/redirect/open-redirect")

    def test_spring_jwt_weak_secret(self):
        code = """
class JwtCfg {
  void build() {
    parser().setSigningKey("secret");
  }
}
"""
        assert _has_rule(code, "java", "spring_jwt.java", "registry/spring/jwt/weak-secret")

    def test_aspnet_jwt_alg_none(self):
        code = """
using Microsoft.IdentityModel.Tokens;

public class AuthConfig {
    public void Configure() {
        var tvp = new TokenValidationParameters {
            RequireSignedTokens = false
        };
    }
}
"""
        assert _has_rule(code, "csharp", "aspnet_jwt.cs", "registry/aspnet/jwt/alg-none")

    def test_aspnet_open_redirect_without_localurl_check(self):
        code = """
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller {
    public IActionResult Jump(string returnUrl) {
        return Redirect(returnUrl);
    }
}
"""
        assert _has_rule(code, "csharp", "aspnet_redirect.cs", "registry/aspnet/redirect/localurl-missing")


class TestPhase5UtilityPackExpansion:
    """14 new rules: shutil path-traversal, weak crypto algorithms, XXE via xmltodict/objectify/pulldom,
    ConfigParser/JSON body deserialization (786→800)."""

    # --- subprocess_lib: shutil path traversal ---

    def test_shutil_copy_user_path(self):
        code = """
import shutil

def copy_upload(request):
    user_path = request.args.get('path')
    shutil.copy(user_path, '/safe/dest')
"""
        assert _has_rule(code, "python", "app.py", "registry/subprocess/path/shutil-copy-user")

    def test_shutil_move_user_path(self):
        code = """
import shutil

def move_file(request):
    user_path = request.args.get('src')
    shutil.move(user_path, '/archive/')
"""
        assert _has_rule(code, "python", "app.py", "registry/subprocess/path/shutil-move-user")

    def test_shutil_rmtree_user_path(self):
        code = """
import shutil

def delete_workspace(request):
    user_dir = request.args.get('workspace')
    shutil.rmtree(user_dir)
"""
        assert _has_rule(code, "python", "app.py", "registry/subprocess/path/shutil-rmtree-user")

    def test_os_remove_user_path(self):
        code = """
import os

def remove_file(request):
    user_file = request.args.get('file')
    os.remove(user_file)
"""
        assert _has_rule(code, "python", "app.py", "registry/subprocess/path/os-remove-user")

    # --- cryptography_lib: weak algorithm usage ---

    def test_user_controlled_hash_algorithm(self):
        code = """
import hashlib

def digest(algorithm, data):
    h = hashlib.new(algorithm, data.encode())
    return h.hexdigest()
"""
        assert _has_rule(code, "python", "crypto.py", "registry/crypto/hash/user-controlled-algorithm")

    def test_hmac_weak_md5(self):
        code = """
import hmac, hashlib

def make_mac(key, msg):
    return hmac.new(key, digestmod=hashlib.md5).update(msg)
"""
        assert _has_rule(code, "python", "mac.py", "registry/crypto/hmac/weak-md5")

    def test_blowfish_cipher_usage(self):
        code = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key, iv, pt):
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv))
    return cipher.encryptor().update(pt)
"""
        assert _has_rule(code, "python", "crypto.py", "registry/crypto/symmetric/blowfish")

    def test_rc4_cipher_usage(self):
        code = """
from Crypto.Cipher import ARC4

def stream_encrypt(key, data):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)
"""
        assert _has_rule(code, "python", "rc4.py", "registry/crypto/symmetric/rc4")

    # --- xml_parsers: XXE via xmltodict, objectify, pulldom ---

    def test_xmltodict_parse_user_xml(self):
        code = """
import xmltodict

def parse_feed(request):
    user_xml = request.data
    doc = xmltodict.parse(user_xml)
    return doc
"""
        assert _has_rule(code, "python", "parser.py", "registry/xml/xxe/xmltodict-user")

    def test_lxml_objectify_user_xml(self):
        code = """
from lxml import objectify

def load_config(request):
    user_xml = request.data
    root = objectify.fromstring(user_xml)
    return root
"""
        assert _has_rule(code, "python", "parser.py", "registry/xml/xxe/lxml-objectify-user")

    def test_pulldom_parse_user_xml(self):
        code = """
from xml.dom import pulldom

def stream_parse(request):
    user_xml = request.data
    events = pulldom.parseString(user_xml)
    return events
"""
        assert _has_rule(code, "python", "stream.py", "registry/xml/xxe/pulldom-user")

    # --- yaml_load: JSON body, configparser body, configparser file path ---

    def test_json_loads_body_variable(self):
        code = """
import json

def handle(request):
    body = request.get_data(as_text=True)
    data = json.loads(body)
    return data
"""
        assert _has_rule(code, "python", "api.py", "registry/yaml/deserialization/json-loads-body")

    def test_configparser_read_string_body(self):
        code = """
import configparser

def apply_config(request):
    body = request.data.decode()
    config = configparser.ConfigParser()
    config.read_string(body)
"""
        assert _has_rule(code, "python", "config.py", "registry/yaml/config/configparser-read-string-body")

    def test_configparser_read_user_file(self):
        code = """
import configparser

def load_config(request):
    config = configparser.ConfigParser()
    user_path = request.args.get('cfg')
    config.read(user_path)
"""
        assert _has_rule(code, "python", "config.py", "registry/yaml/config/configparser-read-user-file")


class TestPhase6NodejsCoreExpansion:
    """8 new Node.js rules: SSRF (http.get, https.get, fetch, net.connect),
    path traversal (createReadStream, unlink, rename), vm code injection (800→808)."""

    def test_http_get_url_variable_ssrf(self):
        code = """
const http = require('http');

app.get('/proxy', (req, res) => {
  const url = req.query.target;
  http.get(url, (response) => response.pipe(res));
});
"""
        assert _has_rule(code, "javascript", "proxy.js", "registry/nodejs/ssrf/http-get-user-url")

    def test_https_get_endpoint_ssrf(self):
        code = """
const https = require('https');

app.post('/fetch', (req, res) => {
  const endpoint = req.body.url;
  https.get(endpoint, (r) => r.pipe(res));
});
"""
        assert _has_rule(code, "javascript", "fetch.js", "registry/nodejs/ssrf/https-get-user-url")

    def test_fetch_user_url_ssrf(self):
        code = """
app.get('/load', async (req, res) => {
  const url = req.query.source;
  const result = await fetch(url);
  res.json(await result.json());
});
"""
        assert _has_rule(code, "javascript", "load.js", "registry/nodejs/ssrf/fetch-user-url")

    def test_net_connect_user_host_ssrf(self):
        code = """
const net = require('net');

app.post('/connect', (req, res) => {
  const port = 80;
  const host = req.body.host;
  const socket = net.connect(port, host);
  socket.pipe(res);
});
"""
        assert _has_rule(code, "javascript", "tcp.js", "registry/nodejs/ssrf/net-connect-user")

    def test_fs_createreadstream_user_path(self):
        code = """
const fs = require('fs');

app.get('/download', (req, res) => {
  const path = req.query.file;
  fs.createReadStream(path).pipe(res);
});
"""
        assert _has_rule(code, "javascript", "download.js", "registry/nodejs/path/fs-createreadstream-user")

    def test_fs_unlink_user_path(self):
        code = """
const fs = require('fs');

app.delete('/file', (req, res) => {
  fs.unlink(req.query.path, (err) => res.json({ ok: !err }));
});
"""
        assert _has_rule(code, "javascript", "files.js", "registry/nodejs/path/fs-unlink-user")

    def test_vm_run_user_code(self):
        code = """
const vm = require('vm');

app.post('/eval', (req, res) => {
  const result = vm.runInNewContext(req.body.code, {});
  res.json({ result });
});
"""
        assert _has_rule(code, "javascript", "eval.js", "registry/nodejs/code-injection/vm-user")

    def test_fs_rename_user_path(self):
        code = """
const fs = require('fs');

app.post('/rename', (req, res) => {
  fs.rename(req.query.src, req.body.dst, (err) => res.json({ ok: !err }));
});
"""
        assert _has_rule(code, "javascript", "files.js", "registry/nodejs/path/fs-rename-user")


class TestPhase6PythonPackExpansion:
    """12 new Python rules across second_order_sql (+4), supply_chain (+4), race_condition_py (+4)
    (808→820)."""

    # --- second_order_sql: cursor.mogrify, queryset.raw, text(f"..."), executemany ---

    def test_cursor_mogrify_stored_sql(self):
        code = """
import psycopg2

def run_stored(conn, sql_template):
    with conn.cursor() as cursor:
        query = cursor.mogrify(sql_template, ())
        cursor.execute(query)
"""
        assert _has_rule(code, "python", "db.py", "registry/python/second-order-sql/cursor-mogrify-stored")

    def test_django_queryset_raw_stored(self):
        code = """
from myapp.models import User

def search(stored_query):
    results = User.objects.raw(sql_query)
    return list(results)
"""
        assert _has_rule(code, "python", "views.py", "registry/python/second-order-sql/django-queryset-raw")

    def test_sqlalchemy_text_fstring(self):
        code = """
from sqlalchemy import text

def query_user(db, username):
    stmt = text(f"SELECT * FROM users WHERE name = '{username}'")
    return db.execute(stmt).fetchall()
"""
        assert _has_rule(code, "python", "db.py", "registry/python/second-order-sql/sqlalchemy-text-fstring")

    def test_psycopg_executemany_stored(self):
        code = """
def bulk_run(conn, sql_template, rows):
    with conn.cursor() as cursor:
        cursor.executemany(sql_template, rows)
"""
        assert _has_rule(code, "python", "db.py", "registry/python/second-order-sql/psycopg-executemany-stored")

    # --- supply_chain: sys.path injection, pkg_resources, pip install user pkg, importlib user ---

    def test_sys_path_injection(self):
        code = """
import sys

def load_plugin(request):
    user_path = request.args.get('plugin_dir')
    sys.path.insert(0, user_path)
    import plugin
"""
        assert _has_rule(code, "python", "plugin.py", "registry/python/supply-chain/sys-path-injection")

    def test_pkg_resources_require_user(self):
        code = """
import pkg_resources

def check_version(request):
    pkg = request.args.get('package')
    pkg_resources.require(user_pkg)
"""
        assert _has_rule(code, "python", "deps.py", "registry/python/supply-chain/pkg-resources-require-user")

    def test_pip_install_user_package(self):
        code = """
import subprocess

def install_dep(request):
    user_pkg = request.json.get('package')
    subprocess.run(['pip', 'install', user_pkg], check=True)
"""
        assert _has_rule(code, "python", "setup.py", "registry/python/supply-chain/pip-install-user-package")

    def test_importlib_user_module(self):
        code = """
import importlib

def load_handler(request):
    module_name = request.args.get('handler')
    mod = importlib.import_module(user_module)
    return mod.handle()
"""
        assert _has_rule(code, "python", "dispatch.py", "registry/python/supply-chain/importlib-user-module")

    # --- race_condition_py: stat, isfile/isdir, os.open, lstat ---

    def test_os_stat_race(self):
        code = """
import os

def check_size(user_path):
    info = os.stat(user_path)
    if info.st_size < 1024 * 1024:
        with open(user_path) as f:
            return f.read()
"""
        assert _has_rule(code, "python", "fileutil.py", "registry/python/toctou/stat-race")

    def test_os_path_isfile_race(self):
        code = """
import os

def serve(request):
    user_path = request.args.get('path')
    if os.path.isfile(user_path):
        with open(user_path, 'rb') as f:
            return f.read()
"""
        assert _has_rule(code, "python", "serve.py", "registry/python/toctou/isfile-isdir-race")

    def test_os_open_user_path(self):
        code = """
import os

def open_raw(request):
    path = request.args.get('path')
    fd = os.open(request.path, os.O_RDONLY)
    return os.read(fd, 4096)
"""
        assert _has_rule(code, "python", "raw.py", "registry/python/toctou/os-open-user-path")

    def test_os_lstat_symlink_race(self):
        code = """
import os

def safe_check(user_path):
    stat = os.lstat(user_path)
    if not stat.st_mode & 0o120000:
        with open(user_path) as f:
            return f.read()
"""
        assert _has_rule(code, "python", "check.py", "registry/python/toctou/lstat-symlink-race")


class TestPhase7ArchiveProtoPollutionExpansion:
        """20 new rules: archive extraction (820→828), prototype pollution (828→835),
        ldap_js extensions (835→838), pug_js extensions (838→840)."""

        # --- archive_extraction_py ---

        def test_tarfile_extractall_user_path(self):
                code = """
import tarfile

def extract(request):
        user_path = request.args.get('dest')
        with tarfile.open('upload.tar.gz') as tar:
                tar.extractall(user_path)
"""
                assert _has_rule(code, "python", "extract.py", "registry/python/archive/tarfile-extractall-user")

        def test_tarfile_extract_member_user(self):
                code = """
import tarfile

def get_file(request):
        member = request.args.get('file')
        with tarfile.open('archive.tar') as tar:
                tar.extract(user_member)
"""
                assert _has_rule(code, "python", "extract.py", "registry/python/archive/tarfile-extract-member")

        def test_zipfile_open_user_path(self):
                code = """
import zipfile

def open_archive(request):
        user_path = request.args.get('archive')
        zf = zipfile.ZipFile(user_path, 'r')
        return zf.namelist()
"""
                assert _has_rule(code, "python", "zip.py", "registry/python/archive/zipfile-open-user")

        def test_zipfile_extractall_user_dest(self):
                code = """
import zipfile

def extract_zip(upload, request):
        dest = request.args.get('dest')
        with zipfile.ZipFile(upload) as zf:
                zf.extractall(user_dest)
"""
                assert _has_rule(code, "python", "zip.py", "registry/python/archive/zipfile-extractall-user")

        def test_zipimport_user_archive(self):
                code = """
import zipimport

def load_plugin(request):
        archive = request.args.get('plugin')
        importer = zipimport.zipimporter(user_archive)
        mod = importer.load_module('plugin')
"""
                assert _has_rule(code, "python", "plugin.py", "registry/python/archive/zipimport-user")

        def test_shutil_unpack_archive_user(self):
                code = """
import shutil

def unpack(request):
        user_file = request.args.get('archive')
        shutil.unpack_archive(user_file, '/tmp/extracted/')
"""
                assert _has_rule(code, "python", "unpack.py", "registry/python/archive/shutil-unpack-user")

        # --- prototype_pollution_js ---

        def test_object_assign_req_body(self):
                code = """
app.post('/update', (req, res) => {
    const config = Object.assign({}, req.body);
    applyConfig(config);
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "config.js", "registry/js/proto-pollution/object-assign-req")

        def test_lodash_merge_req_body(self):
                code = """
const _ = require('lodash');

app.post('/merge', (req, res) => {
    const result = _.merge(obj, req.body);
    res.json(result);
});
"""
                assert _has_rule(code, "javascript", "merge.js", "registry/js/proto-pollution/lodash-merge-req")

        def test_deepmerge_req_body(self):
                code = """
const deepmerge = require('deepmerge');

app.post('/config', (req, res) => {
    const merged = deepmerge(defaults, req.body);
    res.json(merged);
});
"""
                assert _has_rule(code, "javascript", "config.js", "registry/js/proto-pollution/deepmerge-req")

        def test_jquery_extend_deep(self):
                code = """
app.post('/settings', (req, res) => {
    $.extend(true, obj, req.body);
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "settings.js", "registry/js/proto-pollution/jquery-extend-deep")

        def test_bracket_notation_user_key(self):
                code = """
app.post('/set', (req, res) => {
    const key = req.body.key;
    obj[req.body.key] = req.body.value;
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "setter.js", "registry/js/proto-pollution/constructor-property-access")

        def test_lodash_set_user_path(self):
                code = """
const _ = require('lodash');

app.post('/set-prop', (req, res) => {
    _.set(obj, req.body.path, req.body.value);
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "setter.js", "registry/js/proto-pollution/lodash-set-req")

        def test_spread_req_body(self):
                code = """
app.post('/update', (req, res) => {
    const settings = { ...req.body };
    applySettings(settings);
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "update.js", "registry/js/proto-pollution/spread-merge-req")

        # --- ldap_js extensions ---

        def test_ldap_delete_user_dn(self):
                code = """
const ldap = require('ldapjs');

app.delete('/user', (req, res) => {
    client.del(req.query.dn, (err) => res.json({ ok: !err }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/delete-user")

        def test_ldap_compare_user(self):
                code = """
const ldap = require('ldapjs');

app.post('/check', (req, res) => {
    client.compare(req.body.dn, 'uid', req.body.value, (err, matched) => {
        res.json({ matched });
    });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/compare-user")

        def test_ldap_exop_user(self):
                code = """
const ldap = require('ldapjs');

app.post('/exop', (req, res) => {
    client.exop(req.body.oid, req.body.value, (err, value) => res.json({ value }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/exop-user")

        # --- pug_js extensions ---

        def test_pug_renderfile_user_path(self):
                code = """
const pug = require('pug');

app.get('/render', (req, res) => {
    const templatePath = req.query.template;
    const html = pug.renderFile(templatePath, {});
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "render.js", "registry/express/pug/renderfile-user-path")

        def test_pug_render_concat_template(self):
                code = """
const pug = require('pug');

app.post('/render', (req, res) => {
    const html = pug.render(header + req.body.snippet);
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "render.js", "registry/express/pug/render-concat-template")

        def test_pug_dangerous_locals(self):
                code = """
const pug = require('pug');

app.get('/page', (req, res) => {
    const html = pug.render('p !{locals.html}', {
        locals: { html: req.query.content }
    });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "page.js", "registry/express/pug/dangerous-locals")


        class TestPhase8FrameworkPackExpansion:
            """20 new rules across aiohttp_web (+7), graphql_js (+7), and api_security (+6) (840→860)."""

            # --- aiohttp_web ---

            def test_aiohttp_client_request_user_url(self):
                code = """
        import aiohttp

        async def proxy(request):
            async with aiohttp.ClientSession() as session:
                data = await session.request('GET', request.query.get('url'))
                return data
        """
                assert _has_rule(code, "python", "aio.py", "registry/aiohttp/ssrf/client-request-user-url")

            def test_aiohttp_httpseeother_user_location(self):
                code = """
        from aiohttp import web

        def jump(request):
            raise web.HTTPSeeOther(location=request.query.get('next'))
        """
                assert _has_rule(code, "python", "redirect.py", "registry/aiohttp/redirect/httpseeother-user")

            def test_aiohttp_set_cookie_user_value(self):
                code = """
        from aiohttp import web

        def login(request):
            response = web.Response(text='ok')
            response.set_cookie('session', request.query.get('sid'))
            return response
        """
                assert _has_rule(code, "python", "cookie.py", "registry/aiohttp/header/set-cookie-user")

            def test_aiohttp_cookie_httponly_false(self):
                code = """
        from aiohttp import web

        def login(request):
            response = web.Response(text='ok')
            response.set_cookie('session', 'abc', httponly=False)
            return response
        """
                assert _has_rule(code, "python", "cookie.py", "registry/aiohttp/session/cookie-httponly-false")

            def test_aiohttp_jinja2_template_user(self):
                code = """
        from aiohttp import web
        import jinja2

        def render(request):
            tpl = jinja2.Template(request.query.get('template'))
            return web.Response(text=tpl.render())
        """
                assert _has_rule(code, "python", "render.py", "registry/aiohttp/template/jinja2-template-user")

            def test_aiohttp_websocket_send_user_html(self):
                code = """
        from aiohttp import web

        async def ws_handler(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            await ws.send_str(request.query.get('message'))
            return ws
        """
                assert _has_rule(code, "python", "ws.py", "registry/aiohttp/websocket/send-user-html")

            def test_aiohttp_yaml_load_request(self):
                code = """
        from aiohttp import web
        import yaml

        async def parse(request):
            data = yaml.load(await request.text())
            return web.json_response({'ok': bool(data)})
        """
                assert _has_rule(code, "python", "parse.py", "registry/aiohttp/deserialization/yaml-load-request")

            # --- graphql_js ---

            def test_graphql_playground_enabled(self):
                code = """
        const { ApolloServer } = require('apollo-server');

        const server = new ApolloServer({ typeDefs, resolvers, playground: true });
        """
                assert _has_rule(code, "javascript", "server.js", "registry/graphql/playground/enabled-production")

            def test_graphql_graphiql_enabled(self):
                code = """
        const { ApolloServer } = require('apollo-server');

        const server = new ApolloServer({ typeDefs, resolvers, graphiql: true });
        """
                assert _has_rule(code, "javascript", "server.js", "registry/graphql/graphiql/enabled-production")

            def test_graphql_child_process_args(self):
                code = """
        const { ApolloServer } = require('apollo-server');
        const { exec } = require('child_process');

        const resolvers = {
          Query: {
            run: (_, args) => exec(args.command)
          }
        };
        """
                assert _has_rule(code, "javascript", "resolver.js", "registry/graphql/injection/child-process-args")

            def test_graphql_fetch_resolver_url(self):
                code = """
        const { ApolloServer } = require('apollo-server');

        const resolvers = {
          Query: {
            proxy: async (_, args) => fetch(args.target)
          }
        };
        """
                assert _has_rule(code, "javascript", "resolver.js", "registry/graphql/ssrf/fetch-resolver-url")

            def test_graphql_update_mass_assignment(self):
                code = """
        const { ApolloServer } = require('apollo-server');

        const resolvers = {
          Mutation: {
            updateUser: (_, args, { prisma }) => prisma.user.update({ data: args.input })
          }
        };
        """
                assert _has_rule(code, "javascript", "mutation.js", "registry/graphql/mutation/update-mass-assignment")

            def test_graphql_upload_max_size_infinite(self):
                code = """
        const { ApolloServer } = require('apollo-server');
        const { graphqlUploadExpress } = require('graphql-upload');

        app.use(graphqlUploadExpress({ maxFileSize: Infinity }));
        """
                assert _has_rule(code, "javascript", "upload.js", "registry/graphql/upload/max-size-infinite")

            def test_graphql_error_stack_leak(self):
                code = """
        const { ApolloServer } = require('apollo-server');

        const server = new ApolloServer({
          typeDefs,
          resolvers,
          formatError: (err) => err
        });
        """
                assert _has_rule(code, "javascript", "errors.js", "registry/graphql/errors/stack-leak")

            # --- api_security ---

            def test_api_jwt_verify_signature_false(self):
                code = """
        from flask_httpauth import HTTPBasicAuth
        import jwt

        auth = HTTPBasicAuth()

        def parse(token):
            return jwt.decode(token, options={"verify_signature": False})
        """
                assert _has_rule(code, "python", "auth.py", "registry/python/api/jwt-verify-signature-false")

            def test_api_trust_x_forwarded_for(self):
                code = """
        from flask import request
        from flask_httpauth import HTTPBasicAuth

        auth = HTTPBasicAuth()

        def login():
            ip = request.headers.get('X-Forwarded-For')
            return ip
        """
                assert _has_rule(code, "python", "ip.py", "registry/python/api/trust-x-forwarded-for")

            def test_api_password_in_url(self):
                code = """
        from flask import request
        from flask_httpauth import HTTPBasicAuth

        auth = HTTPBasicAuth()

        def do_login():
            pwd = request.args.get('password')
            return pwd
        """
                assert _has_rule(code, "python", "login.py", "registry/python/api/password-in-url")

            def test_api_session_cookie_httponly_false(self):
                code = """
        from flask_httpauth import HTTPBasicAuth

        auth = HTTPBasicAuth()
        SESSION_COOKIE_HTTPONLY = False
        """
                assert _has_rule(code, "python", "settings.py", "registry/python/api/session-cookie-httponly-false")

            def test_api_csrf_exempt_auth_endpoint(self):
                code = """
        from flask import Flask
        from flask_httpauth import HTTPBasicAuth

        auth = HTTPBasicAuth()
        app = Flask(__name__)

        @csrf.exempt
        @app.route('/login', methods=['POST'])
        def login():
            return 'ok'
        """
                assert _has_rule(code, "python", "csrf.py", "registry/python/api/csrf-exempt-auth-endpoint")

            def test_api_weak_random_token(self):
                code = """
        from flask_httpauth import HTTPBasicAuth
        import random

        auth = HTTPBasicAuth()
        reset_token = str(random.random())
        """
                assert _has_rule(code, "python", "token.py", "registry/python/api/weak-random-token")


class TestPhase9RegistryExpansion:
        """20 new rules across ldap_js (+5), pug_js (+5), prototype_pollution_js (+5), archive_extraction_py (+5) (860→880)."""

        # --- ldap_js ---

        def test_ldap_modifydn_user(self):
                code = """
const ldap = require('ldapjs');

app.post('/rename-dn', (req, res) => {
    client.modifyDN(req.body.dn, req.body.newRdn, (err) => res.json({ ok: !err }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/modifydn-user")

        def test_ldap_create_client_user_url(self):
                code = """
const ldap = require('ldapjs');

app.post('/connect', (req, res) => {
    const client = ldap.createClient({ url: req.body.url });
    res.json({ ok: !!client });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/create-client-user-url")

        def test_ldap_size_limit_user(self):
                code = """
const ldap = require('ldapjs');

app.get('/search', (req, res) => {
    client.search(req.query.base, { sizeLimit: req.query.limit }, () => {});
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/search-options-user-size-limit")

        def test_ldap_filter_presence_user(self):
                code = """
const ldap = require('ldapjs');

app.get('/user', (req, res) => {
    client.search('dc=example,dc=com', { filter: '(uid=' + req.query.uid + ')' }, () => {});
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/filter-presence-user")

        def test_ldap_referral_user(self):
                code = """
const ldap = require('ldapjs');

app.post('/opts', (req, res) => {
    const opts = { referrals: { enabled: req.body.referrals } };
    res.json(opts);
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/referral-chasing-user")

        # --- pug_js ---

        def test_pug_compilefileclient_user_path(self):
                code = """
const pug = require('pug');

app.post('/compile-client', (req, res) => {
    const clientFn = pug.compileFileClient(req.body.templatePath);
    res.send(clientFn);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/compilefileclient-user-path")

        def test_pug_renderfile_basedir_user(self):
                code = """
const pug = require('pug');

app.get('/render', (req, res) => {
    const html = pug.renderFile('safe.pug', { basedir: req.query.base });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/renderfile-basedir-user")

        def test_pug_include_user_interpolation(self):
                code = """
const pug = require('pug');

app.get('/inline', (req, res) => {
    const html = pug.render('include ' + req.query.partial);
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/include-user-interpolation")

        def test_pug_locals_unescaped_body(self):
                code = """
const pug = require('pug');

app.post('/view', (req, res) => {
    const html = pug.render('p !{locals.html}', { locals: req.body });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/locals-unescaped-body")

        def test_pug_renderfile_filename_user(self):
                code = """
const pug = require('pug');

app.get('/file', (req, res) => {
    const html = pug.renderFile('a.pug', { filename: req.query.tpl });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/renderfile-filename-user")

        # --- prototype_pollution_js ---

        def test_proto_lodash_mergewith_req(self):
                code = """
const _ = require('lodash');

app.post('/mergewith', (req, res) => {
    _.mergeWith(obj, req.body);
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/lodash-mergewith-req")

        def test_proto_lodash_defaultsdeep_req(self):
                code = """
const _ = require('lodash');

app.post('/defaults', (req, res) => {
    _.defaultsDeep(config, req.body);
    res.json(config);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/lodash-defaultsdeep-req")

        def test_proto_zipobjectdeep_req(self):
                code = """
const _ = require('lodash');

app.post('/zip', (req, res) => {
    const out = _.zipObjectDeep(req.body.paths, req.body.values);
    res.json(out);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/lodash-zipobjectdeep-req")

        def test_proto_deepmerge_all_req(self):
                code = """
const deepmerge = require('deepmerge');

app.post('/mergeall', (req, res) => {
    const merged = deepmerge.all([defaults, req.body]);
    res.json(merged);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/deepmerge-all-req")

        def test_proto_object_assign_req_query(self):
                code = """
app.get('/assign', (req, res) => {
    const cfg = Object.assign({}, req.query);
    res.json(cfg);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/object-assign-req-query")

        # --- archive_extraction_py ---

        def test_archive_tar_extractfile_user_member(self):
                code = """
import tarfile

def read_member(request):
        with tarfile.open('up.tar') as tar:
                return tar.extractfile(request.args.get('member'))
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/tarfile-extractfile-user-member")

        def test_archive_tar_getmember_user(self):
                code = """
import tarfile

def pick_member(request):
        with tarfile.open('up.tar') as tar:
                return tar.getmember(request.args.get('name'))
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/tarfile-getmember-user")

        def test_archive_zip_open_member_user(self):
                code = """
import zipfile

def open_member(request):
        with zipfile.ZipFile('up.zip') as zf:
                return zf.open(request.args.get('member'))
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-open-member-user")

        def test_archive_zip_read_user_member(self):
                code = """
import zipfile

def read_member(request):
        with zipfile.ZipFile('up.zip') as zf:
                return zf.read(request.args.get('member'))
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-read-user-member")

        def test_archive_zip_slip_path_join(self):
                code = """
import os, zipfile

def extract_member(extract_dir, member):
        out = os.path.join(extract_dir, member.filename)
        return out
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/zip-slip-path-join")


class TestPhase10RegistryExpansion:
        """20 new rules across ldap_js (+5), pug_js (+5), prototype_pollution_js (+5), archive_extraction_py (+5) (880→900)."""

        # --- ldap_js ---

        def test_ldap_starttls_user_options(self):
                code = """
const ldap = require('ldapjs');

app.post('/tls', (req, res) => {
    client.starttls(req.body.tlsOptions, null, () => {});
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/starttls-user-options")

        def test_ldap_search_scope_user(self):
                code = """
const ldap = require('ldapjs');

app.get('/search', (req, res) => {
    client.search('dc=example,dc=com', { scope: req.query.scope }, () => {});
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/search-scope-user")

        def test_ldap_search_timeout_user(self):
                code = """
const ldap = require('ldapjs');

app.get('/search', (req, res) => {
    client.search('dc=example,dc=com', { timeout: req.query.timeout }, () => {});
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/search-timeout-user")

        def test_ldap_bind_password_from_query(self):
                code = """
const ldap = require('ldapjs');

app.post('/bind', (req, res) => {
    client.bind(config.bindDN, req.query.password, () => res.json({ ok: true }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/bind-password-from-query")

        def test_ldap_url_template_literal_user(self):
                code = """
const ldap = require('ldapjs');

app.post('/connect', (req, res) => {
    const client = ldap.createClient({ url: `ldap://${req.body.host}` });
    res.json({ ok: !!client });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/url-template-literal-user")

        # --- pug_js ---

        def test_pug_renderfile_cache_user(self):
                code = """
const pug = require('pug');

app.get('/render', (req, res) => {
    const html = pug.renderFile('view.pug', { cache: req.query.cache });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/renderfile-cache-user")

        def test_pug_compile_compiledebug_user(self):
                code = """
const pug = require('pug');

app.post('/compile', (req, res) => {
    const fn = pug.compile(req.body.template, { compileDebug: req.query.debug });
    res.send(fn({}));
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/compile-compiledebug-user")

        def test_pug_render_pretty_user(self):
                code = """
const pug = require('pug');

app.post('/render', (req, res) => {
    const html = pug.render(req.body.template, { pretty: req.query.pretty });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/render-pretty-user")

        def test_pug_res_render_user_view(self):
                code = """
const pug = require('pug');

app.get('/page', (req, res) => {
    res.render(req.query.view, { user: 'x' });
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/res-render-user-view")

        def test_pug_renderfile_basedir_path_join_user(self):
                code = """
const pug = require('pug');
const path = require('path');

app.get('/render', (req, res) => {
    const html = pug.renderFile('a.pug', { basedir: path.join('/templates', req.query.dir) });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/renderfile-basedir-path-join-user")

        # --- prototype_pollution_js ---

        def test_proto_object_defineproperty_user_key(self):
                code = """
const _ = require('lodash');

app.post('/define', (req, res) => {
    Object.defineProperty(obj, req.body.key, { value: 1 });
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/object-defineproperty-user-key")

        def test_proto_for_in_req_body(self):
                code = """
const _ = require('lodash');

app.post('/copy', (req, res) => {
    for (const k in req.body) {
        target[k] = req.body[k];
    }
    res.json(target);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/for-in-req-body")

        def test_proto_for_in_req_query(self):
                code = """
const _ = require('lodash');

app.get('/copy', (req, res) => {
    for (const k in req.query) {
        target[k] = req.query[k];
    }
    res.json(target);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/for-in-req-query")

        def test_proto_dot_prop_set_req(self):
                code = """
const _ = require('lodash');
const dotProp = require('dot-prop');

app.post('/set', (req, res) => {
    dotProp.set(obj, req.body.path, req.body.value);
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/dot-prop-set-req")

        def test_proto_fromentries_req_body(self):
                code = """
const _ = require('lodash');

app.post('/entries', (req, res) => {
    const rebuilt = Object.fromEntries(Object.entries(req.body));
    res.json(rebuilt);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/fromentries-req-body")

        # --- archive_extraction_py ---

        def test_archive_zip_extract_user_member(self):
                code = """
import zipfile

def extract_one(request):
        with zipfile.ZipFile('u.zip') as zf:
                return zf.extract(request.args.get('member'))
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-extract-user-member")

        def test_archive_shutil_unpack_user_dest(self):
                code = """
import shutil

def unpack(request):
        file_path = '/tmp/in.zip'
        shutil.unpack_archive(file_path, request.args.get('dest'))
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/shutil-unpack-user-dest")

        def test_archive_tar_extractall_members_user(self):
                code = """
import tarfile

def selective_extract(user_members):
        with tarfile.open('u.tar') as tar:
                tar.extractall(path=safe_dir, members=user_members)
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/tarfile-extractall-members-user")

        def test_archive_zip_namelist_path_join(self):
                code = """
import os, zipfile

def unsafe_join(zf, root):
        for name in zf.namelist():
                out = os.path.join(root, name)
                return out
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-namelist-path-join")

        def test_archive_tar_member_name_path_join(self):
                code = """
import os, tarfile

def unsafe_tar(root, member):
        out = os.path.join(root, member.name)
        return out
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/tar-member-name-path-join")


class TestPhase11RegistryExpansion:
        """20 new rules across ldap_js (+5), pug_js (+5), prototype_pollution_js (+5), archive_extraction_py (+5) (900→920)."""

        # --- ldap_js ---

        def test_ldap_search_attributes_user(self):
                code = """
const ldap = require('ldapjs');

app.get('/search', (req, res) => {
    client.search('dc=example,dc=com', { attributes: req.query.fields }, () => {});
    res.json({ ok: true });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/search-attributes-user")

        def test_ldap_abandon_user_msgid(self):
                code = """
const ldap = require('ldapjs');

app.post('/cancel', (req, res) => {
    client.abandon(req.body.messageId, () => res.json({ ok: true }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/abandon-user-msgid")

        def test_ldap_modify_change_user_op(self):
                code = """
const ldap = require('ldapjs');

app.post('/modify', (req, res) => {
    const change = new ldap.Change({ modification: { type: req.body.attr, vals: ['v'] } });
    client.modify('cn=user', change, () => res.json({ ok: true }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/modify-change-user-op")

        def test_ldap_reconnect_user_url(self):
                code = """
const ldap = require('ldapjs');

app.post('/reconnect', (req, res) => {
    const client = ldap.createClient({ reconnect: { url: req.body.url, maxDelay: 5000 } });
    res.json({ ok: !!client });
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/reconnect-user-url")

        def test_ldap_change_password_user(self):
                code = """
const ldap = require('ldapjs');

app.post('/passwd', (req, res) => {
    client.passwordModify(req.body.credentials, () => res.json({ ok: true }));
});
"""
                assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/change-password-user")

        # --- pug_js ---

        def test_pug_extends_user_path(self):
                code = """
const pug = require('pug');

app.post('/render', (req, res) => {
    const html = pug.render('extends ' + req.body.layout + '\\nblock content\\n  p Hello');
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/extends-user-path")

        def test_pug_render_json_user_locals(self):
                code = """
const pug = require('pug');

app.post('/render', (req, res) => {
    const template = 'p= name';
    const html = pug.render(template, req.body);
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/render-json-user-locals")

        def test_pug_compile_globals_user(self):
                code = """
const pug = require('pug');

app.post('/compile', (req, res) => {
    const fn = pug.compile('p= x', { globals: req.body.globals });
    res.send(fn({ x: 'hi' }));
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/compile-globals-user")

        def test_pug_res_render_layout_user(self):
                code = """
const pug = require('pug');

app.get('/page', (req, res) => {
    res.render('view', { title: 'X', layout: req.query.layout });
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/res-render-layout-user")

        def test_pug_render_selfclosing_user(self):
                code = """
const pug = require('pug');

app.post('/render', (req, res) => {
    const html = pug.render('p Hello', { selfClosingTags: req.query.selfClose });
    res.send(html);
});
"""
                assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/render-selfclosing-user")

        # --- prototype_pollution_js ---

        def test_proto_qs_parse_allowproto(self):
                code = """
const qs = require('qs');

app.post('/parse', (req, res) => {
    const parsed = qs.parse(req.rawBody, { allowPrototypes: true });
    res.json(parsed);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/qs-parse-allowproto")

        def test_proto_hoek_merge_req(self):
                code = """
const Hoek = require('@hapi/hoek');

app.post('/merge', (req, res) => {
    const merged = Hoek.merge(config, req.body);
    res.json(merged);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/hoek-merge-req")

        def test_proto_immer_produce_req(self):
                code = """
const { produce } = require('immer');

app.post('/update', (req, res) => {
    const next = produce(state, req.body.recipe);
    res.json(next);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/immer-produce-req")

        def test_proto_mixin_req_body(self):
                code = """
const mixin = require('mixin-deep');

app.post('/config', (req, res) => {
    const result = mixin(obj, req.body);
    res.json(result);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/mixin-req-body")

        def test_proto_object_entries_reduce_req(self):
                code = """
const _ = require('lodash');

app.post('/build', (req, res) => {
    const result = Object.entries(req.body).reduce((acc, [k, v]) => { acc[k] = v; return acc; }, {});
    res.json(result);
});
"""
                assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/object-entries-reduce-req")

        # --- archive_extraction_py ---

        def test_archive_patoolib_extract_user(self):
                code = """
import patoolib

def extract_archive(user_path):
        patoolib.extract_archive(user_path, outdir='/tmp/out')
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/patoolib-extract-user")

        def test_archive_py7zr_extract_user(self):
                code = """
import py7zr

def extract_7z(user_dest):
        with py7zr.SevenZipFile('archive.7z') as archive:
                archive.extractall(path=user_dest)
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/py7zr-extract-user")

        def test_archive_zipfile_extract_user_dest(self):
                code = """
import zipfile

def extract_member(user_dest):
        with zipfile.ZipFile('u.zip') as zf:
                zf.extract(member, user_dest)
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-extract-user-dest")

        def test_archive_rarfile_extract_user(self):
                code = """
import rarfile

def extract_rar(user_path):
        with rarfile.RarFile(user_path) as rf:
                rf.extractall('/tmp/out')
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/rarfile-extract-user")

        def test_archive_bz2_open_user(self):
                code = """
import bz2

def read_bz2(user_path):
        with bz2.open(user_path, 'rb') as f:
                return f.read()
"""
                assert _has_rule(code, "python", "archive.py", "registry/python/archive/bz2-open-user")


class TestPhase12RegistryExpansion:
    """20 new rules across ldap_js (+5), pug_js (+5), prototype_pollution_js (+5), archive_extraction_py (+5) (920→940)."""

    # --- ldap_js ---

    def test_ldap_search_base_user(self):
        code = """
const ldap = require('ldapjs');

app.get('/search', (req, res) => {
    client.search(req.query.base, { filter: '(uid=admin)' }, () => {});
    res.json({ ok: true });
});
"""
        assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/search-base-user")

    def test_ldap_add_entry_user(self):
        code = """
const ldap = require('ldapjs');

app.post('/add', (req, res) => {
    const dn = 'cn=new,dc=example,dc=com';
    ldapClient.add(dn, req.body, () => res.json({ ok: true }));
});
"""
        assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/add-entry-user")

    def test_ldap_control_oid_user(self):
        code = """
const ldap = require('ldapjs');

app.post('/control', (req, res) => {
    const ctrl = new ldap.Control({ type: req.body.oid, criticality: true });
    client.search('dc=example,dc=com', { controls: [ctrl] }, () => {});
    res.json({ ok: true });
});
"""
        assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/control-oid-user")

    def test_ldap_client_options_timeout_user(self):
        code = """
const ldap = require('ldapjs');

app.post('/connect', (req, res) => {
    const client = ldap.createClient({ url: 'ldap://srv', connectTimeout: req.body.timeout });
    res.json({ ok: !!client });
});
"""
        assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/client-options-timeout-user")

    def test_ldap_password_reset_target_user(self):
        code = """
const ldap = require('ldapjs');

app.post('/reset', (req, res) => {
    resetPassword(req.body.dn, req.body.newPass, () => res.json({ ok: true }));
});
"""
        assert _has_rule(code, "javascript", "ldap.js", "registry/js/ldap/password-reset-target-user")

    # --- pug_js ---

    def test_pug_res_locals_user_all(self):
        code = """
const pug = require('pug');

app.post('/page', (req, res) => {
    res.locals = req.body;
    res.render('profile');
});
"""
        assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/res-locals-user-all")

    def test_pug_renderfile_options_user(self):
        code = """
const pug = require('pug');

app.post('/render', (req, res) => {
    const html = pug.renderFile(viewPath, req.body);
    res.send(html);
});
"""
        assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/renderfile-options-user")

    def test_pug_compile_plugins_user(self):
        code = """
const pug = require('pug');

app.post('/compile', (req, res) => {
    const fn = pug.compile('p Hello', { plugins: req.body.plugins });
    res.send(fn({}));
});
"""
        assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/compile-plugins-user")

    def test_pug_render_doctype_user(self):
        code = """
const pug = require('pug');

app.get('/render', (req, res) => {
    const html = pug.render('p Hello', { doctype: req.query.doctype });
    res.send(html);
});
"""
        assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/render-doctype-user")

    def test_pug_compile_inlineruntime_user(self):
        code = """
const pug = require('pug');

app.post('/compile', (req, res) => {
    const fn = pug.compile('p Hello', { inlineRuntimeFunctions: req.body.inline });
    res.send(fn({}));
});
"""
        assert _has_rule(code, "javascript", "pug.js", "registry/express/pug/compile-inlinerunstime-user")

    # --- prototype_pollution_js ---

    def test_proto_klona_deep_req(self):
        code = """
const { klona } = require('klona');

app.post('/clone', (req, res) => {
    const cloned = klona(req.body);
    res.json(cloned);
});
"""
        assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/klona-deep-req")

    def test_proto_merge_deep_req(self):
        code = """
const mergeDeep = require('merge-deep');

app.post('/merge', (req, res) => {
    const merged = mergeDeep(config, req.body);
    res.json(merged);
});
"""
        assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/merge-deep-req")

    def test_proto_json_merge_patch_req(self):
        code = """
const jsonmergepatch = require('json-merge-patch');

app.patch('/state', (req, res) => {
    const updated = jsonmergepatch.apply(state, req.body);
    res.json(updated);
});
"""
        assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/json-merge-patch-req")

    def test_proto_object_fromentries_map_req(self):
        code = """
const _ = require('lodash');

app.post('/build', (req, res) => {
    const result = Object.fromEntries(new Map(req.body.entries));
    res.json(result);
});
"""
        assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/object-fromentries-map-req")

    def test_proto_reflect_set_user_key(self):
        code = """
const _ = require('lodash');

app.post('/prop', (req, res) => {
    Reflect.set(obj, req.body.key, req.body.value);
    res.json({ ok: true });
});
"""
        assert _has_rule(code, "javascript", "proto.js", "registry/js/proto-pollution/reflect-set-user-key")

    # --- archive_extraction_py ---

    def test_archive_gzip_open_user(self):
        code = """
import gzip

def read_gz(user_path):
    with gzip.open(user_path, 'rb') as f:
        return f.read()
"""
        assert _has_rule(code, "python", "archive.py", "registry/python/archive/gzip-open-user")

    def test_archive_lzma_open_user(self):
        code = """
import lzma

def read_lzma(user_path):
    with lzma.open(user_path, 'rb') as f:
        return f.read()
"""
        assert _has_rule(code, "python", "archive.py", "registry/python/archive/lzma-open-user")

    def test_archive_zipfile_testzip_user(self):
        code = """
import zipfile

def test_archive(user_path):
    with zipfile.ZipFile(user_path) as zf:
        bad = zf.testzip()
        return bad
"""
        assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-testzip-user")

    def test_archive_tarfile_open_mode_user(self):
        code = """
import tarfile

def open_tar(request):
    mode = request.args.get('mode', 'r')
    with tarfile.open('archive.tar', mode=request.args.get('mode')) as tar:
        tar.extractall('/tmp/out')
"""
        assert _has_rule(code, "python", "archive.py", "registry/python/archive/tarfile-open-mode-user")

    def test_archive_zipfile_setpassword_user(self):
        code = """
import zipfile

def extract_protected(user_password):
    with zipfile.ZipFile('secret.zip') as zf:
        zf.setpassword(user_password)
        zf.extractall('/tmp/out')
"""
        assert _has_rule(code, "python", "archive.py", "registry/python/archive/zipfile-setpassword-user")


class TestPhase13RegistryExpansion:
    """20 new rules across aiohttp_web (+5), api_security (+5), celery (+5), tornado_web (+5) (940→960)."""

    # --- aiohttp_web ---

    def test_aiohttp_client_post_user_url(self):
        code = """
import aiohttp

async def proxy(request):
    async with aiohttp.ClientSession() as session:
        return await session.post(request.query.get('target'))
"""
        assert _has_rule(code, "python", "aio.py", "registry/aiohttp/ssrf/client-post-user-url")

    def test_aiohttp_http_temporary_redirect_user(self):
        code = """
from aiohttp import web

def jump(request):
    raise web.HTTPTemporaryRedirect(location=request.query.get('next'))
"""
        assert _has_rule(code, "python", "aio.py", "registry/aiohttp/redirect/httptemporaryredirect-user")

    def test_aiohttp_content_disposition_user(self):
        code = """
from aiohttp import web

def download(request):
    response = web.Response(text='ok')
    response.headers['Content-Disposition'] = request.query.get('filename')
    return response
"""
        assert _has_rule(code, "python", "aio.py", "registry/aiohttp/header/content-disposition-user")

    def test_aiohttp_orjson_loads_request(self):
        code = """
import orjson

async def parse(request):
    payload = orjson.loads(await request.read())
    return payload
"""
        assert _has_rule(code, "python", "aio.py", "registry/aiohttp/deserialization/orjson-loads-request")

    def test_aiohttp_open_user_path(self):
        code = """
def read_file(request):
    with open(request.query.get('path'), 'rb') as f:
        return f.read()
"""
        assert _has_rule(code, "python", "aio.py", "registry/aiohttp/path/open-user-path")

    # --- api_security ---

    def test_api_flask_secret_key_hardcoded(self):
        code = """
SECRET_KEY = 'supersecretkey123456'
"""
        assert _has_rule(code, "python", "api.py", "registry/python/api/flask-secret-key-hardcoded")

    def test_api_cors_origin_reflection(self):
        code = """
from flask import request
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

def set_headers(response):
    response.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin')
    return response
"""
        assert _has_rule(code, "python", "api.py", "registry/python/api/cors-origin-reflection")

    def test_api_jwt_decode_no_algorithms(self):
        code = """
import jwt
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

def parse(token, key):
    return jwt.decode(token, key)
"""
        assert _has_rule(code, "python", "api.py", "registry/python/api/jwt-decode-no-algorithms")

    def test_api_session_cookie_secure_false(self):
        code = """
SESSION_COOKIE_SECURE = False
"""
        assert _has_rule(code, "python", "api.py", "registry/python/api/session-cookie-secure-false")

    def test_api_jwt_audience_verification_disabled(self):
        code = """
import jwt
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

def parse(token, key):
    return jwt.decode(token, key, options={'verify_aud': False})
"""
        assert _has_rule(code, "python", "api.py", "registry/python/api/jwt-audience-verification-disabled")

    # --- celery ---

    def test_celery_subprocess_shell_true(self):
        code = """
import subprocess
from celery import Celery

app = Celery('x')

@app.task
def task(task_arg):
    return subprocess.run(task_arg, shell=True)
"""
        assert _has_rule(code, "python", "tasks.py", "registry/celery/task/subprocess-shell-true")

    def test_celery_requests_verify_false(self):
        code = """
import requests
from celery import Celery

app = Celery('x')

@app.task
def task(url):
    return requests.get(url, verify=False)
"""
        assert _has_rule(code, "python", "tasks.py", "registry/celery/task/requests-verify-false")

    def test_celery_broker_redis_no_tls(self):
        code = """
broker_url = 'redis://localhost:6379/0'
"""
        assert _has_rule(code, "python", "celeryconfig.py", "registry/celery/broker/redis-no-tls")

    def test_celery_dill_serializer(self):
        code = """
CELERY_TASK_SERIALIZER = 'dill'
"""
        assert _has_rule(code, "python", "celeryconfig.py", "registry/celery/deserialization/dill-serializer")

    def test_celery_importlib_user_module(self):
        code = """
import importlib
from celery import Celery

app = Celery('x')

@app.task
def task(task_arg):
    mod = importlib.import_module(task_arg)
    return mod
"""
        assert _has_rule(code, "python", "tasks.py", "registry/celery/task/importlib-user-module")

    # --- tornado_web ---

    def test_tornado_check_xsrf_cookie_disabled(self):
        code = """
check_xsrf_cookie = False
"""
        assert _has_rule(code, "python", "tornado.py", "registry/tornado/auth/check-xsrf-cookie-disabled")

    def test_tornado_set_header_injection(self):
        code = """
class Handler:
    def get(self):
        self.set_header('X-Result', self.get_argument('value'))
"""
        assert _has_rule(code, "python", "tornado.py", "registry/tornado/header/injection-set-header")

    def test_tornado_render_string_user(self):
        code = """
class Handler:
    def get(self):
        return self.render_string(self.get_argument('tpl'))
"""
        assert _has_rule(code, "python", "tornado.py", "registry/tornado/template/render-string-user")

    def test_tornado_secure_cookie_false(self):
        code = """
class Handler:
    def get(self):
        self.set_secure_cookie('sid', 'abc', secure=False)
"""
        assert _has_rule(code, "python", "tornado.py", "registry/tornado/session/secure-cookie-false")

    def test_tornado_os_remove_user(self):
        code = """
import os

class Handler:
    def post(self):
        os.remove(self.get_argument('path'))
"""
        assert _has_rule(code, "python", "tornado.py", "registry/tornado/path/os-remove-user")


class TestPhase14RegistryExpansion:
    """20 new rules across graphql_py (+5), jwt_py (+5), redis_py (+5), requests_lib (+5) (960->980)."""

    # --- graphql_py ---

    def test_graphql_command_injection_resolver(self):
        code = """
import graphene
import subprocess

class Query(graphene.ObjectType):
    result = graphene.String(cmd=graphene.String())

    def resolve_result(root, info, cmd):
        return subprocess.run(info.context.get('cmd'), shell=True)
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/command-injection-resolver")

    def test_graphql_debug_mode_production(self):
        code = """
import graphene

class Query(graphene.ObjectType):
    name = graphene.String()

schema = graphene.Schema(query=Query, debug=True)
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/debug-mode-production")

    def test_graphql_open_redirect_resolver(self):
        code = """
import graphene
from werkzeug.utils import redirect

class Mutation(graphene.Mutation):
    class Arguments:
        url = graphene.String()

    def mutate(root, info, url):
        return redirect(info.context.get('next'))
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/open-redirect-resolver")

    def test_graphql_xxe_xml_arg(self):
        code = """
import graphene
from lxml import etree

class Query(graphene.ObjectType):
    result = graphene.String(xml=graphene.String())

    def resolve_result(root, info, xml):
        return etree.fromstring(info.context.get('xml'))
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/xxe-xml-arg")

    def test_graphql_log_sensitive_arg(self):
        code = """
import graphene
import logging

logger = logging.getLogger(__name__)

class Mutation(graphene.Mutation):
    class Arguments:
        password = graphene.String()

    def mutate(root, info, password):
        logger.info(info.context.get("password"))
        return Mutation()
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/log-sensitive-arg")

    # --- jwt_py ---

    def test_jwt_rsa_private_key_hardcoded(self):
        code = """
import jwt

PRIVATE_KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5TNJT
-----END RSA PRIVATE KEY-----\"\"\"

token = jwt.encode({'sub': 'user'}, PRIVATE_KEY, algorithm='RS256')
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/rsa-private-key-hardcoded")

    def test_jwt_kid_sql_injection(self):
        code = """
import jwt

def get_key(token):
    header = jwt.get_unverified_header(token)
    cursor.execute(f"SELECT * FROM keys WHERE id = {header['kid']}")
    row = cursor.fetchone()
    return row['key']
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/kid-sql-injection")

    def test_jwt_debug_log_payload(self):
        code = """
import jwt
import logging

logger = logging.getLogger(__name__)

def parse_token(token, secret):
    payload = logger.debug(jwt.decode(token, secret, algorithms=['HS256']))
    return payload
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/debug-log-payload")

    def test_jwt_token_in_query_param(self):
        code = """
import jwt
from flask import request

def get_user():
    token = request.args.get('token')
    return jwt.decode(token, SECRET, algorithms=['HS256'])
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/token-in-query-param")

    def test_jwt_token_in_session_insecure(self):
        code = """
import jwt
from flask import session

def login(user):
    session['token'] = jwt.encode({'sub': user}, SECRET, algorithm='HS256')
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/token-in-session-insecure")

    # --- redis_py ---

    def test_redis_yaml_unsafe_get(self):
        code = """
import redis
import yaml

r = redis.Redis(host='localhost')

def load_config(key):
    return yaml.load(r.get(key))
"""
        assert _has_rule(code, "python", "cache.py", "registry/redis/deserialization/yaml-unsafe-get")

    def test_redis_zadd_user_score(self):
        code = """
import redis
from flask import request

r = redis.Redis(host='localhost')

def add_score(user_key):
    r.zadd(user_key, {'score': 100})
"""
        assert _has_rule(code, "python", "cache.py", "registry/redis/injection/zadd-user-score")

    def test_redis_cluster_no_ssl(self):
        code = """
import redis
from redis.cluster import RedisCluster

startup_nodes = [{"host": "redis.example.com", "port": "7000"}]
r = RedisCluster(host="redis.example.com", port=7000)
"""
        assert _has_rule(code, "python", "cache.py", "registry/redis/auth/cluster-no-ssl")

    def test_redis_pipeline_user_cmd(self):
        code = """
import redis
from flask import request

r = redis.Redis(host='localhost')

def batch_ops():
    with r.pipeline() as pipe:
        pipe.execute_command(user_cmd, user_arg)
"""
        assert _has_rule(code, "python", "cache.py", "registry/redis/injection/pipeline-user-cmd")

    def test_redis_unencrypted_pii_hset(self):
        code = """
import redis

r = redis.Redis(host='localhost')

def store_user(email, password):
    r.hset("user", "password", password)
"""
        assert _has_rule(code, "python", "cache.py", "registry/redis/storage/unencrypted-pii-hset")

    # --- requests_lib ---

    def test_requests_httpx_get_user_url(self):
        code = """
import httpx
from flask import request

def fetch():
    user_url = request.args.get('url')
    return httpx.get(user_url)
"""
        assert _has_rule(code, "python", "client.py", "registry/requests/ssrf/httpx-get-user-url")

    def test_requests_oauth_token_logged(self):
        code = """
import requests
import logging

logger = logging.getLogger(__name__)

def get_token(code):
    r = requests.post(TOKEN_URL, data={'code': code})
    access_token = r.json()['access_token']
    logger.debug(access_token)
    return access_token
"""
        assert _has_rule(code, "python", "client.py", "registry/requests/auth/oauth-token-logged")

    def test_requests_urllib3_user_url(self):
        code = """
import requests
import urllib3

http = urllib3.PoolManager()

def fetch(user_url):
    resp = http.request("GET", user_url)
    return resp.data
"""
        assert _has_rule(code, "python", "client.py", "registry/requests/ssrf/urllib3-user-url")

    def test_requests_xml_response_xxe(self):
        code = """
import requests
import lxml.etree

def parse_feed(url):
    response = requests.get(url)
    return lxml.etree.fromstring(response.content)
"""
        assert _has_rule(code, "python", "client.py", "registry/requests/response/xml-response-xxe")

    def test_requests_no_hostname_check(self):
        code = """
import requests
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
"""
        assert _has_rule(code, "python", "client.py", "registry/requests/tls/no-hostname-check")


class TestPhase15RegistryExpansion:
    """Final 20 rules across graphql_py (+5), jwt_py (+5), pymongo (+5), template_engines_py (+5) (980->1000)."""

    # --- graphql_py ---

    def test_graphql_graphiql_enabled(self):
        code = """
import graphene

class Query(graphene.ObjectType):
    ping = graphene.String()

app = GraphQL(schema=graphene.Schema(query=Query), graphiql=True)
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/graphiql-enabled")

    def test_graphql_mutation_mass_assignment(self):
        code = """
import graphene

class Mutation(graphene.Mutation):
    class Arguments:
        payload = graphene.JSONString()

    def mutate(root, info, payload):
        return User.update(**info.context)
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/mutation-mass-assignment")

    def test_graphql_yaml_load_user_arg(self):
        code = """
import graphene
import yaml

class Query(graphene.ObjectType):
    result = graphene.String(data=graphene.String())

    def resolve_result(root, info, data):
        return yaml.load(info.context.get('yaml'))
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/yaml-load-user-arg")

    def test_graphql_pickle_loads_user_arg(self):
        code = """
import graphene
import pickle

class Query(graphene.ObjectType):
    result = graphene.String(blob=graphene.String())

    def resolve_result(root, info, blob):
        return pickle.loads(info.context.get('blob'))
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/pickle-loads-user-arg")

    def test_graphql_exec_user_arg(self):
        code = """
import graphene

class Query(graphene.ObjectType):
    result = graphene.String(code=graphene.String())

    def resolve_result(root, info, code):
        exec(info.context.get('code'))
        return 'ok'
"""
        assert _has_rule(code, "python", "schema.py", "registry/python/graphql/exec-user-arg")

    # --- jwt_py ---

    def test_jwt_pyjwkclient_user_url(self):
        code = """
import jwt
from jwt import PyJWKClient
from flask import request

def verifier():
    client = PyJWKClient(request.args.get('jwks'))
    return client
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/pyjwkclient-user-url")

    def test_jwt_verify_issuer_disabled(self):
        code = """
import jwt

def parse(token, key):
    return jwt.decode(token, key, algorithms=['RS256'], options={'verify_iss': False})
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/verify-issuer-disabled")

    def test_jwt_verify_nbf_disabled(self):
        code = """
import jwt

def parse(token, key):
    return jwt.decode(token, key, algorithms=['RS256'], options={'verify_nbf': False})
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/verify-nbf-disabled")

    def test_jwt_decode_complete_no_verify(self):
        code = """
import jwt

def parse(token):
    return jwt.api_jwt.decode_complete(token, options={'verify_signature': False})
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/decode-complete-no-verify")

    def test_jwt_short_secret_key(self):
        code = """
import jwt

SECRET_KEY = 'abc123'

def make(user):
    return jwt.encode({'sub': user}, SECRET_KEY, algorithm='HS256')
"""
        assert _has_rule(code, "python", "auth.py", "registry/python/jwt/short-secret-key")

    # --- pymongo ---

    def test_pymongo_find_one_and_update_user(self):
        code = """
import pymongo
from flask import request

collection = pymongo.MongoClient().db.users

def update_user():
    return collection.find_one_and_update(request.json.get('filter'), request.json.get('update'))
"""
        assert _has_rule(code, "python", "db.py", "registry/pymongo/nosqli/find-one-and-update-user")

    def test_pymongo_bson_decode_user(self):
        code = """
import pymongo
import bson
from flask import request

def parse_blob():
    return bson.BSON(request.data).decode()
"""
        assert _has_rule(code, "python", "db.py", "registry/pymongo/deserialization/bson-decode-user")

    def test_pymongo_tls_insecure_options(self):
        code = """
import pymongo

client = pymongo.MongoClient('mongodb://localhost:27017', tlsAllowInvalidCertificates=True)
"""
        assert _has_rule(code, "python", "db.py", "registry/pymongo/auth/tls-insecure-options")

    def test_pymongo_find_one_user_return(self):
        code = """
import pymongo
from flask import request

collection = pymongo.MongoClient().db.users

def get_user():
    return collection.find_one(request.args)
"""
        assert _has_rule(code, "python", "db.py", "registry/pymongo/exposure/find-one-user-return")

    def test_pymongo_sort_user_field(self):
        code = """
import pymongo
from flask import request

collection = pymongo.MongoClient().db.users

def list_users():
    return collection.find({}).sort(request.args.get('field'))
"""
        assert _has_rule(code, "python", "db.py", "registry/pymongo/nosqli/sort-user-field")

    # --- template_engines_py ---

    def test_template_jinja2_autoescape_disabled(self):
        code = """
import jinja2

env = jinja2.Environment(autoescape=False)
"""
        assert _has_rule(code, "python", "tpl.py", "registry/python/template/jinja2-autoescape-disabled")

    def test_template_flask_render_template_string_fstring(self):
        code = """
from flask import request, render_template_string

def preview():
    return render_template_string(f"<p>{request.args.get('content')}</p>")
"""
        assert _has_rule(code, "python", "tpl.py", "registry/python/template/flask-render-template-string-fstring")

    def test_template_mako_lookup_user_directory(self):
        code = """
import mako
from mako.lookup import TemplateLookup
from flask import request

lookup = TemplateLookup(directories=[request.args.get('templates_dir')])
"""
        assert _has_rule(code, "python", "tpl.py", "registry/python/template/mako-templatelookup-user-directory")

    def test_template_django_mark_safe_user(self):
        code = """
import jinja2
from django.utils.safestring import mark_safe
from flask import request

def render_user():
    return mark_safe(request.args.get('html'))
"""
        assert _has_rule(code, "python", "tpl.py", "registry/python/template/django-mark-safe-user")

    def test_template_jinja2_finalize_markup_user(self):
        code = """
import jinja2
from markupsafe import Markup

env = jinja2.Environment(finalize=Markup)
"""
        assert _has_rule(code, "python", "tpl.py", "registry/python/template/jinja2-finalize-markup-user")

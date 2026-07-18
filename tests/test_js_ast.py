from __future__ import annotations

import json

from guardmarly.js_ast_analyzer import analyze_js_ast


class TestJsAstAnalyzer:
  def test_sourcemap_source_root_remaps_findings(self, tmp_path):
    bundle_file = tmp_path / "bundle.js"
    map_file = tmp_path / "bundle.js.map"

    bundle_file.write_text(
      "document.write(req.query.html);\n//# sourceMappingURL=bundle.js.map\n",
      encoding="utf-8",
    )
    map_file.write_text(
      json.dumps({
        "version": 3,
        "file": "bundle.js",
        "sourceRoot": "src",
        "sources": ["app.ts"],
        "names": [],
        "mappings": "AAAA",
      }),
      encoding="utf-8",
    )

    result = analyze_js_ast(bundle_file.read_text(encoding="utf-8"), filename=str(bundle_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-002")

    assert "[source-mapped]" in finding.title
    assert "src/app.ts:1" in finding.description

  def test_adjacent_minified_sidecar_map_is_found_without_comment(self, tmp_path):
    bundle_file = tmp_path / "bundle.min.js"
    map_file = tmp_path / "bundle.min.js.map"

    bundle_file.write_text("document.write(req.query.html);\n", encoding="utf-8")
    map_file.write_text(
      json.dumps({
        "version": 3,
        "file": "bundle.min.js",
        "sources": ["src/original.js"],
        "names": [],
        "mappings": "AAAA",
      }),
      encoding="utf-8",
    )

    result = analyze_js_ast(bundle_file.read_text(encoding="utf-8"), filename=str(bundle_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-002")

    assert "[source-mapped]" in finding.title
    assert "original.js:1" in finding.description

  def test_sourcemap_comment_is_case_insensitive(self, tmp_path):
    bundle_file = tmp_path / "bundle.js"
    map_file = tmp_path / "bundle.js.map"

    bundle_file.write_text(
      "document.write(req.query.html);\n//# sOuRcEMaPpInGURL=bundle.js.map\n",
      encoding="utf-8",
    )
    map_file.write_text(
      json.dumps({
        "version": 3,
        "file": "bundle.js",
        "sources": ["src/cased.ts"],
        "names": [],
        "mappings": "AAAA",
      }),
      encoding="utf-8",
    )

    result = analyze_js_ast(bundle_file.read_text(encoding="utf-8"), filename=str(bundle_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-002")

    assert "[source-mapped]" in finding.title
    assert "cased.ts:1" in finding.description

  def test_inline_base64_sourcemap_remaps_findings(self, tmp_path):
    bundle_file = tmp_path / "bundle.inline.js"
    import base64 as _b64
    sourcemap_json = json.dumps({
        "version": 3,
        "file": "bundle.inline.js",
        "sources": ["src/from-inline.ts"],
        "names": [],
        "mappings": "AAAA",
    })
    b64 = _b64.b64encode(sourcemap_json.encode()).decode()
    data_url = f"data:application/json;charset=utf-8;base64,{b64}"
    bundle_file.write_text(
        f"document.write(req.query.html);\n//# sourceMappingURL={data_url}\n",
        encoding="utf-8",
    )

    result = analyze_js_ast(bundle_file.read_text(encoding="utf-8"), filename=str(bundle_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-002")

    assert "[source-mapped]" in finding.title
    assert "from-inline.ts:1" in finding.description

  def test_helper_return_redirect_used_directly_in_sink_is_detected(self, tmp_path):
    helper_file = tmp_path / "redirects.js"
    app_file = tmp_path / "app.js"

    helper_file.write_text(
      """
export function computeRedirect(req) {
  return req.query.next;
}
""",
      encoding="utf-8",
    )
    app_code = """
import { computeRedirect } from './redirects';

app.get('/logout', (req, res) => {
  res.redirect(computeRedirect(req));
});
"""
    app_file.write_text(app_code, encoding="utf-8")

    result = analyze_js_ast(app_code, filename=str(app_file))
    finding = next(
      finding
      for finding in result.findings
      if finding.rule_id == "JS-039"
    )

    labels = [frame.label for frame in finding.trace]
    assert any(label == "through `computeRedirect()`" for label in labels)
    assert labels[-1] == "sink `res.redirect()`"

  def test_helper_return_ssrf_used_directly_in_sink_is_detected(self, tmp_path):
    helper_file = tmp_path / "urls.js"
    app_file = tmp_path / "app.js"

    helper_file.write_text(
      """
export function buildWebhookUrl(req) {
  return req.body.targetUrl;
}
""",
      encoding="utf-8",
    )
    app_code = """
import { buildWebhookUrl } from './urls';

async function sendWebhook(req) {
  return await fetch(buildWebhookUrl(req));
}
"""
    app_file.write_text(app_code, encoding="utf-8")

    result = analyze_js_ast(app_code, filename=str(app_file))
    finding = next(
      finding
      for finding in result.findings
      if finding.rule_id == "JS-040"
    )

    labels = [frame.label for frame in finding.trace]
    assert finding.cwe == "CWE-918"
    assert labels[-1] == "sink `HTTP client call`"

  def test_indexed_sourcemap_sections_remap_multiple_lines(self, tmp_path):
    bundle_file = tmp_path / "bundle.js"
    map_file = tmp_path / "bundle.js.map"

    bundle_file.write_text(
      "document.write(req.query.first);\ndocument.write(req.query.second);\n//# sourceMappingURL=bundle.js.map\n",
      encoding="utf-8",
    )
    map_file.write_text(
      json.dumps({
        "version": 3,
        "file": "bundle.js",
        "sections": [
          {
            "offset": {"line": 0, "column": 0},
            "map": {
              "version": 3,
              "sources": ["first.ts"],
              "names": [],
              "mappings": "AAAA",
            },
          },
          {
            "offset": {"line": 1, "column": 0},
            "map": {
              "version": 3,
              "sources": ["second.ts"],
              "names": [],
              "mappings": "AAAA",
            },
          },
        ],
      }),
      encoding="utf-8",
    )

    result = analyze_js_ast(bundle_file.read_text(encoding="utf-8"), filename=str(bundle_file))
    js002_findings = [f for f in result.findings if f.rule_id == "JS-002"]

    assert len(js002_findings) >= 1
    descriptions = "\n".join(f.description for f in js002_findings)
    assert "first.ts:1" in descriptions or "second.ts:1" in descriptions

  def test_sourcemap_remap_sets_original_file_field(self, tmp_path):
    """Source-mapped findings must carry the original file path in original_file."""
    bundle_file = tmp_path / "bundle.js"
    map_file = tmp_path / "bundle.js.map"

    bundle_file.write_text(
      "document.write(req.query.html);\n//# sourceMappingURL=bundle.js.map\n",
      encoding="utf-8",
    )
    map_file.write_text(
      json.dumps({
        "version": 3,
        "file": "bundle.js",
        "sources": ["src/app.ts"],
        "names": [],
        "mappings": "AAAA",
      }),
      encoding="utf-8",
    )

    result = analyze_js_ast(bundle_file.read_text(encoding="utf-8"), filename=str(bundle_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-002")

    assert "[source-mapped]" in finding.title
    assert finding.original_file.endswith("app.ts")
    d = finding.as_dict()
    assert "original_file" in d
    assert d["original_file"].endswith("app.ts")

  def test_sourcemap_remap_sets_trace_frame_file_path(self, tmp_path):
    """Source-mapped trace frames must carry file_path for the original source."""
    from guardmarly._types import Finding, TraceFrame, Severity
    from guardmarly.js_engine.source_map_resolver import remap_findings_to_source_map

    map_file = tmp_path / "bundle.js.map"
    map_file.write_text(
      json.dumps({
        "version": 3,
        "file": "bundle.js",
        "sources": ["src/views.ts"],
        "names": [],
        "mappings": "AAAA",
      }),
      encoding="utf-8",
    )
    bundle_file = tmp_path / "bundle.js"
    bundle_file.write_text(
      "document.write(req.query.html);\n//# sourceMappingURL=bundle.js.map\n",
      encoding="utf-8",
    )

    # Use a finding that has trace frames (as produced by the structural checker)
    finding = Finding(
      category="security",
      severity=Severity.CRITICAL,
      title="XSS via document.write()",
      description="test",
      line=1,
      rule_id="JS-002",
      cwe="CWE-79",
      agent="js-ast-analyzer",
      confidence=0.96,
      analysis_kind="syntax-ast",
      trace=(
        TraceFrame(kind="source", label="source `req.query.html`", line=1),
        TraceFrame(kind="sink", label="sink `document.write()`", line=1),
      ),
    )

    remapped = remap_findings_to_source_map([finding], str(bundle_file))
    assert len(remapped) == 1
    f = remapped[0]
    assert "[source-mapped]" in f.title
    assert f.original_file.endswith("views.ts")

    # Every trace frame at the remapped line must carry the original file path
    frame_paths = [frame.file_path for frame in f.trace if frame.file_path]
    assert len(frame_paths) >= 1
    assert all(p.endswith("views.ts") for p in frame_paths)

    # as_dict() must expose file_path when set
    frame_dicts = [frame.as_dict() for frame in f.trace]
    assert any("file_path" in fd for fd in frame_dicts)

  def test_non_sourcemapped_finding_has_empty_original_file(self):
    """Non-minified findings with no source map must have empty original_file."""
    code = "document.write(req.query.html);\n"
    result = analyze_js_ast(code)
    finding = next((f for f in result.findings if f.rule_id == "JS-002"), None)
    if finding:
      assert finding.original_file == ""
      d = finding.as_dict()
      assert "original_file" not in d  # omitted when empty

    def test_react_create_element_dangerous_html_detected_structurally(self):
        code = """
function UserBio(props) {
  return React.createElement('div', {
    className: 'bio',
    dangerouslySetInnerHTML: { __html: props.bio }
  });
}
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-003" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-79"
        assert labels[0] == "react prop `props.bio`"
        assert labels[-1] == "sink `React.createElement dangerouslySetInnerHTML`"

    def test_jsx_prop_bag_dangerous_html_detected_structurally(self):
        code = """
function UserBio({ bio }) {
  const htmlProps = { __html: bio };
  return <section dangerouslySetInnerHTML={htmlProps} />;
}
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-003" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert any(label == "through prop bag `htmlProps`" for label in labels)
        assert labels[-1] == "sink `dangerouslySetInnerHTML`"

    def test_multiline_sql_template_detected_structurally(self):
        code = """
const id = req.query.id;
await db.query(
  `SELECT * FROM users
   WHERE id = '${id}'`
);
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-010" and finding.agent == "js-ast-analyzer"
        )

        assert finding.cwe == "CWE-89"
        assert finding.analysis_kind == "syntax-ast"
        assert any(frame.kind == "source" for frame in finding.trace)
        assert finding.trace[-1].label == "sink `db.query()`"

    def test_multiline_shell_true_detected_structurally(self):
        code = """
const { spawn } = require('child_process');
spawn(
  'tar',
  ['-czf', 'archive.tgz', req.query.path],
  {
    cwd: '/tmp',
    shell: true,
  }
);
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-008" and finding.agent == "js-ast-analyzer"
        )

        assert finding.cwe == "CWE-78"
        assert finding.analysis_kind == "syntax-ast"

    def test_multiline_innerhtml_assignment_detected_structurally(self):
        code = """
const name = req.query.name;
document.getElementById('greeting').innerHTML =
  `<p>${name}</p>`;
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-059" and finding.agent == "js-ast-analyzer"
        )

        assert finding.cwe == "CWE-79"
        assert any(frame.kind == "source" for frame in finding.trace)
        assert finding.trace[-1].label == "sink `.innerHTML`"

    def test_multiline_ssrf_alias_chain_detected_structurally(self):
        code = """
const targetUrl = req.body.targetUrl;
const finalUrl = buildWebhookUrl(targetUrl);
await fetch(
  finalUrl,
  { method: 'POST' }
);
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-040" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-918"
        assert labels[0].startswith("source `req.body.targetUrl`")
        assert labels[-1] == "sink `HTTP client call`"

    def test_object_route_missing_auth_detected_structurally(self):
        code = """
fastify.route({
  method: 'GET',
  url: '/admin/users',
  handler: async (request, reply) => {
    const users = await User.findAll();
    reply.send(users);
  }
});
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-034" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-862"
        assert labels[0] == "route `/admin/users` method `GET`"
        assert "no auth middleware detected" in labels
        assert labels[-1] == "admin route reachable without auth"

    def test_object_route_auth_without_role_guard_detected_structurally(self):
        code = """
fastify.route({
  method: 'GET',
  url: '/admin/users',
  preHandler: [requireAuth],
  handler: async (request, reply) => {
    const users = await User.findAll();
    reply.send(users);
  }
});
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-035" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-285"
        assert "auth middleware `requireAuth`" in labels
        assert "no privilege guard detected" in labels
        assert labels[-1] == "admin route reachable after auth only"

    def test_object_route_idor_detected_structurally(self):
        code = """
fastify.route({
  method: 'GET',
  url: '/accounts/:accountId',
  preHandler: [requireAuth],
  handler: async (request, reply) => {
    const accountId = request.params.accountId;
    const account = await Account.findByPk(accountId);
    reply.send(account);
  }
});
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-033" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-639"
        assert "resource parameter `accountId`" in labels
        assert "auth middleware `requireAuth`" in labels
        assert labels[-1].startswith("resource lookup `const account = await Account.findByPk(accountId)")

    def test_imported_redirect_helper_detected_structurally(self, tmp_path):
        helper_file = tmp_path / "redirect_helper.js"
        app_file = tmp_path / "app.js"
        helper_file.write_text(
            """
export function redirectTo(res, target) {
  return res.redirect(target);
}
""",
            encoding="utf-8",
        )
        app_code = """
import { redirectTo } from './redirect_helper';

app.get('/logout', (req, res) => {
  const next = req.query.next;
  redirectTo(res, next);
});
"""
        app_file.write_text(app_code, encoding="utf-8")

        result = analyze_js_ast(app_code, filename=str(app_file))
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-039" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert any(label == "through `redirectTo()`" for label in labels)
        assert labels[-1] == "sink `res.redirect()`"

    def test_hapi_nested_auth_without_role_guard_detected_structurally(self):
        code = """
server.route({
  method: 'GET',
  path: '/admin/users',
  options: { auth: 'jwt' },
  handler: async (request, h) => {
    const users = await User.findAll();
    return users;
  }
});
"""
        result = analyze_js_ast(code)

        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-035" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-285"
        assert any("auth option `auth`" in label for label in labels)
        assert labels[-1] == "admin route reachable after auth only"

    def test_helper_return_chain_redirect_detected_structurally(self, tmp_path):
        selectors_file = tmp_path / "selectors.js"
        builders_file = tmp_path / "builders.js"
        app_file = tmp_path / "app.js"
        selectors_file.write_text(
            """
export function readNext(req) {
  return req.query.next;
}
""",
            encoding="utf-8",
        )
        builders_file.write_text(
            """
import { readNext } from './selectors';

export function computeRedirect(req) {
  return readNext(req);
}
""",
            encoding="utf-8",
        )
        app_code = """
import { computeRedirect } from './builders';

app.get('/logout', (req, res) => {
  const target = computeRedirect(req);
  res.redirect(target);
});
"""
        app_file.write_text(app_code, encoding="utf-8")

        result = analyze_js_ast(app_code, filename=str(app_file))
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-039" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert any(label == "through `computeRedirect()`" for label in labels)
        assert any(label == "through `readNext()`" for label in labels)
        assert labels[-1] == "sink `res.redirect()`"

    def test_koa_router_use_auth_without_role_guard_detected_structurally(self):
        code = """
const router = new Router();

router.use('/admin', requireAuth);
router.get('/admin/users', async (ctx) => {
  return User.findAll();
});
"""
        result = analyze_js_ast(code)
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-035" and finding.agent == "js-ast-analyzer"
        )

        assert finding.cwe == "CWE-285"
        assert any(frame.label == "auth middleware `requireAuth`" for frame in finding.trace)

    def test_nest_admin_controller_auth_without_role_guard_detected_structurally(self):
        code = """
@Controller('admin')
@UseGuards(AuthGuard('jwt'))
export class AdminController {
  @Get('users')
  async listUsers() {
    return this.userService.findAll();
  }
}
"""
        result = analyze_js_ast(code)
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-035" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-285"
        assert labels[0] == "route `/admin/users` method `GET`"
        assert any("UseGuards" in label or "AuthGuard" in label for label in labels)

    def test_next_app_route_idor_detected_structurally(self, tmp_path):
        route_file = tmp_path / "app" / "api" / "accounts" / "[accountId]" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_code = """
export async function GET(request, { params }) {
  const account = await Account.findByPk(params.accountId);
  return Response.json(account);
}
"""
        route_file.write_text(route_code, encoding="utf-8")

        result = analyze_js_ast(route_code, filename=str(route_file))
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-033" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.cwe == "CWE-639"
        assert labels[0] == "route `/api/accounts/:accountId` method `GET`"
        assert "resource parameter `accountId`" in labels

    def test_hapi_route_missing_auth_detected_structurally(self):
        code = """
const server = Hapi.server();

server.route({
  method: 'GET',
  path: '/admin/users',
  handler: async (request, h) => User.findAll(),
});
"""
        result = analyze_js_ast(code)
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-024" and finding.agent == "js-ast-analyzer"
        )

        assert finding.cwe == "CWE-862"

    def test_graphql_idor_detected_structurally(self):
        code = """
const resolvers = {
  Query: {
    account: async (_parent, args, context) => {
      if (!context.user) throw new Error('auth required');
      return db.account.findUnique({ where: { id: args.id } });
    }
  }
};
const server = new ApolloServer({ resolvers });
"""
        result = analyze_js_ast(code)
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-028" and finding.agent == "js-ast-analyzer"
        )

        assert finding.cwe == "CWE-639"

    def test_reexported_redirect_alias_detected_structurally(self, tmp_path):
        redirect_file = tmp_path / "redirect.js"
        barrel_file = tmp_path / "index.ts"
        app_file = tmp_path / "app.js"

        redirect_file.write_text(
            """
export function redirectTo(res, target) {
  return res.redirect(target);
}
""",
            encoding="utf-8",
        )
        barrel_file.write_text(
            """
export { redirectTo as go } from './redirect';
""",
            encoding="utf-8",
        )
        app_code = """
import { go } from './index';

app.get('/logout', (req, res) => {
  go(res, req.query.next);
});
"""
        app_file.write_text(app_code, encoding="utf-8")

        result = analyze_js_ast(app_code, filename=str(app_file))
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-039" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.analysis_kind == "syntax-ast"
        assert any(label == "through `go()`" for label in labels)
        assert labels[-1] == "sink `res.redirect()`"

    def test_helper_dom_sanitizer_return_suppresses_xss_structurally(self, tmp_path):
        helper_file = tmp_path / "sanitize.js"
        app_file = tmp_path / "app.js"

        helper_file.write_text(
            """
export function sanitizeMarkup(html) {
  return DOMPurify.sanitize(html);
}
""",
            encoding="utf-8",
        )
        app_code = """
import { sanitizeMarkup } from './sanitize';

const raw = req.query.html;
const safe = sanitizeMarkup(raw);
element.innerHTML = safe;
"""
        app_file.write_text(app_code, encoding="utf-8")

        result = analyze_js_ast(app_code, filename=str(app_file))
        assert not any(f.rule_id in {"JS-001", "JS-059"} for f in result.findings)

    def test_nest_controller_service_call_chain_idor_detected_structurally(self, tmp_path):
        service_file = tmp_path / "accounts.service.ts"
        controller_file = tmp_path / "accounts.controller.ts"

        service_file.write_text(
            """
export class AccountsService {
  async loadAccount(accountId) {
    return Account.findByPk(accountId);
  }
}
""",
            encoding="utf-8",
        )
        controller_code = """
import { AccountsService } from './accounts.service';

@Controller('accounts')
@UseGuards(AuthGuard('jwt'))
export class AccountsController {
  constructor(private readonly accountsService: AccountsService) {}

  @Get(':accountId')
  async show(params) {
    return this.load(params.accountId);
  }

  async load(accountId) {
    return this.accountsService.loadAccount(accountId);
  }
}
"""
        controller_file.write_text(controller_code, encoding="utf-8")

        result = analyze_js_ast(controller_code, filename=str(controller_file))
        finding = next(
            finding
            for finding in result.findings
            if finding.rule_id == "JS-033" and finding.agent == "js-ast-analyzer"
        )

        labels = [frame.label for frame in finding.trace]
        assert finding.analysis_kind == "syntax-ast"
        assert any(label == "through `this.load()`" for label in labels)
        assert any(label == "through `this.accountsService.loadAccount()`" for label in labels)

    def test_regex_fallback_findings_are_still_merged(self):
        code = """
app.get('/admin/users', async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
"""
        result = analyze_js_ast(code)

        assert any(finding.rule_id == "JS-034" for finding in result.findings)

    def test_inline_suppression_applies_to_ast_findings(self):
        code = "document.write(req.query.html); // guardmarly: ignore[CWE-79]"
        result = analyze_js_ast(code)

        assert not any(finding.cwe == "CWE-79" for finding in result.findings)

  def test_sarif_codeflow_uses_source_mapped_file_path(self, tmp_path):
    """End-to-end: after source-map remapping, SARIF codeFlow locations must
    reference the original source file, not the bundle path."""
    import json as _json
    from guardmarly._types import Finding, TraceFrame, Severity, AnalysisResult
    from guardmarly.js_engine.source_map_resolver import remap_findings_to_source_map
    from guardmarly.reporters import format_sarif

    bundle_file = tmp_path / "bundle.js"
    map_file = tmp_path / "bundle.js.map"
    bundle_file.write_text(
      "document.write(req.query.html);\n//# sourceMappingURL=bundle.js.map\n",
      encoding="utf-8",
    )
    map_file.write_text(
      _json.dumps({
        "version": 3,
        "file": "bundle.js",
        "sources": ["src/views.ts"],
        "names": [],
        "mappings": "AAAA",
      }),
      encoding="utf-8",
    )

    # Build a structural finding with both source and sink trace frames
    finding = Finding(
      category="security",
      severity=Severity.CRITICAL,
      title="XSS via document.write()",
      description="Unsanitized user input flows to document.write()",
      line=1,
      rule_id="JS-002",
      cwe="CWE-79",
      agent="js-ast-analyzer",
      confidence=0.96,
      analysis_kind="syntax-ast",
      trace=(
        TraceFrame(kind="source", label="source `req.query.html`", line=1),
        TraceFrame(kind="sink", label="sink `document.write()`", line=1),
      ),
    )

    remapped = remap_findings_to_source_map([finding], str(bundle_file))
    assert remapped, "Source-map remapping produced no findings"
    assert remapped[0].trace, "Remapped finding must have trace frames"

    # Wrap in AnalysisResult for format_sarif
    result = AnalysisResult(file_path=str(bundle_file), language="javascript", findings=remapped)

    # Format as SARIF
    sarif_output = format_sarif([result])
    sarif = _json.loads(sarif_output)

    run = sarif["runs"][0]
    result_obj = run["results"][0]
    assert "codeFlows" in result_obj, "SARIF result must contain codeFlows"

    thread_flow = result_obj["codeFlows"][0]["threadFlows"][0]
    locations = thread_flow["locations"]
    assert len(locations) >= 1

    uris = [
      loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
      for loc in locations
    ]
    # Every codeFlow location must resolve to the source file, not the bundle
    assert all("views.ts" in uri for uri in uris), (
      f"Expected all codeFlow URIs to reference 'views.ts', got: {uris}"
    )

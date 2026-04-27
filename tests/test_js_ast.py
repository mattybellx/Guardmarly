from __future__ import annotations

from ansede_static.js_ast_analyzer import analyze_js_ast


class TestJsAstAnalyzer:
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
            if finding.rule_id == "JS-027" and finding.agent == "js-ast-analyzer"
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
        assert not any(f.rule_id in {"JS-001", "JS-027"} for f in result.findings)

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
        code = "document.write(req.query.html); // ansede: ignore[CWE-79]"
        result = analyze_js_ast(code)

        assert not any(finding.cwe == "CWE-79" for finding in result.findings)

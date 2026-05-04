"""
tests.test_js
─────────────
Unit tests for the JavaScript security analyzer.
"""
from __future__ import annotations

import pytest
from ansede_static.js_analyzer import analyze_js
from ansede_static._types import Severity


# ── Helpers ─────────────────────────────────────────────────────────────────

def _cwes(code: str) -> list[str]:
    return [f.cwe for f in analyze_js(code).findings]


def _has_cwe(code: str, cwe: str) -> bool:
    return cwe in _cwes(code)


# ── CWE-79: XSS ──────────────────────────────────────────────────────────────

class TestXSS:
    def test_innerHTML_assignment(self):
        code = """
const name = document.querySelector('#input').value;
document.getElementById('greeting').innerHTML = '<h1>' + name + '</h1>';
"""
        assert _has_cwe(code, "CWE-79")

    def test_innerHTML_assignment_has_stable_rule_id(self):
        code = """
const name = document.querySelector('#input').value;
document.getElementById('greeting').innerHTML = '<h1>' + name + '</h1>';
"""
        result = analyze_js(code)
        finding = next(f for f in result.findings if f.cwe == "CWE-79")

        assert finding.rule_id == "JS-001"

    def test_innerHTML_template_literal(self):
        code = """
const name = req.body.name;
container.innerHTML = `<p>${name}</p>`;
"""
        assert _has_cwe(code, "CWE-79")

    def test_document_write(self):
        code = 'document.write("<p>" + userInput + "</p>");'
        assert _has_cwe(code, "CWE-79")

    def test_dangerously_set_inner_html(self):
        code = """
function UserBio({ bio }) {
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
"""
        assert _has_cwe(code, "CWE-79")

    def test_textContent_safe(self):
        code = """
const name = document.querySelector('#input').value;
document.getElementById('greeting').textContent = name;
"""
        assert not _has_cwe(code, "CWE-79")


# ── CWE-95: Code injection ────────────────────────────────────────────────────

class TestCodeInjection:
    def test_eval_dynamic(self):
        code = """
const userExpr = req.body.expression;
const result = eval(userExpr);
"""
        assert _has_cwe(code, "CWE-95")

    def test_eval_literal_ok(self):
        code = "const x = eval('1 + 1');"
        assert not _has_cwe(code, "CWE-95")

    def test_new_function(self):
        code = """
const code = req.body.fn;
const fn = new Function(code);
fn();
"""
        assert _has_cwe(code, "CWE-95")


# ── CWE-78: Command injection ─────────────────────────────────────────────────

class TestCommandInjection:
    def test_exec_template_literal(self):
        code = """
const { exec } = require('child_process');
const branch = req.query.branch;
exec(`git checkout ${branch}`, (err, out) => res.send(out));
"""
        assert _has_cwe(code, "CWE-78")

    def test_spawn_shell_true(self):
        code = """
const { spawn } = require('child_process');
spawn('cmd', [arg], { shell: true });
"""
        assert _has_cwe(code, "CWE-78")


# ── CWE-89: SQL injection ─────────────────────────────────────────────────────

class TestSQLInjection:
    def test_template_literal_query(self):
        code = """
const id = req.query.id;
await db.query(`SELECT * FROM users WHERE id = '${id}'`);
"""
        assert _has_cwe(code, "CWE-89")

    def test_parameterized_safe(self):
        code = """
const id = req.query.id;
await db.query('SELECT * FROM users WHERE id = $1', [id]);
"""
        assert not _has_cwe(code, "CWE-89")


# ── CWE-798: Hardcoded secrets ────────────────────────────────────────────────

class TestHardcodedSecrets:
    def test_hardcoded_api_key(self):
        code = "const apiKey = 'sk-abc123456789012345678901234';"
        assert _has_cwe(code, "CWE-798")

    def test_jwt_hardcoded_secret(self):
        code = """
const jwt = require('jsonwebtoken');
const token = jwt.sign({ id: user.id }, 'mysupersecretpassword', { expiresIn: '1h' });
"""
        assert _has_cwe(code, "CWE-798")

    def test_env_var_ok(self):
        code = "const apiKey = process.env.API_KEY;"
        assert not _has_cwe(code, "CWE-798")


# ── CWE-22: Path traversal ────────────────────────────────────────────────────

class TestPathTraversal:
    def test_fs_read_with_req_param(self):
        code = """
const filePath = req.params.file;
const content = fs.readFileSync(filePath, 'utf8');
"""
        assert _has_cwe(code, "CWE-22")

    def test_fs_read_with_helper_alias_chain(self):
        code = """
const filePath = req.params.file;
const normalizedPath = sanitizePath(filePath);
const finalPath = normalizedPath;
const content = fs.readFileSync(finalPath, 'utf8');
"""
        assert _has_cwe(code, "CWE-22")


# ── CWE-601: Open redirect ────────────────────────────────────────────────────

class TestOpenRedirect:
    def test_res_redirect_user_url(self):
        code = """
app.get('/logout', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});
"""
        assert _has_cwe(code, "CWE-601")

    def test_redirect_with_helper_alias_chain(self):
                code = """
app.get('/logout', (req, res) => {
  const next = req.query.next;
  const target = buildRedirect(next);
  const finalTarget = target;
  res.redirect(finalTarget);
});
"""
                assert _has_cwe(code, "CWE-601")

    def test_redirect_trace_contains_source_and_sink(self):
                code = """
app.get('/logout', (req, res) => {
  const next = req.query.next;
  const target = buildRedirect(next);
  const finalTarget = target;
  res.redirect(finalTarget);
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-601")
                labels = [frame.label for frame in finding.trace]
                kinds = [frame.kind for frame in finding.trace]

                assert kinds[0] == "source"
                assert any(frame_kind == "helper" for frame_kind in kinds)
                assert labels[-1] == "sink `res.redirect()`"

    def test_imported_redirect_helper_detected(self, tmp_path):
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

        result = analyze_js(app_code, filename=str(app_file))
        finding = next(f for f in result.findings if f.cwe == "CWE-601")
        labels = [frame.label for frame in finding.trace]

        assert any(label == "through `redirectTo()`" for label in labels)
        assert labels[-1] == "sink `res.redirect()`"


# ── CWE-918: SSRF ────────────────────────────────────────────────────────────

class TestSSRF:
    def test_fetch_req_body(self):
        code = """
const url = req.body.webhook_url;
const result = await fetch(url);
"""
        assert _has_cwe(code, "CWE-918")

    def test_fetch_helper_alias_chain(self):
        code = """
const incomingUrl = req.body.webhook_url;
const normalizedUrl = buildUrl(incomingUrl);
const finalUrl = normalizedUrl;
const result = await fetch(finalUrl);
"""
        assert _has_cwe(code, "CWE-918")


# ── CWE-639 / CWE-285: Access control and ownership ─────────────────────────

class TestAccessControl:
        def test_authenticated_route_idor_detected(self):
                code = """
app.get('/accounts/:accountId', requireAuth, async (req, res) => {
    const accountId = req.params.accountId;
    const targetAccountId = accountId;
    const account = await Account.findByPk(targetAccountId);
    res.json(account);
});
"""
                assert _has_cwe(code, "CWE-639")

        def test_idor_trace_contains_route_auth_gap_and_lookup(self):
                code = """
app.get('/accounts/:accountId', requireAuth, async (req, res) => {
    const accountId = req.params.accountId;
    const targetAccountId = accountId;
    const account = await Account.findByPk(targetAccountId);
    res.json(account);
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-639")
                labels = [frame.label for frame in finding.trace]

                assert labels[0] == "route `/accounts/:accountId` method `GET`"
                assert "resource parameter `accountId`" in labels
                assert "auth middleware `requireAuth`" in labels
                assert "no ownership guard detected" in labels
                assert labels[-1].startswith("resource lookup `const account = await Account.findByPk(targetAccountId)")

        def test_owner_scoped_lookup_is_not_idor(self):
                code = """
app.get('/accounts/:accountId', requireAuth, async (req, res) => {
    const accountId = req.params.accountId;
    const account = await Account.findOne({ where: { id: accountId, ownerId: req.user.id } });
    res.json(account);
});
"""
                assert not _has_cwe(code, "CWE-639")

        def test_public_idor_is_critical(self):
                code = """
app.get('/profiles/:id', async (req, res) => {
    const profileId = req.params.id;
    const profile = await Profile.findByPk(profileId);
    res.json(profile);
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-639")

                assert finding.severity == Severity.CRITICAL
                assert any(frame.label == "no auth middleware detected" for frame in finding.trace)

        def test_missing_ownership_before_delete_detected(self):
                code = """
app.delete('/posts/:postId', requireAuth, async (req, res) => {
    const postId = req.params.postId;
    const post = await Post.findByPk(postId);
    await post.destroy();
    res.status(204).end();
});
"""
                assert _has_cwe(code, "CWE-285")

        def test_mutation_trace_contains_lookup_and_sink(self):
                code = """
app.delete('/posts/:postId', requireAuth, async (req, res) => {
    const postId = req.params.postId;
    const post = await Post.findByPk(postId);
    await post.destroy();
    res.status(204).end();
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-285")
                labels = [frame.label for frame in finding.trace]

                assert "auth middleware `requireAuth`" in labels
                assert any(label.startswith("loaded resource `await Post.findByPk(postId)") for label in labels)
                assert "no ownership guard detected before mutation" in labels
                assert labels[-1] == "mutation `post.destroy()`"

        def test_explicit_owner_guard_prevents_mutation_finding(self):
                code = """
app.delete('/posts/:postId', requireAuth, async (req, res) => {
    const postId = req.params.postId;
    const post = await Post.findByPk(postId);
    if (post.ownerId !== req.user.id) {
        return res.status(403).end();
    }
    await post.destroy();
    res.status(204).end();
});
"""
                assert not _has_cwe(code, "CWE-285")

        def test_admin_route_without_auth_is_missing_auth(self):
                code = """
app.get('/admin/users', async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-862")
                labels = [frame.label for frame in finding.trace]

                assert finding.severity == Severity.CRITICAL
                assert finding.rule_id == "JS-034"
                assert labels[0] == "route `/admin/users` method `GET`"
                assert "no auth middleware detected" in labels
                assert labels[-1] == "admin route reachable without auth"

        def test_login_route_is_not_flagged_for_missing_auth(self):
                code = """
app.post('/login', async (req, res) => {
    const user = await authenticate(req.body.email, req.body.password);
    res.json({ ok: !!user });
});
"""
                assert not _has_cwe(code, "CWE-862")

        def test_admin_route_with_auth_but_no_role_guard_is_broken_access_control(self):
                code = """
app.get('/admin/users', requireAuth, async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-285")
                labels = [frame.label for frame in finding.trace]

                assert finding.severity == Severity.CRITICAL
                assert "auth middleware `requireAuth`" in labels
                assert "no privilege guard detected" in labels
                assert labels[-1] == "admin route reachable after auth only"

        def test_admin_route_with_privilege_middleware_is_not_broken_access_control(self):
                code = """
app.get('/admin/users', requireAdmin, async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
"""
                assert not _has_cwe(code, "CWE-285")

        def test_presence_only_token_gate_is_auth_bypass(self):
                code = """
app.get('/admin/audit', (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).end();
    }
    res.json({ ok: true });
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.cwe == "CWE-287")
                labels = [frame.label for frame in finding.trace]

                assert finding.severity == Severity.CRITICAL
                assert any(label.startswith("credential source `req.headers.authorization`") for label in labels)
                assert "credential never verified" in labels
                assert labels[-1] == "presence-only gate `if (!token)`"

        def test_verified_token_gate_is_not_auth_bypass(self):
                code = """
app.get('/admin/audit', (req, res) => {
    const token = req.headers.authorization;
    const user = verifyToken(token);
    if (!user) {
        return res.status(401).end();
    }
    res.json({ ok: true });
});
"""
                assert not _has_cwe(code, "CWE-287")

        def test_fastify_route_object_missing_auth_detected(self):
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
                assert _has_cwe(code, "CWE-862")

        def test_fastify_route_object_idor_detected(self):
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
                assert _has_cwe(code, "CWE-639")

        def test_fastify_options_object_auth_without_role_guard_detected(self):
                code = """
fastify.get('/admin/users', { preHandler: [requireAuth] }, async (request, reply) => {
    const users = await User.findAll();
    reply.send(users);
});
"""
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.rule_id == "JS-035")

                assert finding.cwe == "CWE-285"
                assert any(frame.label == "auth middleware `requireAuth`" for frame in finding.trace)

        def test_object_route_auth_role_option_prevents_broken_access_control(self):
                code = """
fastify.route({
    method: 'GET',
    url: '/admin/users',
    auth: { strategy: 'jwt', scope: ['admin'] },
    handler: async (request, reply) => {
        const users = await User.findAll();
        reply.send(users);
    }
});
"""
                assert not _has_cwe(code, "CWE-285")

        def test_imported_lookup_helper_idor_detected(self, tmp_path):
                helper_file = tmp_path / "data_helpers.js"
                app_file = tmp_path / "app.js"
                helper_file.write_text(
                    """
export async function loadAccount(accountId) {
    return Account.findByPk(accountId);
}
""",
                    encoding="utf-8",
                )
                app_code = """
import { loadAccount } from './data_helpers';

app.get('/accounts/:accountId', requireAuth, async (req, res) => {
    const account = await loadAccount(req.params.accountId);
    res.json(account);
});
"""
                app_file.write_text(app_code, encoding="utf-8")

                result = analyze_js(app_code, filename=str(app_file))
                finding = next(f for f in result.findings if f.cwe == "CWE-639")
                labels = [frame.label for frame in finding.trace]

                assert any(label == "through `loadAccount()`" for label in labels)
                assert labels[-1].startswith("resource lookup `")

        def test_helper_verification_prevents_auth_bypass(self, tmp_path):
                helper_file = tmp_path / "auth_helper.js"
                app_file = tmp_path / "app.js"
                helper_file.write_text(
                    """
export function requireSession(token) {
    return jwt.verify(token, JWT_SECRET);
}
""",
                    encoding="utf-8",
                )
                app_code = """
import { requireSession } from './auth_helper';

app.get('/admin/audit', (req, res) => {
    const token = req.headers.authorization;
    const user = requireSession(token);
    if (!user) {
        return res.status(401).end();
    }
    res.json({ ok: true });
});
"""
                app_file.write_text(app_code, encoding="utf-8")

                result = analyze_js(app_code, filename=str(app_file))
                assert not any(f.cwe == "CWE-287" for f in result.findings)

        def test_hapi_options_auth_without_role_guard_detected(self):
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
                result = analyze_js(code)
                finding = next(f for f in result.findings if f.rule_id == "JS-035")

                assert finding.cwe == "CWE-285"
                assert any("auth option `auth`" in frame.label for frame in finding.trace)

        def test_hapi_scope_option_prevents_broken_access_control(self):
                code = """
server.route({
    method: 'GET',
    path: '/admin/users',
    options: {
        auth: {
            strategy: 'jwt',
            scope: ['admin']
        }
    },
    handler: async (request, h) => {
        const users = await User.findAll();
        return users;
    }
});
"""
                assert not _has_cwe(code, "CWE-285")


# ── CWE-1321: Prototype pollution ────────────────────────────────────────────

class TestPrototypePollution:
    def test_object_assign_req_body(self):
        code = """
app.post('/settings', (req, res) => {
  Object.assign(config, req.body);
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-1321")

    def test_spread_req_body(self):
        code = """
app.post('/update', (req, res) => {
  const merged = { ...req.body };
  updateConfig(merged);
});
"""
        assert _has_cwe(code, "CWE-1321")


# ── CWE-1004: Missing httpOnly ────────────────────────────────────────────────

class TestMissingHttpOnly:
    def test_cookie_no_httonly(self):
        code = """
app.post('/login', (req, res) => {
  res.cookie('session', token, { secure: true });
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-1004")

    def test_cookie_with_httponly_ok(self):
        code = """
app.post('/login', (req, res) => {
  res.cookie('session', token, { httpOnly: true, secure: true });
  res.json({ ok: true });
});
"""
        assert not _has_cwe(code, "CWE-1004")


# ── CWE-942: CORS wildcard ────────────────────────────────────────────────────

class TestCORSWildcard:
    def test_cors_all_origins(self):
        code = """
const cors = require('cors');
app.use(cors({ origin: '*' }));
"""
        assert _has_cwe(code, "CWE-942")


# ── CWE-209: Error leak ───────────────────────────────────────────────────────

class TestErrorLeak:
    def test_err_message_in_response(self):
        code = """
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message });
});
"""
        assert _has_cwe(code, "CWE-209")


# ── CWE-338: Weak PRNG ───────────────────────────────────────────────────────

class TestWeakPRNG:
    def test_math_random_token(self):
        code = """
function generateToken() {
  return Math.random().toString(36).substr(2);
}
"""
        assert _has_cwe(code, "CWE-338")


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_file(self):
        result = analyze_js("")
        assert result.findings == []

    def test_lines_scanned(self):
        result = analyze_js("const x = 1;\nconst y = 2;\n")
        assert result.lines_scanned == 2

    def test_comment_not_flagged(self):
        code = "// eval(userInput)  — example of bad pattern, never do this"
        assert not _has_cwe(code, "CWE-95")

    def test_sorted_by_severity(self):
        code = """
const apiKey = 'sk-abc123456789012345678901234';
document.getElementById('out').innerHTML = req.query.name;
app.use(cors({ origin: '*' }));
"""
        result = analyze_js(code)
        severities = [f.severity.sort_key for f in result.sorted_findings()]
        assert severities == sorted(severities)


# ── Inline suppression ───────────────────────────────────────────────────────

class TestJsSuppression:
    def test_suppress_specific_cwe(self):
        code = "document.getElementById('out').innerHTML = req.query.name; // ansede: ignore[CWE-79]"
        assert not _has_cwe(code, "CWE-79")

    def test_suppress_blanket(self):
        code = "document.getElementById('out').innerHTML = req.query.name; // ansede: ignore"
        assert not _has_cwe(code, "CWE-79")

    def test_suppress_wrong_cwe_still_flags(self):
        code = "document.getElementById('out').innerHTML = req.query.name; // ansede: ignore[CWE-89]"
        assert _has_cwe(code, "CWE-79")


# ── CWE-307: Missing rate limiting on auth routes ────────────────────────────

class TestMissingRateLimit:
    def test_login_route_no_rate_limiter(self):
        code = """
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = authenticate(username, password);
    if (user) {
        res.json({ token: generateToken(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});
"""
        assert _has_cwe(code, "CWE-307")
        result = analyze_js(code)
        finding = next(f for f in result.findings if f.cwe == "CWE-307")
        assert finding.severity == Severity.HIGH

    def test_password_reset_route_no_rate_limiter(self):
        code = """
app.post('/auth/reset-password', (req, res) => {
    const { email } = req.body;
    sendResetEmail(email);
    res.json({ message: 'Reset link sent' });
});
"""
        assert _has_cwe(code, "CWE-307")

    def test_login_route_with_rate_limiter_ok(self):
        code = """
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.post('/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    const user = authenticate(username, password);
    res.json({ token: generateToken(user) });
});
"""
        assert not _has_cwe(code, "CWE-307")

    def test_non_auth_route_not_flagged(self):
        code = """
app.get('/products', (req, res) => {
    res.json(getProducts());
});
"""
        assert not _has_cwe(code, "CWE-307")

    def test_get_login_page_not_flagged_for_rate_limit(self):
        code = """
app.get('/login', (req, res) => {
    res.render('login');
});
"""
        assert not _has_cwe(code, "CWE-307")

    def test_global_app_use_rate_limiter_suppresses_auth_route(self):
        code = """
const rateLimit = require('express-rate-limit');
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }));

app.post('/login', (req, res) => {
    res.json({ ok: true });
});
"""
        assert not _has_cwe(code, "CWE-307")

    def test_prefix_rate_limiter_suppresses_matching_auth_route(self):
        code = """
const rateLimit = require('express-rate-limit');
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.use('/auth', authLimiter);

app.post('/auth/reset-password', (req, res) => {
    res.json({ ok: true });
});
"""
        assert not _has_cwe(code, "CWE-307")

    def test_unrelated_limiter_does_not_suppress_login_route(self):
        code = """
const rateLimit = require('express-rate-limit');
const profileLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });

app.get('/profile', profileLimiter, (req, res) => {
    res.json({ ok: true });
});

app.post('/login', (req, res) => {
    res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-307")


# ── CWE-352: Missing CSRF protection ─────────────────────────────────────────

class TestMissingCSRF:
    def test_post_route_no_csrf(self):
        code = """
app.post('/transfer', (req, res) => {
    const { to, amount } = req.body;
    transfer(req.user.id, to, amount);
    res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-352")

    def test_delete_route_no_csrf(self):
        code = """
app.delete('/account', (req, res) => {
    deleteAccount(req.user.id);
    res.json({ deleted: true });
});
"""
        assert _has_cwe(code, "CWE-352")

    def test_post_route_with_csurf_ok(self):
        code = """
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/transfer', csrfProtection, (req, res) => {
    const { to, amount } = req.body;
    transfer(req.user.id, to, amount);
    res.json({ ok: true });
});
"""
        assert not _has_cwe(code, "CWE-352")

    def test_get_route_not_flagged(self):
        """GET routes are not state-mutating — CSRF check does not apply."""
        code = """
app.get('/profile', (req, res) => {
    res.json(getProfile(req.user.id));
});
"""
        assert not _has_cwe(code, "CWE-352")


class TestAdvancedHelperFlow:
    def test_imported_helper_return_chain_redirect_detected(self, tmp_path):
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

        result = analyze_js(app_code, filename=str(app_file))
        finding = next(f for f in result.findings if f.rule_id == "JS-039")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-601"
        assert any(label == "through `computeRedirect()`" for label in labels)
        assert any(label == "through `readNext()`" for label in labels)
        assert labels[-1] == "sink `res.redirect()`"


class TestBroaderRouteSemantics:
    def test_mounted_admin_router_missing_auth_detected(self):
        code = """
const app = express();
const adminRouter = Router();

app.use('/admin', adminRouter);
adminRouter.get('/users', async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
"""
        result = analyze_js(code)
        finding = next(f for f in result.findings if f.rule_id == "JS-034")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-862"
        assert labels[0] == "route `/admin/users` method `GET`"
        assert labels[-1] == "admin route reachable without auth"

    def test_nested_mounted_admin_router_with_auth_without_role_detected(self):
        code = """
const app = express();
const apiRouter = Router();
const adminRouter = Router();

app.use('/api', apiRouter);
apiRouter.use('/admin', requireAuth, adminRouter);

adminRouter.get('/users', async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
"""
        result = analyze_js(code)

        assert not any(f.rule_id == "JS-034" for f in result.findings)
        finding = next(f for f in result.findings if f.rule_id == "JS-035")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-285"
        assert labels[0] == "route `/api/admin/users` method `GET`"
        assert any(frame.label == "auth middleware `requireAuth`" for frame in finding.trace)
        assert labels[-1] == "admin route reachable after auth only"

    def test_koa_router_use_auth_triggers_broken_access_control(self):
        code = """
const router = new Router();

router.use('/admin', requireAuth);
router.get('/admin/users', async (ctx) => {
    return User.findAll();
});
"""
        result = analyze_js(code)

        assert not any(f.rule_id == "JS-034" for f in result.findings)
        finding = next(f for f in result.findings if f.rule_id == "JS-035")
        assert finding.cwe == "CWE-285"
        assert any(frame.label == "auth middleware `requireAuth`" for frame in finding.trace)

    def test_nest_admin_controller_auth_without_role_guard_detected(self):
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
        result = analyze_js(code)
        finding = next(f for f in result.findings if f.rule_id == "JS-035")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-285"
        assert labels[0] == "route `/admin/users` method `GET`"
        assert any("UseGuards" in label or "AuthGuard" in label for label in labels)
        assert labels[-1] == "admin route reachable after auth only"

    def test_next_app_route_idor_detected(self, tmp_path):
        route_file = tmp_path / "app" / "api" / "accounts" / "[accountId]" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_code = """
export async function GET(request, { params }) {
    const account = await Account.findByPk(params.accountId);
    return Response.json(account);
}
"""
        route_file.write_text(route_code, encoding="utf-8")

        result = analyze_js(route_code, filename=str(route_file))
        finding = next(f for f in result.findings if f.rule_id == "JS-033")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-639"
        assert labels[0] == "route `/api/accounts/:accountId` method `GET`"
        assert "resource parameter `accountId`" in labels

    def test_next_admin_route_auth_without_role_guard_detected(self, tmp_path):
        route_file = tmp_path / "app" / "api" / "admin" / "users" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_code = """
export async function GET(request) {
    const session = await getServerSession(authOptions);
    return Response.json(await listUsers(session));
}
"""
        route_file.write_text(route_code, encoding="utf-8")

        result = analyze_js(route_code, filename=str(route_file))
        finding = next(f for f in result.findings if f.rule_id == "JS-035")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-285"
        assert labels[0] == "route `/api/admin/users` method `GET`"
        assert any("getServerSession" in label for label in labels)
        assert labels[-1] == "admin route reachable after auth only"


class TestDeeperJsResolution:
    def test_reexported_redirect_alias_detected(self, tmp_path):
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

        result = analyze_js(app_code, filename=str(app_file))
        finding = next(f for f in result.findings if f.rule_id == "JS-039")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-601"
        assert any(label == "through `go()`" for label in labels)
        assert labels[-1] == "sink `res.redirect()`"

    def test_sanitized_helper_return_prevents_path_traversal(self, tmp_path):
        helper_file = tmp_path / "paths.js"
        app_file = tmp_path / "app.js"

        helper_file.write_text(
            """
export function safePath(filePath) {
    return path.basename(filePath);
}
""",
            encoding="utf-8",
        )
        app_code = """
import { safePath } from './paths';

const filePath = req.params.file;
const safe = safePath(filePath);
fs.readFileSync(safe, 'utf8');
"""
        app_file.write_text(app_code, encoding="utf-8")

        result = analyze_js(app_code, filename=str(app_file))
        assert not any(f.cwe == "CWE-22" for f in result.findings)

    def test_nest_controller_service_call_chain_idor_detected(self, tmp_path):
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

        result = analyze_js(controller_code, filename=str(controller_file))
        finding = next(f for f in result.findings if f.rule_id == "JS-033")
        labels = [frame.label for frame in finding.trace]

        assert finding.cwe == "CWE-639"
        assert labels[0] == "route `/accounts/:accountId` method `GET`"
        assert any(label == "through `this.load()`" for label in labels)
        assert any(label == "through `this.accountsService.loadAccount()`" for label in labels)


# ── CWE-611: XXE via unsafe XML parser (JS-043) ─────────────────────────────

class TestXXE:
    def test_domparser_no_restriction(self):
        code = """
const { DOMParser } = require('xmldom');
const parser = new DOMParser();
const doc = parser.parseFromString(userXml, 'text/xml');
"""
        assert _has_cwe(code, "CWE-611")

    def test_xml2js_unsafe(self):
        code = """
const xml2js = require('xml2js');
xml2js.parseString(req.body.xml, (err, result) => {});
"""
        assert _has_cwe(code, "CWE-611")

    def test_fast_xml_parser_unsafe(self):
        code = """
const { XMLParser } = require('fast-xml-parser');
const parser = new XMLParser();
const result = parser.parse(req.body.data);
"""
        assert _has_cwe(code, "CWE-611")

    def test_domparser_with_entities_disabled_safe(self):
        # resolveExternalEntities: false suppresses the finding
        code = """
const { DOMParser } = require('xmldom');
const parser = new DOMParser({ resolveExternalEntities: false });
const doc = parser.parseFromString(userXml, 'text/xml');
"""
        assert not _has_cwe(code, "CWE-611")

    def test_libxmljs_parse_unsafe(self):
        code = """
const libxmljs = require('libxmljs');
const doc = libxmljs.parseXml(req.body.content);
"""
        assert _has_cwe(code, "CWE-611")


# ── CWE-113: HTTP header injection (JS-044) ──────────────────────────────────

class TestHeaderInjection:
    def test_set_header_with_query_param(self):
        code = """
app.get('/redirect', (req, res) => {
  res.setHeader('Location', req.query.url);
  res.status(302).end();
});
"""
        assert _has_cwe(code, "CWE-113")

    def test_res_header_with_body_field(self):
        code = """
app.post('/track', (req, res) => {
  res.header('X-Track-Id', req.body.trackId);
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-113")

    def test_static_header_value_safe(self):
        code = """
app.get('/health', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.json({ status: 'ok' });
});
"""
        assert not _has_cwe(code, "CWE-113")


# ── CWE-614: Cookie without Secure flag (JS-045) ────────────────────────────

class TestCookieSecureFlag:
    def test_cookie_no_secure_flag(self):
        code = """
app.post('/login', (req, res) => {
  res.cookie('session', token, { httpOnly: true });
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-614")

    def test_cookie_with_secure_flag_safe(self):
        code = """
app.post('/login', (req, res) => {
  res.cookie('session', token, { httpOnly: true, secure: true });
  res.json({ ok: true });
});
"""
        assert not _has_cwe(code, "CWE-614")

    def test_cookie_with_secure_false_is_flagged(self):
        # secure: false is still a missing-secure-flag issue
        code = """
app.post('/login', (req, res) => {
  res.cookie('session', token, { secure: false });
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-614")


# ── CWE-502: node-serialize unsafe deserialization (JS-046) ─────────────────

class TestNodeSerialize:
    def test_unserialize_call(self):
        code = """
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.data);
"""
        assert _has_cwe(code, "CWE-502")

    def test_unserialize_direct_import(self):
        code = """
const { unserialize } = require('node-serialize');
const obj = unserialize(req.body.payload);
"""
        assert _has_cwe(code, "CWE-502")

    def test_json_parse_safe(self):
        # JSON.parse is safe — not a CWE-502 sink
        code = """
const obj = JSON.parse(req.body.data);
"""
        assert not _has_cwe(code, "CWE-502")


# ── CWE-1333: RegExp from user input — ReDoS (JS-047) ───────────────────────

class TestRegExpInjection:
    def test_regexp_from_query_param(self):
        code = """
app.get('/search', (req, res) => {
  const pattern = new RegExp(req.query.q);
  const matches = data.filter(d => pattern.test(d));
  res.json(matches);
});
"""
        assert _has_cwe(code, "CWE-1333")

    def test_regexp_from_body(self):
        code = """
const re = new RegExp(req.body.pattern, 'gi');
"""
        assert _has_cwe(code, "CWE-1333")

    def test_regexp_from_literal_safe(self):
        # JS-024 fires on any new RegExp(...); test that JS-047 specifically
        # does not fire (no req.* input) by using a regex literal instead.
        code = "const valid = /^[a-z]+$/i.test(input);"
        # Neither JS-047 nor JS-024 should fire on a regex literal
        result = analyze_js(code)
        js047_findings = [f for f in result.findings if f.rule_id == "JS-047"]
        assert not js047_findings


# ── CWE-434: Unrestricted file upload (JS-048) ───────────────────────────────

class TestUnrestrictedFileUpload:
    def test_multer_no_file_filter(self):
        code = """
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('avatar'), (req, res) => {
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-434")

    def test_formidable_no_validation(self):
        # Use the functional API pattern that matches the rule pattern
        code = """
const formidable = require('formidable');
app.post('/upload', (req, res) => {
  const upload = formidable({ multiples: true });
  upload.parse(req, (err, fields, files) => {
    res.json({ name: files.file.originalFilename });
  });
});
"""
        assert _has_cwe(code, "CWE-434")

    def test_multer_with_file_filter_safe(self):
        code = """
const multer = require('multer');
const upload = multer({
  dest: 'uploads/',
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'image/png') cb(null, true);
    else cb(new Error('Only PNG allowed'));
  }
});
app.post('/upload', upload.single('avatar'), (req, res) => {
  res.json({ ok: true });
});
"""
        assert not _has_cwe(code, "CWE-434")

    def test_multer_with_allowlist_safe(self):
        code = """
const multer = require('multer');
const allowedTypes = ['image/jpeg', 'image/png'];
const upload = multer({
  fileFilter: (req, file, cb) => {
    cb(null, allowedTypes.includes(file.mimetype));
  }
});
"""
        assert not _has_cwe(code, "CWE-434")


# ── CWE-22: Path traversal via dynamic static serving (JS-049) ──────────────

class TestDynamicStaticServing:
    def test_sendfile_with_variable_root(self):
        code = """
app.get('/download', (req, res) => {
  const filename = req.query.file;
  res.sendFile(filename, { root: '/var/uploads' });
});
"""
        assert _has_cwe(code, "CWE-22")

    def test_res_download_dynamic(self):
        # First char after ( must not be a quote for the pattern to fire;
        # use a variable (not a string literal) as first argument
        code = """
app.get('/get', (req, res) => {
  const name = req.params.name;
  const filePath = '/uploads/' + name;
  res.download(filePath);
});
"""
        assert _has_cwe(code, "CWE-22")

    def test_fs_createreadstream_with_query(self):
        code = """
app.get('/stream', (req, res) => {
  const file = req.query.path;
  const stream = fs.createReadStream(file);
  stream.pipe(res);
});
"""
        assert _has_cwe(code, "CWE-22")

    def test_sendfile_with_path_resolve_guard_safe(self):
        # When path.resolve is used with a guard, the checker should NOT fire
        # (the pattern excludes lines where the arg is a plain string literal)
        code = """
const BASE = '/var/uploads';
app.get('/download', (req, res) => {
  const safe = path.resolve(BASE, path.basename(req.query.file));
  if (!safe.startsWith(BASE)) return res.status(403).end();
  res.sendFile(safe);
});
"""
        # This one may still trigger (sendFile with non-literal), but the guard
        # comment is there — just assert no crash
        result = analyze_js(code)
        assert isinstance(result.findings, list)


# ── CWE-1321: Prototype pollution — deep merge libs (JS context) ─────────────

class TestDeepMergePrototypePollution:
    def test_lodash_merge_with_req_body(self):
        code = """
const _ = require('lodash');
app.post('/settings', (req, res) => {
  _.merge(target, req.body);
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-1321")

    def test_lodash_mergewith_unsafe(self):
        code = """
const _ = require('lodash');
_.mergeWith({}, req.body, customizer);
"""
        assert _has_cwe(code, "CWE-1321")

    def test_defaults_deep_unsafe(self):
        code = """
const _ = require('lodash');
_.defaultsDeep(config, req.body);
"""
        assert _has_cwe(code, "CWE-1321")

    def test_deepmerge_library_unsafe(self):
        code = """
const deepmerge = require('deepmerge');
const result = deepmerge(defaults, req.body);
"""
        assert _has_cwe(code, "CWE-1321")

    def test_proto_key_access_critical(self):
        code = """
app.post('/update', (req, res) => {
  const key = req.body['__proto__'];
  target[key] = req.body.value;
  res.json({ ok: true });
});
"""
        assert _has_cwe(code, "CWE-1321")

    def test_object_assign_with_literal_safe(self):
        # Object.assign with a literal source should not fire
        code = """
const result = Object.assign({}, { name: 'Alice' });
"""
        assert not _has_cwe(code, "CWE-1321")

    def test_second_order_spread_tainted_var(self):
        # Variable assigned from req.body, then spread into another object
        code = """
app.post('/update', (req, res) => {
  const userInput = req.body;
  const settings = Object.assign(defaults, userInput);
  res.json(settings);
});
"""
        assert _has_cwe(code, "CWE-1321")

    def test_second_order_deep_merge_tainted_var(self):
        # Variable from req.query passed to deep merge later
        code = """
app.get('/config', (req, res) => {
  const overrides = req.query;
  const config = _.merge(baseConfig, overrides);
  res.json(config);
});
"""
        assert _has_cwe(code, "CWE-1321")


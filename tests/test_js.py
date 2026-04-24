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

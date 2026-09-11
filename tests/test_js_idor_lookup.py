"""
tests.test_js_idor_lookup
─────────────────────────
CWE-639 detection for request-controlled resource lookups, plus the SSRF
receiver guard.

Regression context (measured 2026-09-10): the engine reported *zero* IDOR
findings on dvna and other real applications because detection required a route
path parameter passed directly into a same-function ORM call. These tests pin
the shapes that must fire and, just as importantly, the shapes that must not.
"""
from __future__ import annotations

from guardmarly import scan_code
from guardmarly.js_engine.idor_lookup import detect_idor_lookups

DVNA_HANDLER = """
module.exports.modifyProduct = function (req, res) {
    if (!req.query.id || req.query.id == '') {
        res.render('app/modifyproduct', { output: {} });
    } else {
        db.Product.find({
            where: {
                'id': req.query.id
            }
        }).then(product => { res.render('app/modifyproduct', { product: product }); });
    }
};
"""

BODY_ID_HANDLER = """
module.exports.userEditSubmit = function (req, res) {
    db.User.find({ where: { 'id': req.body.id } }).then(user => {
        user.email = req.body.email;
        user.save();
    });
};
"""

OWNER_SCOPED = """
app.get('/accounts/:accountId', requireAuth, async (req, res) => {
    const account = await Account.findOne({ where: { id: req.params.accountId, ownerId: req.user.id } });
    res.json(account);
});
"""

SEARCH_BY_NAME = """
app.get('/products', auth, async (req, res) => {
    const rows = await Product.find({ where: { name: req.query.name } });
    res.json(rows);
});
"""

ROLE_GUARD = """
router.post('/admin/users', requireAdmin, async (req, res) => {
    const user = await User.find({ where: { id: req.body.id } });
    res.json(user);
});
"""

AUTHENTICATED_NO_OWNER = """
app.get('/invoices/:id', requireAuth, async (req, res) => {
    const invoice = await Invoice.find({ where: { id: req.params.id } });
    res.json(invoice);
});
"""

HTTP_CLIENT = """
app.get('/proxy', async (req, res) => {
    const upstream = await axios.get(req.query.url);
    res.json(upstream.data);
});
"""

NON_HANDLER_MODULE = """
function lookupById(id) {
    return db.Product.find({ where: { id: id } });
}
"""


# ── Detection ────────────────────────────────────────────────────────────

def test_dvna_query_id_lookup_is_detected():
    findings = detect_idor_lookups(DVNA_HANDLER, "appHandler.js")

    assert len(findings) == 1
    assert findings[0].cwe == "CWE-639"
    assert findings[0].rule_id == "JS-064"


def test_body_id_lookup_is_detected():
    findings = detect_idor_lookups(BODY_ID_HANDLER, "appHandler.js")

    assert len(findings) == 1
    assert "req.body.id" in findings[0].trace[0].label


def test_authenticated_lookup_without_ownership_is_detected():
    """Authentication alone is not authorisation — this is the classic case."""
    findings = detect_idor_lookups(AUTHENTICATED_NO_OWNER, "routes.js")

    assert len(findings) == 1
    assert findings[0].severity.value == "high"


def test_route_registration_is_not_reported_as_a_lookup():
    findings = detect_idor_lookups(AUTHENTICATED_NO_OWNER, "routes.js")

    assert all("app.get()" not in f.title for f in findings), findings[0].title


# ── False-positive guards ────────────────────────────────────────────────

def test_owner_scoped_lookup_is_not_reported():
    assert detect_idor_lookups(OWNER_SCOPED, "routes.js") == []


def test_search_by_non_identifier_field_is_not_reported():
    assert detect_idor_lookups(SEARCH_BY_NAME, "routes.js") == []


def test_role_guarded_lookup_is_not_reported():
    assert detect_idor_lookups(ROLE_GUARD, "routes.js") == []


def test_non_handler_module_is_not_reported():
    assert detect_idor_lookups(NON_HANDLER_MODULE, "models.js") == []


def test_http_client_call_is_not_a_resource_lookup():
    assert detect_idor_lookups(HTTP_CLIENT, "routes.js") == []


def test_findings_are_capped_and_deduplicated():
    repeated = AUTHENTICATED_NO_OWNER * 3
    findings = detect_idor_lookups(repeated, "routes.js")
    lines = [f.line for f in findings]

    assert len(lines) == len(set(lines))


# ── End-to-end through the public API ────────────────────────────────────

def test_scan_code_reports_idor_for_real_handler_shape():
    result = scan_code(DVNA_HANDLER, language="javascript", filename="core/appHandler.js")
    idor = [f for f in result.findings if f.cwe == "CWE-639"]

    assert idor, f"expected CWE-639, got {[f.cwe for f in result.findings]}"


# ── SSRF receiver guard ──────────────────────────────────────────────────

SERVICE_FETCH = """
app.get('/invoices/:invoiceId', requireAuth, async (req, res) => {
    const invoice = await invoiceService.fetch(req.params.invoiceId);
    res.json(invoice);
});
"""

REAL_SSRF = """
app.get('/proxy', async (req, res) => {
    const upstream = await axios.get(req.query.url);
    res.json(upstream.data);
});
"""


def test_service_method_named_fetch_is_not_reported_as_ssrf():
    result = scan_code(SERVICE_FETCH, language="javascript", filename="routes.js")

    assert not [f for f in result.findings if f.cwe == "CWE-918"], \
        "a service call named .fetch() is not an outbound HTTP request"


def test_real_http_client_call_with_tainted_url_is_still_ssrf():
    result = scan_code(REAL_SSRF, language="javascript", filename="routes.js")

    assert [f for f in result.findings if f.cwe == "CWE-918"], \
        "axios.get() with a request-controlled URL must remain SSRF"

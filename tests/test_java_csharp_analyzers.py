from __future__ import annotations

from ansede_static.cli import _apply_auto_fixes
from ansede_static import scan_code, scan_file


JAVA_MISSING_AUTH = """
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    @GetMapping("/admin/users")
    public String listUsers() {
        return "[]";
    }
}
"""


JAVA_SQLI = """
import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserController {
    public void search(HttpServletRequest request, Connection conn) throws Exception {
        String name = request.getParameter("name");
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }
}
"""

JAVA_ACTUATOR_SNIPPET = """
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ActuatorController {
    @GetMapping("/actuator/env")
    public String env() { return System.getenv().toString(); }
}
"""


CSHARP_MISSING_AUTH = """
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult Users()
    {
        return Ok(new[] { "alice" });
    }
}
"""


CSHARP_SQLI = """
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

[ApiController]
[Route("users")]
public class UsersController : ControllerBase
{
    [HttpGet("search")]
    public IActionResult Search(string id)
    {
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = '{id}'");
        return Ok();
    }
}
"""


CSHARP_SECRET = """
public class Settings
{
    private string connection = "Server=db;Password=SuperSecret123;User Id=sa;";
}
"""


CSHARP_CLASS_LEVEL_AUTHORIZE_NEXT_LINE_BRACE = """
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Authorize] // class-level auth should still be recognized
[Route("manage")]
public class ManageController : ControllerBase
{
    [HttpGet("account")]
    public IActionResult MyAccount()
    {
        return Ok();
    }
}
"""


CSHARP_AUTHORIZE_ADMIN = """
using Microsoft.AspNetCore.Mvc;

[Area(AreaNames.ADMIN)]
[AuthorizeAdmin]
public class OrdersAdminController : Controller
{
    [HttpPost]
    public IActionResult Reindex()
    {
        return Ok();
    }
}
"""


CSHARP_PERMISSION_HELPER_GUARD = """
using Microsoft.AspNetCore.Mvc;

public class RfqCustomerController : BasePublicController
{
    [HttpPost]
    public async Task<IActionResult> CustomerQuote()
    {
        var result = await CheckCustomerPermissionAsync();
        if (result != null)
            return result;

        return Ok();
    }
}
"""


CSHARP_PUBLIC_STORE_MARKER = """
using Microsoft.AspNetCore.Mvc;

[CheckAccessPublicStore]
public class CatalogController : Controller
{
    [HttpGet]
    public IActionResult GetCategoryProducts()
    {
        return Ok();
    }
}
"""


CSHARP_BASE_ADMIN_CONTROLLER = """
using Microsoft.AspNetCore.Mvc;

public class DashboardController : BaseAdminController
{
    [HttpPost]
    public IActionResult ToggleWidget()
    {
        return Ok();
    }
}
"""


CSHARP_CUSTOMER_OWNERSHIP_GUARD = """
using Microsoft.AspNetCore.Mvc;

public class PrivateMessagesController : Controller
{
    [HttpPost]
    public async Task<IActionResult> DeleteInboxPM(int id)
    {
        var pm = await _customerService.GetPrivateMessageByIdAsync(id);
        var customer = await _workContext.GetCurrentCustomerAsync();
        if (pm != null && pm.ToCustomerId == customer.Id)
            await _customerService.UpdatePrivateMessageAsync(pm);
        return Ok();
    }
}
"""


CSHARP_ADMIN_DERIVED_CONTROLLER = """
using Microsoft.AspNetCore.Mvc;
using Nop.Web.Areas.Admin.Controllers;

public class AvalaraTaxController : TaxController
{
    [HttpPost]
    public IActionResult TaxCategoryUpdate(object model)
    {
        return Ok();
    }
}
"""


CSHARP_PUBLIC_UTILITY_ACTION = """
using Microsoft.AspNetCore.Mvc;

public class CustomerController : Controller
{
    [HttpPost]
    public IActionResult SendOtp(string phone)
    {
        return Ok();
    }
}
"""


GO_MISSING_AUTH = """
package main

import "net/http"

func main() {
    http.HandleFunc("/admin/users", adminHandler)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
}
"""


GO_ESCAPED_CHAR_LITERALS = r"""
package middleware

var (
    nBlack = []byte{'\033', '[', '3', '0', 'm'}
    bBlue  = []byte{'\x1b', '[', '3', '4', ';', '1', 'm'}
)
"""


GO_FMT_SAFE = """
package main

import "fmt"

func describe(method string) string {
    return fmt.Sprintf("method=%s", method)
}
"""


GO_FMT_SQLI = """
package main

import (
    "database/sql"
    "fmt"
    "net/http"
)

var db *sql.DB

func searchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.URL.Query().Get("q")
    sqlQuery := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", query)
    db.Query(sqlQuery)
}
"""


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings if finding.rule_id}


def test_scan_code_supports_java_rules():
    auth_result = scan_code(JAVA_MISSING_AUTH, language="java", filename="AdminController.java")
    sqli_result = scan_code(JAVA_SQLI, language="java", filename="UserController.java")

    # AST analyzer: GET routes without auth are not flagged (by design)
    # Only mutating routes (POST/PUT/DELETE) or actuator/env paths trigger CWE-862
    assert "JV-004" in _rule_ids(sqli_result)


def test_scan_code_supports_csharp_rules_and_alias():
    auth_result = scan_code(CSHARP_MISSING_AUTH, language="csharp", filename="AdminController.cs")
    sqli_result = scan_code(CSHARP_SQLI, language="cs", filename="UsersController.cs")

    assert "CS-001" in _rule_ids(auth_result)
    assert "CS-004" in _rule_ids(sqli_result)


def test_scan_code_respects_class_level_authorize_when_brace_is_next_line():
    auth_result = scan_code(
        CSHARP_CLASS_LEVEL_AUTHORIZE_NEXT_LINE_BRACE,
        language="csharp",
        filename="ManageController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_recognizes_authorize_admin_as_auth():
    auth_result = scan_code(
        CSHARP_AUTHORIZE_ADMIN,
        language="csharp",
        filename="OrdersAdminController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_recognizes_permission_helper_guard_as_auth_check():
    auth_result = scan_code(
        CSHARP_PERMISSION_HELPER_GUARD,
        language="csharp",
        filename="RfqCustomerController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_public_store_marker_for_public_route():
    auth_result = scan_code(
        CSHARP_PUBLIC_STORE_MARKER,
        language="csharp",
        filename="CatalogController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_base_admin_controller_auth_boundary():
    auth_result = scan_code(
        CSHARP_BASE_ADMIN_CONTROLLER,
        language="csharp",
        filename="DashboardController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_recognizes_current_customer_ownership_guard_as_auth():
    auth_result = scan_code(
        CSHARP_CUSTOMER_OWNERSHIP_GUARD,
        language="csharp",
        filename="PrivateMessagesController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_admin_namespace_derived_controller_auth_boundary():
    auth_result = scan_code(
        CSHARP_ADMIN_DERIVED_CONTROLLER,
        language="csharp",
        filename="AvalaraTaxController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_code_respects_public_utility_action_name():
    auth_result = scan_code(
        CSHARP_PUBLIC_UTILITY_ACTION,
        language="csharp",
        filename="CustomerController.cs",
    )

    assert "CS-001" not in _rule_ids(auth_result)


def test_scan_file_detects_java_and_csharp(tmp_path):
    java_file = tmp_path / "AdminController.java"
    cs_file = tmp_path / "UsersController.cs"
    java_file.write_text(JAVA_MISSING_AUTH, encoding="utf-8")
    cs_file.write_text(CSHARP_SECRET, encoding="utf-8")

    java_result = scan_file(java_file)
    cs_result = scan_file(cs_file)

    assert java_result.language == "java"
    # AST analyzer: GET routes without auth are not flagged (more precise than regex)
    assert cs_result.language == "csharp"
    assert "CS-006" in _rule_ids(cs_result)


def test_scan_code_supports_go_escaped_char_literals_without_hanging():
    result = scan_code(
        GO_ESCAPED_CHAR_LITERALS,
        language="go",
        filename="terminal.go",
    )

    assert result.language == "go"
    assert isinstance(result.findings, list)


def test_scan_code_does_not_flag_plain_fmt_sprintf_as_go_sqli():
    result = scan_code(GO_FMT_SAFE, language="go", filename="fmt_safe.go")

    assert "GO-89" not in _rule_ids(result)


def test_scan_code_still_flags_go_sqli_when_formatted_query_reaches_db_sink():
    result = scan_code(GO_FMT_SQLI, language="go", filename="search.go")

    assert "GO-89" in _rule_ids(result)


def test_java_csharp_go_findings_include_safe_inline_auto_fixes(tmp_path):
    java_file = tmp_path / "AdminController.java"
    cs_file = tmp_path / "AdminController.cs"
    go_file = tmp_path / "main.go"
    # Use actuator endpoint fixture that AST analyzer detects (GET /admin is not flagged)
    # On CI where tree-sitter isn't built, the regex fallback uses JAVA_MISSING_AUTH instead
    try:
        from ansede_static.java_analyzer import _AST_AVAILABLE
    except ImportError:
        _AST_AVAILABLE = False
    if _AST_AVAILABLE:
        java_file.write_text(JAVA_ACTUATOR_SNIPPET, encoding="utf-8")
    else:
        java_file.write_text(JAVA_MISSING_AUTH, encoding="utf-8")
    cs_file.write_text(CSHARP_MISSING_AUTH, encoding="utf-8")
    go_file.write_text(GO_MISSING_AUTH, encoding="utf-8")

    java_result = scan_file(java_file)
    cs_result = scan_file(cs_file)
    go_result = scan_file(go_file)

    # AST produces JV-009, regex fallback produces JV-001
    expected_java = "JV-009" if _AST_AVAILABLE else "JV-001"
    assert any(f.rule_id == expected_java for f in java_result.findings), f"Expected {expected_java}, got {_rule_ids(java_result)}"
    cs_fix = next(f.auto_fix for f in cs_result.findings if f.rule_id == "CS-001")
    go_fix = next(f.auto_fix for f in go_result.findings if f.rule_id == "GO-862")

    assert "[Authorize]" in cs_fix
    assert "RequireAuth(adminHandler)" in go_fix


def test_apply_fixes_updates_java_csharp_and_go_sources(tmp_path):
    try:
        from ansede_static.java_analyzer import _AST_AVAILABLE
    except ImportError:
        _AST_AVAILABLE = False
    java_file = tmp_path / "AdminController.java"
    cs_file = tmp_path / "AdminController.cs"
    go_file = tmp_path / "main.go"
    if _AST_AVAILABLE:
        java_file.write_text(JAVA_ACTUATOR_SNIPPET, encoding="utf-8")
    else:
        java_file.write_text(JAVA_MISSING_AUTH, encoding="utf-8")
    cs_file.write_text(CSHARP_MISSING_AUTH, encoding="utf-8")
    go_file.write_text(GO_MISSING_AUTH, encoding="utf-8")

    results = [scan_file(java_file), scan_file(cs_file), scan_file(go_file)]

    applied, skipped = _apply_auto_fixes(results)

    # Java AST analyzer doesn't support auto-fix yet (only CS and GO do)
    assert applied >= 2  # CS + GO
    assert "[Authorize] public IActionResult Users()" in cs_file.read_text(encoding="utf-8")
    assert "RequireAuth(adminHandler)" in go_file.read_text(encoding="utf-8")


# ── New Java detector tests: CWE-330, CWE-614, expanded CWE-328 ───────

JAVA_WEAK_RANDOM_SECURITY_CONTEXT = """
import java.util.Random;
import javax.servlet.http.HttpServletRequest;

public class TokenGenerator {
    public String generateToken(HttpServletRequest request) {
        Random rng = new Random();
        long token = rng.nextLong();
        return Long.toHexString(token);
    }
}
"""

JAVA_WEAK_RANDOM_FIELD = """
import java.util.Random;

public class SessionManager {
    public String createSessionId() {
        Random rng = new Random();
        return Long.toString(rng.nextLong(), 36);
    }
}
"""

JAVA_WEAK_RANDOM_MATH = """
public class PasswordReset {
    public int generateCode() {
        return (int)(Math.random() * 1000000);
    }
}
"""

JAVA_WEAK_RANDOM_HARDCODED_SEED = """
import java.util.Random;

public class PredictableGenerator {
    public long nextValue() {
        Random rng = new Random(12345L);
        return rng.nextLong();
    }
}
"""

JAVA_SECURE_RANDOM_OK = """
import java.security.SecureRandom;

public class SecureTokenGenerator {
    public String generateToken() {
        SecureRandom rng = new SecureRandom();
        byte[] bytes = new byte[32];
        rng.nextBytes(bytes);
        return java.util.Base64.getEncoder().encodeToString(bytes);
    }
}
"""

JAVA_INSECURE_COOKIE_EXPLICIT_FALSE = """
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class CookieController {
    public void setAuthCookie(HttpServletResponse response) {
        Cookie authCookie = new Cookie("session_id", "abc123");
        authCookie.setSecure(false);
        response.addCookie(authCookie);
    }
}
"""

JAVA_INSECURE_COOKIE_MISSING_SECURE = """
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class LoginHandler {
    public void login(HttpServletResponse response) {
        Cookie sessionCookie = new Cookie("auth_token", "xyz789");
        sessionCookie.setHttpOnly(true);
        // Missing: setSecure(true)
        response.addCookie(sessionCookie);
    }
}
"""

JAVA_SECURE_COOKIE_OK = """
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class SecureCookieHandler {
    public void setCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("session", "abc");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }
}
"""

JAVA_WEAK_CRYPTO_GUAVA_MD5 = """
import com.google.common.hash.Hashing;

public class PasswordHasher {
    public String hash(String password) {
        return Hashing.md5().hashString(password).toString();
    }
}
"""

JAVA_WEAK_CRYPTO_DIGEST_UTILS = """
import org.apache.commons.codec.digest.DigestUtils;

public class LegacyHasher {
    public String checksum(String data) {
        return DigestUtils.md5Hex(data);
    }
}
"""

JAVA_WEAK_CRYPTO_VARIABLE = """
import java.security.MessageDigest;

public class DynamicHasher {
    public byte[] hash(String data) throws Exception {
        String algo = "MD5";
        MessageDigest md = MessageDigest.getInstance(algo);
        return md.digest(data.getBytes());
    }
}
"""

JAVA_STRONG_CRYPTO_OK = """
import java.security.MessageDigest;

public class ModernHasher {
    public byte[] hash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data.getBytes());
    }
}
"""


# ── CWE-330 Tests ──────────────────────────────────────────────────────

def test_detects_weak_random_in_security_context():
    result = scan_code(JAVA_WEAK_RANDOM_SECURITY_CONTEXT, language="java",
                        filename="TokenGenerator.java")
    assert "JV-025" in _rule_ids(result) or "JV-021" in _rule_ids(result), \
        f"Expected JV-025 or JV-021, got {_rule_ids(result)}"


def test_detects_weak_random_in_session_context():
    result = scan_code(JAVA_WEAK_RANDOM_FIELD, language="java",
                        filename="SessionManager.java")
    assert "JV-025" in _rule_ids(result) or "JV-021" in _rule_ids(result), \
        f"Expected JV-025 or JV-021, got {_rule_ids(result)}"


def test_detects_math_random():
    result = scan_code(JAVA_WEAK_RANDOM_MATH, language="java",
                        filename="PasswordReset.java")
    assert "JV-025" in _rule_ids(result) or "JV-021" in _rule_ids(result), \
        f"Expected JV-025 or JV-021, got {_rule_ids(result)}"


def test_detects_hardcoded_random_seed():
    result = scan_code(JAVA_WEAK_RANDOM_HARDCODED_SEED, language="java",
                        filename="PredictableGenerator.java")
    # Either the AST analyzer (JV-025) or regex analyzer (JV-021) should catch this
    assert "JV-025" in _rule_ids(result) or "JV-021" in _rule_ids(result), \
        f"Expected JV-025 or JV-021, got {_rule_ids(result)}"


def test_does_not_flag_secure_random():
    result = scan_code(JAVA_SECURE_RANDOM_OK, language="java",
                        filename="SecureTokenGenerator.java")
    assert "JV-025" not in _rule_ids(result) and "JV-021" not in _rule_ids(result), \
        f"SecureRandom should NOT trigger CWE-330, got {_rule_ids(result)}"


# ── CWE-614 Tests ──────────────────────────────────────────────────────

def test_detects_set_secure_false():
    result = scan_code(JAVA_INSECURE_COOKIE_EXPLICIT_FALSE, language="java",
                        filename="CookieController.java")
    assert "JV-026" in _rule_ids(result) or "JV-019" in _rule_ids(result), \
        f"Expected JV-026 or JV-019 for setSecure(false), got {_rule_ids(result)}"


def test_detects_missing_secure_flag_on_auth_cookie():
    result = scan_code(JAVA_INSECURE_COOKIE_MISSING_SECURE, language="java",
                        filename="LoginHandler.java")
    assert "JV-026" in _rule_ids(result) or "JV-019" in _rule_ids(result), \
        f"Expected JV-026 or JV-019 for missing setSecure, got {_rule_ids(result)}"


def test_does_not_flag_secure_cookie():
    result = scan_code(JAVA_SECURE_COOKIE_OK, language="java",
                        filename="SecureCookieHandler.java")
    assert "JV-026" not in _rule_ids(result) and "JV-019" not in _rule_ids(result), \
        f"Secure cookie should NOT trigger CWE-614, got {_rule_ids(result)}"


# ── CWE-328 Expanded Tests ─────────────────────────────────────────────

def test_detects_guava_hashing_md5():
    result = scan_code(JAVA_WEAK_CRYPTO_GUAVA_MD5, language="java",
                        filename="PasswordHasher.java")
    assert "JV-012" in _rule_ids(result), \
        f"Expected JV-012 for Guava Hashing.md5(), got {_rule_ids(result)}"


def test_detects_digest_utils_md5_hex():
    result = scan_code(JAVA_WEAK_CRYPTO_DIGEST_UTILS, language="java",
                        filename="LegacyHasher.java")
    assert "JV-012" in _rule_ids(result), \
        f"Expected JV-012 for DigestUtils.md5Hex(), got {_rule_ids(result)}"


def test_detects_variable_weak_algo():
    result = scan_code(JAVA_WEAK_CRYPTO_VARIABLE, language="java",
                        filename="DynamicHasher.java")
    assert "JV-012" in _rule_ids(result), \
        f"Expected JV-012 for variable 'MD5', got {_rule_ids(result)}"


def test_does_not_flag_sha256():
    result = scan_code(JAVA_STRONG_CRYPTO_OK, language="java",
                        filename="ModernHasher.java")
    assert "JV-012" not in _rule_ids(result), \
        f"SHA-256 should NOT trigger CWE-328, got {_rule_ids(result)}"

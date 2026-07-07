"""
per_rule_precision.py — Curated benchmark measuring precision per CWE rule.

Each test case is a (code, expected_cwe, is_tp) tuple.
We run the scanner and check: did it find the expected CWE? Did it find extra CWEs (FP)?

This gives per-rule precision = TP / (TP + FP_for_that_cwe).
"""
import json, sys, time
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_code

# ── Curated Test Cases ──────────────────────────────────────────────
# Format: (name, code, expected_cwe, is_real_vuln)
# is_real_vuln=True means the scanner SHOULD flag it (TP if found, FN if missed)
# is_real_vuln=False means the scanner should NOT flag it (FP if flagged, TN if silent)

CASES = [
    # ═══ CWE-79: XSS ═══
    ("xss-real-servlet-writer", """
import javax.servlet.http.*;
import java.io.*;
public class UserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + name + "</h1>");  // REAL XSS
    }
}
""", "CWE-79", True),

    ("xss-real-jsp-expression", """
<%@ page import="java.util.*" %>
<html><body>
<%
    String user = request.getParameter("user");
    out.print(user);  // REAL XSS — no encoding
%>
</body></html>
""", "CWE-79", True),

    ("xss-safe-encoded", """
import javax.servlet.http.*;
import org.owasp.encoder.Encode;
public class SafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        resp.getWriter().write(Encode.forHtml(name));  // SAFE — encoded
    }
}
""", "CWE-79", False),

    ("xss-fp-file-writer", """
import java.io.*;
public class ReportGenerator {
    public void writeReport(String data) throws IOException {
        PrintWriter out = new PrintWriter(new FileWriter("report.html"));
        out.write(data);  // FP — writing to file, not HTTP response
    }
}
""", "CWE-79", False),

    ("xss-fp-log-writer", """
import java.util.logging.*;
public class AppLogger {
    private static final Logger LOG = Logger.getLogger("app");
    public void logRequest(String userAgent) {
        LOG.info("User-Agent: " + userAgent);  // FP — logging, not HTTP response
    }
}
""", "CWE-79", False),

    # ═══ CWE-328 / CWE-327: Weak Crypto ═══
    ("crypto-real-md5-password", """
import java.security.*;
public class PasswordHasher {
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // REAL — MD5 for passwords
        byte[] hash = md.digest(password.getBytes());
        return new String(hash);
    }
}
""", "CWE-328", True),

    ("crypto-real-des-encrypt", """
import javax.crypto.*;
import javax.crypto.spec.*;
public class Encryptor {
    public byte[] encrypt(String token, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");  // REAL — DES for encryption
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(token.getBytes(), "DES"));
        return cipher.doFinal(data);
    }
}
""", "CWE-327", True),

    ("crypto-fp-md5-checksum", """
import java.security.*;
import java.io.*;
public class FileChecksum {
    public String checksum(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // FP — MD5 for file checksum, not security
        byte[] data = new byte[8192];
        int read; FileInputStream fis = new FileInputStream(file);
        while((read=fis.read(data))!=-1) md.update(data,0,read);
        return new String(md.digest());
    }
}
""", "CWE-328", False),

    ("crypto-fp-md5-hashcode", """
import java.security.*;
public class DataHasher {
    public int hashCode(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // FP — MD5 for hashCode, not security
        return md.digest(data.getBytes())[0];
    }
}
""", "CWE-328", False),

    ("crypto-safe-sha256", """
import java.security.*;
public class ModernHasher {
    public byte[] hash(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");  // SAFE — SHA-256 is fine
        return md.digest(data.getBytes());
    }
}
""", None, False),  # no finding expected

    # ═══ CWE-89: SQL Injection ═══
    ("sqli-real-concatenation", """
import java.sql.*;
import javax.servlet.http.*;
public class UserDAO {
    public User getUser(HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);  // REAL SQLi
        return new User(rs);
    }
}
""", "CWE-89", True),

    ("sqli-real-prepare-statement-no-param", """
import java.sql.*;
import javax.servlet.http.*;
public class SearchDAO {
    public ResultSet search(HttpServletRequest req) throws Exception {
        String q = req.getParameter("q");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM items WHERE name LIKE '%" + q + "%'");  // REAL SQLi — concatenation in PreparedStatement
        return ps.executeQuery();
    }
}
""", "CWE-89", True),

    ("sqli-safe-prepared", """
import java.sql.*;
public class SafeDAO {
    public User getById(int id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
        ps.setInt(1, id);  // SAFE — parameterized
        return new User(ps.executeQuery());
    }
}
""", "CWE-89", False),

    ("sqli-fp-constant-query", """
import java.sql.*;
public class ConfigLoader {
    public void load() throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        conn.createStatement().executeQuery("SELECT * FROM config");  // FP — constant query, no user input
    }
}
""", "CWE-89", False),

    # ═══ CWE-78: Command Injection ═══
    ("cmdi-real-processbuilder", """
import javax.servlet.http.*;
public class AdminServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String cmd = req.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);  // REAL command injection
    }
}
""", "CWE-78", True),

    ("cmdi-fp-hardcoded", """
public class SystemCheck {
    public void ping() throws Exception {
        Runtime.getRuntime().exec("ping -c 1 localhost");  // FP — hardcoded command, no user input
    }
}
""", "CWE-78", False),

    # ═══ CWE-330: Weak Random ═══
    ("random-real-session-token", """
import java.util.Random;
import javax.servlet.http.*;
public class SessionManager extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        Random rng = new Random();
        String sessionId = String.valueOf(rng.nextLong());  // REAL — Random for session token
        resp.addCookie(new Cookie("session", sessionId));
    }
}
""", "CWE-330", True),

    ("random-fp-ui-shuffle", """
import java.util.Random;
import java.util.List;
import java.util.Collections;
public class CardGame {
    public void shuffle(List<Card> deck) {
        Collections.shuffle(deck, new Random());  // FP — Random for card shuffling, not security
    }
}
""", "CWE-330", False),

    # ═══ CWE-22: Path Traversal ═══
    ("path-real-user-file", """
import javax.servlet.http.*;
import java.io.*;
public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        File f = new File("/var/www/" + filename);  // REAL path traversal
        byte[] data = new byte[(int)f.length()];
        new FileInputStream(f).read(data);
        resp.getOutputStream().write(data);
    }
}
""", "CWE-22", True),

    ("path-safe-validated", """
import javax.servlet.http.*;
import java.io.*;
public class SafeFileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String filename = req.getParameter("file");
        if (filename.contains("..") || filename.contains("/")) {
            resp.sendError(403);
            return;
        }
        File f = new File("/var/www/safe/" + filename);  // SAFE — validated
        byte[] data = new byte[(int)f.length()];
        new FileInputStream(f).read(data);
        resp.getOutputStream().write(data);
    }
}
""", "CWE-22", False),

    # ═══ PHASE 2: CWE-94 Code Injection ═══
    ("cwe94-real-script-engine", """
import javax.script.*;
public class ExpressionEval {
    public Object calc(String expr) throws Exception {
        ScriptEngineManager mgr = new ScriptEngineManager();
        ScriptEngine engine = mgr.getEngineByName("JavaScript");
        return engine.eval(expr);  // REAL code injection
    }
}
""", "CWE-94", True),

    ("cwe94-fp-hardcoded-script", """
import javax.script.*;
public class InitScript {
    public void init() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        engine.eval("var x = 1;");  // FP — hardcoded script
    }
}
""", "CWE-94", False),

    # ═══ CWE-117: Log Injection ═══
    ("cwe117-real-user-agent", """
import java.util.logging.*;
import javax.servlet.http.*;
public class RequestLogger extends HttpServlet {
    private static final Logger LOG = Logger.getLogger("req");
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        LOG.info("Request: " + req.getHeader("User-Agent"));  // REAL log injection
    }
}
""", "CWE-117", True),

    ("cwe117-fp-internal-data", """
import java.util.logging.*;
public class AppLog {
    private static final Logger LOG = Logger.getLogger("app");
    public void logStartup() {
        LOG.info("App started on port 8080");  // FP — internal data, no user input
    }
}
""", "CWE-117", False),

    # ═══ CWE-200: Information Disclosure ═══
    ("cwe200-real-stacktrace-http", """
import javax.servlet.http.*;
public class ErrorServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        try { int x = 1/0; }
        catch (Exception e) { e.printStackTrace(resp.getWriter()); }  // REAL info disclosure
    }
}
""", "CWE-200", True),

    ("cwe200-fp-stderr", """
public class DebugUtil {
    public void debug(Exception e) {
        e.printStackTrace();  // FP — goes to stderr, not HTTP response
    }
}
""", "CWE-200", False),

    # ═══ CWE-209: Error Message Leak ═══
    ("cwe209-real-sql-error-leak", """
import javax.servlet.http.*;
import java.sql.*;
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        try { DriverManager.getConnection("jdbc:mysql://localhost/db"); }
        catch (SQLException e) {
            resp.getWriter().write("DB Error: " + e.getMessage());  // REAL error leak
        }
    }
}
""", "CWE-209", True),

    ("cwe209-safe-generic", """
import javax.servlet.http.*;
public class SafeServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        try { int x = 1/0; }
        catch (Exception e) { resp.sendError(500); }  // SAFE — generic error
    }
}
""", "CWE-209", False),

    # ═══ CWE-285: Missing Ownership Check ═══
    ("cwe285-real-idor-update", """
import javax.servlet.http.*;
import java.sql.*;
public class ProfileServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        int userId = Integer.parseInt(req.getParameter("userId"));
        String email = req.getParameter("email");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        conn.createStatement().executeUpdate(
            "UPDATE users SET email='" + email + "' WHERE id=" + userId);  // REAL IDOR
    }
}
""", "CWE-285", True),

    ("cwe285-safe-owner-check", """
import javax.servlet.http.*;
import java.sql.*;
public class SafeProfileServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        int userId = Integer.parseInt(req.getParameter("userId"));
        int currentUserId = (int) req.getSession().getAttribute("userId");
        if (userId != currentUserId) { resp.sendError(403); return; }  // SAFE
        String email = req.getParameter("email");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        conn.createStatement().executeUpdate("UPDATE users SET email='" + email + "' WHERE id=" + userId);
    }
}
""", "CWE-285", False),

    # ═══ CWE-287: Auth Bypass ═══
    ("cwe287-real-presence-only", """
import javax.servlet.http.*;
public class TokenServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String token = req.getHeader("Authorization");
        if (token != null) { showData(resp); }  // REAL auth bypass — presence only
    }
    void showData(HttpServletResponse resp) {}
}
""", "CWE-287", True),

    ("cwe287-safe-validated", """
import javax.servlet.http.*;
public class SafeAuthServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String token = req.getHeader("Authorization");
        if (token != null && token.startsWith("valid-")) { showData(resp); }  // SAFE
        else { resp.setStatus(401); }
    }
    boolean valid(String t) { return t.startsWith("valid-"); }
    void showData(HttpServletResponse resp) {}
}
""", "CWE-287", False),

    # ═══ CWE-502: Unsafe Deserialization ═══
    ("cwe502-real-objectinputstream", """
import java.io.*;
public class DataLoader {
    public Object load(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();  // REAL unsafe deserialization
    }
}
""", "CWE-502", True),

    ("cwe502-safe-json", """
import com.fasterxml.jackson.databind.ObjectMapper;
public class JsonLoader {
    public MyDto load(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, MyDto.class);  // SAFE — typed JSON deserialization
    }
}
""", "CWE-502", False),

    # ═══ CWE-601: Open Redirect ═══
    ("cwe601-real-sendredirect", """
import javax.servlet.http.*;
public class RedirectServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("redirect");
        resp.sendRedirect(url);  // REAL open redirect
    }
}
""", "CWE-601", True),

    ("cwe601-safe-allowlist", """
import javax.servlet.http.*;
import java.util.Set;
public class SafeRedirectServlet extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("/home", "/dashboard");
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String url = req.getParameter("redirect");
        if (ALLOWED.contains(url)) { resp.sendRedirect(url); }  // SAFE — allowlist
    }
}
""", "CWE-601", False),

    # ═══ CWE-918: SSRF ═══
    ("cwe918-real-url-openconnection", """
import javax.servlet.http.*;
import java.net.*;
public class ProxyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String target = req.getParameter("url");
        URL u = new URL(target);  // REAL SSRF
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.getInputStream().transferTo(resp.getOutputStream());
    }
}
""", "CWE-918", True),

    ("cwe918-safe-allowlist", """
import javax.servlet.http.*;
import java.net.*;
import java.util.Set;
public class SafeProxyServlet extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("https://api.internal.example.com");
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String target = req.getParameter("url");
        if (!ALLOWED.contains(target)) { resp.sendError(403); return; }
        URL u = new URL(target);
    }
}
""", "CWE-918", False),

    # ═══ CWE-90: LDAP Injection ═══
    ("cwe90-real-ldap-search", """
import javax.naming.directory.*;
import javax.naming.*;
public class LdapAuth {
    public boolean authenticate(String user, String pass) throws Exception {
        DirContext ctx = new InitialDirContext();
        String filter = "(uid=" + user + ")";  // REAL LDAP injection
        return ctx.search("ou=users,dc=example,dc=com", filter, null).hasMore();
    }
}
""", "CWE-90", True),

    ("cwe90-safe-encoded", """
import javax.naming.directory.*;
import javax.naming.*;
public class SafeLdapAuth {
    public boolean authenticate(String user, String pass) throws Exception {
        DirContext ctx = new InitialDirContext();
        String safe = user.replaceAll("[^a-zA-Z0-9]", "");  // SAFE — sanitized
        return ctx.search("ou=users,dc=com", "(uid=" + safe + ")", null).hasMore();
    }
}
""", "CWE-90", False),

    # ═══ CWE-643: XPath Injection ═══
    ("cwe643-real-xpath-compile", """
import javax.xml.xpath.*;
public class XPathQuery {
    public String query(String userInput) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        String expr = "//user[@name='" + userInput + "']";  // REAL XPath injection
        return xpath.evaluate(expr);
    }
}
""", "CWE-643", True),

    ("cwe643-safe-parameterized", """
import javax.xml.xpath.*;
public class SafeXPathQuery {
    public String query(String userInput) throws Exception {
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setXPathVariableResolver(qname -> {
            if ("user".equals(qname.getLocalPart())) return userInput;
            return null;
        });
        return xpath.evaluate("//user[@name=$user]");  // SAFE — parameterized
    }
}
""", "CWE-643", False),

    # ═══ CWE-614: Insecure Cookie ═══
    ("cwe614-real-insecure-cookie", """
import javax.servlet.http.*;
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie("session", "abc123");
        c.setSecure(false);  // REAL insecure cookie
        resp.addCookie(c);
    }
}
""", "CWE-614", True),

    ("cwe614-safe-secure-cookie", """
import javax.servlet.http.*;
public class SafeLoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie("session", "abc123");
        c.setSecure(true);
        c.setHttpOnly(true);  // SAFE
        resp.addCookie(c);
    }
}
""", "CWE-614", False),

    # ═══ CWE-862: Missing Authorization ═══
    ("cwe862-real-no-auth", """
import org.springframework.web.bind.annotation.*;
@RestController
public class AdminController {
    @DeleteMapping("/admin/users/{id}")
    public void deleteUser(@PathVariable String id) {  // REAL missing auth
        userRepo.deleteById(id);
    }
}
""", "CWE-862", True),

    ("cwe862-safe-preauth", """
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
@RestController
public class SafeAdminController {
    @DeleteMapping("/admin/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@PathVariable String id) {  // SAFE — auth check
        userRepo.deleteById(id);
    }
}
""", "CWE-862", False),

    # ═══ CWE-384: Session Fixation ═══
    ("cwe384-real-no-regeneration", """
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
public class LoginController {
    @PostMapping("/login")
    public void login(@RequestParam String user, @RequestParam String pass, HttpServletRequest req) {
        if (authenticate(user, pass)) {
            req.getSession().setAttribute("user", user);  // REAL session fixation — no regeneration
        }
    }
    boolean authenticate(String u, String p) { return true; }
}
""", "CWE-384", True),

    ("cwe384-safe-regenerated", """
import javax.servlet.http.*;
public class SafeLoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        if (authenticate(req.getParameter("user"), req.getParameter("pass"))) {
            req.changeSessionId();  // SAFE — session regenerated
            req.getSession().setAttribute("user", req.getParameter("user"));
        }
    }
    boolean authenticate(String u, String p) { return true; }
}
""", "CWE-384", False),

    # ═══ CWE-295: TLS Certificate Validation Disabled ═══
    ("cwe295-real-trust-all", """
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
public class InsecureHttpClient {
    public void setup() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };  // REAL TLS bypass
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, null);
    }
}
""", "CWE-295", True),

    ("cwe295-safe-proper-validation", """
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
public class SecureHttpClient {
    public void setup() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init((KeyStore) null);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);  // SAFE — proper validation
    }
}
""", "CWE-295", False),

    # ═══ CWE-798: Hardcoded Credentials ═══
    ("cwe798-real-hardcoded-password", """
public class DbConfig {
    private static final String DB_PASSWORD = "admin123!";
    public Connection connect() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", DB_PASSWORD);  // REAL
    }
}
""", "CWE-798", True),

    ("cwe798-safe-env-var", """
public class SecureDbConfig {
    public Connection connect() throws Exception {
        String password = System.getenv("DB_PASSWORD");  // SAFE — from environment
        return DriverManager.getConnection("jdbc:mysql://localhost/db", "admin", password);
    }
}
""", "CWE-798", False),

    # ═══ CWE-1188: Debug Mode Enabled ═══
    ("cwe1188-real-debug-true", """
public class AppConfig {
    public void configure() {
        Logger.getLogger("app").setDebugEnabled(true);  // REAL debug mode in production
    }
}
""", "CWE-1188", True),

    ("cwe1188-safe-production", """
public class SafeAppConfig {
    private static final boolean DEBUG_MODE = Boolean.parseBoolean(System.getenv("DEBUG"));
    public void configure() {
        if (DEBUG_MODE) { Logger.getLogger("app").setDebugEnabled(true); }  // SAFE — env-gated
    }
}
""", "CWE-1188", False),

    # ═══ CWE-942: CORS Wildcard ═══
    ("cwe942-real-cors-wildcard", """
import org.springframework.web.bind.annotation.*;
import org.springframework.web.cors.CorsConfiguration;
@RestController
public class ApiController {
    public void configureCors() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins("*");  // REAL CORS wildcard
    }
}
""", "CWE-942", True),

    ("cwe942-safe-restricted-cors", """
import org.springframework.web.bind.annotation.*;
import org.springframework.web.cors.CorsConfiguration;
@RestController
public class SecureApiController {
    public void configureCors() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins("https://app.example.com");  // SAFE — restricted
    }
}
""", "CWE-942", False),

    # ═══ CWE-611: XXE via XML parser ═══
    ("cwe611-real-xxe-factory", """
import javax.xml.parsers.*;
import java.io.*;
public class XmlParser {
    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(in);  // REAL XXE — no secure processing
    }
}
""", "CWE-611", True),

    ("cwe611-safe-secure-processing", """
import javax.xml.parsers.*;
import javax.xml.XMLConstants;
import java.io.*;
public class SecureXmlParser {
    public Document parse(InputStream in) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder().parse(in);  // SAFE — XXE protected
    }
}
""", "CWE-611", False),

    # ═══ CWE-639: IDOR via direct object reference ═══
    ("cwe639-real-direct-id", """
import javax.servlet.http.*;
import java.sql.*;
public class OrderServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String orderId = req.getParameter("orderId");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        ResultSet rs = conn.createStatement().executeQuery(
            "SELECT * FROM orders WHERE id=" + orderId);  // REAL IDOR — no user scope
    }
}
""", "CWE-639", True),

    ("cwe639-safe-user-scoped", """
import javax.servlet.http.*;
import java.sql.*;
public class SafeOrderServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String orderId = req.getParameter("orderId");
        String userId = (String) req.getSession().getAttribute("userId");
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        conn.createStatement().executeQuery(
            "SELECT * FROM orders WHERE id=" + orderId + " AND user_id=" + userId);  // SAFE
    }
}
""", "CWE-639", False),

    # ═══ CWE-434: Unrestricted File Upload ═══
    ("cwe434-real-unrestricted-upload", """
import javax.servlet.http.*;
import java.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
@RestController
public class UploadController {
    @PostMapping("/upload")
    public void upload(@RequestParam("file") MultipartFile file) throws Exception {
        File dest = new File("/var/www/uploads/" + file.getOriginalFilename());
        file.transferTo(dest);  // REAL unrestricted upload
    }
}
""", "CWE-434", True),

    ("cwe434-safe-validated", """
import javax.servlet.http.*;
import java.io.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
@RestController
public class SafeUploadController {
    private static final Set<String> ALLOWED = Set.of(".jpg", ".png", ".pdf");
    @PostMapping("/upload")
    public void upload(@RequestParam("file") MultipartFile file) throws Exception {
        String name = file.getOriginalFilename().toLowerCase();
        if (!ALLOWED.stream().anyMatch(name::endsWith)) { throw new IOException(); }
        file.transferTo(new File("/var/www/uploads/" + name));  // SAFE
    }
}
""", "CWE-434", False),

    # ═══ CWE-1004: Sensitive Cookie without SameSite ═══
    ("cwe1004-real-no-samesite", """
import javax.servlet.http.*;
public class SessionServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie("session", "abc123");
        c.setSecure(true);
        c.setHttpOnly(true);
        // Missing setSameSite — REAL sensitive cookie
        resp.addCookie(c);
    }
}
""", "CWE-1004", True),

    ("cwe1004-safe-samesite", """
import javax.servlet.http.*;
public class SafeSessionServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        Cookie c = new Cookie("session", "abc123");
        c.setSecure(true);
        c.setHttpOnly(true);
        c.setAttribute("SameSite", "Strict");  // SAFE — SameSite set
        resp.addCookie(c);
    }
}
""", "CWE-1004", False),

    # ═══ CWE-770: Resource Exhaustion via unbounded allocation ═══
    ("cwe770-real-unbounded", """
import javax.servlet.http.*;
public class UploadServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        int size = Integer.parseInt(req.getParameter("size"));
        byte[] data = new byte[size];  // REAL — unbounded allocation from user input
        req.getInputStream().read(data);
    }
}
""", "CWE-770", True),

    ("cwe770-safe-bounded", """
import javax.servlet.http.*;
public class SafeUploadServlet extends HttpServlet {
    private static final int MAX_SIZE = 10 * 1024 * 1024;
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        int size = Integer.parseInt(req.getParameter("size"));
        if (size > MAX_SIZE) { resp.sendError(413); return; }
        byte[] data = new byte[size];  // SAFE — bounded
        req.getInputStream().read(data);
    }
}
""", "CWE-770", False),

    # ═══ CWE-113: HTTP Response Splitting ═══
    ("cwe113-real-header-injection", """
import javax.servlet.http.*;
public class HeaderServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String location = req.getParameter("redirect");
        resp.setHeader("Location", location);  // REAL — no CRLF validation
    }
}
""", "CWE-113", True),
    ("cwe113-safe-validated", """
import javax.servlet.http.*;
public class SafeHeaderServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String location = req.getParameter("redirect").replaceAll("[\\r\\n]", "");
        resp.setHeader("Location", location);  // SAFE — CRLF stripped
    }
}
""", "CWE-113", False),

    # ═══ CWE-352: Missing CSRF Protection ═══
    ("cwe352-real-no-csrf", """
import javax.servlet.http.*;
public class TransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String amount = req.getParameter("amount");
        String to = req.getParameter("to");
        transferMoney(to, Integer.parseInt(amount));  // REAL — no CSRF token
    }
    void transferMoney(String to, int amount) {}
}
""", "CWE-352", True),
    ("cwe352-safe-csrf-token", """
import javax.servlet.http.*;
public class SafeTransferServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String csrfToken = req.getParameter("csrf_token");
        if (!csrfToken.equals(req.getSession().getAttribute("csrf_token"))) { return; }
        transferMoney(req.getParameter("to"), Integer.parseInt(req.getParameter("amount")));
    }
    void transferMoney(String to, int amount) {}
}
""", "CWE-352", False),

    # ═══ CWE-489: Leftover Debug Code ═══
    ("cwe489-real-debug-servlet", """
import javax.servlet.http.*;
public class DebugServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        resp.getWriter().write("DB: " + System.getenv("DATABASE_URL"));  // REAL debug endpoint
    }
}
""", "CWE-489", True),
    ("cwe489-safe-no-debug", """
import javax.servlet.http.*;
public class StatusServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        resp.getWriter().write("OK");  // SAFE — no sensitive info
    }
}
""", "CWE-489", False),

    # ═══ CWE-521: Weak Password Requirements ═══
    ("cwe521-real-weak-password", """
public class PasswordValidator {
    public boolean isValid(String password) {
        return password.length() >= 4;  // REAL — too weak
    }
}
""", "CWE-521", True),
    ("cwe521-safe-strong-password", """
public class StrongPasswordValidator {
    public boolean isValid(String password) {
        return password.length() >= 12 && password.matches(".*[A-Z].*") 
            && password.matches(".*[0-9].*") && password.matches(".*[^a-zA-Z0-9].*");
    }
}
""", "CWE-521", False),

    # ═══ CWE-319: Cleartext Transmission ═══
    ("cwe319-real-cleartext-jdbc", """
public class DbConnector {
    public Connection connect() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://db.example.com:3306/mydb", "user", "pass");
        // REAL — no useSSL, no verifyServerCertificate
    }
}
""", "CWE-319", True),
    ("cwe319-safe-tls-jdbc", """
public class SecureDbConnector {
    public Connection connect() throws Exception {
        return DriverManager.getConnection(
            "jdbc:mysql://db.example.com:3306/mydb?useSSL=true&verifyServerCertificate=true", "user", "pass");
    }
}
""", "CWE-319", False),

    # ═══ CWE-73: External Control of File Name ═══
    ("cwe73-real-file-name", """
import javax.servlet.http.*;
import java.io.*;
public class ReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String report = req.getParameter("report");
        File f = new File("/var/reports/" + report + ".pdf");  // REAL
        Files.copy(f.toPath(), resp.getOutputStream());
    }
}
""", "CWE-73", True),
    ("cwe73-safe-basename", """
import javax.servlet.http.*;
import java.io.*;
public class SafeReportServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String report = new File(req.getParameter("report")).getName();
        File f = new File("/var/reports/" + report);
        Files.copy(f.toPath(), resp.getOutputStream());
    }
}
""", "CWE-73", False),

    # ═══ CWE-91: XML Injection ═══
    ("cwe91-real-xml-injection", """
public class XmlBuilder {
    public String buildXml(String userData) {
        return "<user><name>" + userData + "</name></user>";  // REAL XML injection
    }
}
""", "CWE-91", True),
    ("cwe91-safe-escaped", """
import org.apache.commons.text.StringEscapeUtils;
public class SafeXmlBuilder {
    public String buildXml(String userData) {
        return "<user><name>" + StringEscapeUtils.escapeXml10(userData) + "</name></user>";
    }
}
""", "CWE-91", False),

    # ═══ CWE-208: Timing Attack ═══
    ("cwe208-real-timing-leak", """
public class TokenValidator {
    public boolean checkToken(String input, String stored) {
        return input.equals(stored);  // REAL timing attack vector
    }
}
""", "CWE-208", True),
    ("cwe208-safe-constant-time", """
import java.security.MessageDigest;
public class SafeTokenValidator {
    public boolean checkToken(String input, String stored) {
        return MessageDigest.isEqual(input.getBytes(), stored.getBytes());
    }
}
""", "CWE-208", False),

    # ═══ CWE-306: Missing Authentication on Critical Function ═══
    ("cwe306-real-no-auth", """
import javax.servlet.http.*;
public class AdminServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        resp.getWriter().write(File.readString("/etc/passwd"));  // REAL — no auth
    }
}
""", "CWE-306", True),
    ("cwe306-safe-authenticated", """
import javax.servlet.http.*;
public class SafeAdminServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        if (req.getSession().getAttribute("user") == null) { resp.sendError(401); return; }
        resp.getWriter().write("OK");
    }
}
""", "CWE-306", False),

    # ═══ CWE-312: Cleartext Storage of Sensitive Data ═══
    ("cwe312-real-cleartext-storage", """
import java.io.*;
public class CredentialStore {
    public void save(String password) throws Exception {
        Files.writeString(Path.of("/tmp/passwords.txt"), password);  // REAL cleartext storage
    }
}
""", "CWE-312", True),
    ("cwe312-safe-hashed", """
import java.security.MessageDigest;
import java.io.*;
public class SafeCredentialStore {
    public void save(String password) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(password.getBytes());
        Files.write(Path.of("/tmp/passwords.hash"), hash);
    }
}
""", "CWE-312", False),

    # ═══ CWE-326: Inadequate Encryption Strength ═══
    ("cwe326-real-weak-key-size", """
import javax.crypto.*;
public class WeakEncryption {
    public byte[] encrypt(byte[] data) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(64);  // REAL — 64-bit key is too weak
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, kg.generateKey());
        return c.doFinal(data);
    }
}
""", "CWE-326", True),
    ("cwe326-safe-strong-key", """
import javax.crypto.*;
public class StrongEncryption {
    public byte[] encrypt(byte[] data) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);  // SAFE — 256-bit key
        return Cipher.getInstance("AES").doFinal(data);
    }
}
""", "CWE-326", False),

    # ═══ CWE-400: Resource Exhaustion ═══
    ("cwe400-real-unbounded-loop", """
import javax.servlet.http.*;
public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        int limit = Integer.parseInt(req.getParameter("limit"));
        for (int i = 0; i < limit; i++) { doWork(); }  // REAL — unbounded loop
    }
    void doWork() {}
}
""", "CWE-400", True),
    ("cwe400-safe-bounded", """
import javax.servlet.http.*;
public class SafeSearchServlet extends HttpServlet {
    private static final int MAX = 100;
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        int limit = Math.min(Integer.parseInt(req.getParameter("limit")), MAX);
        for (int i = 0; i < limit; i++) { doWork(); }
    }
    void doWork() {}
}
""", "CWE-400", False),

    # ═══ CWE-470: Unsafe Reflection ═══
    ("cwe470-real-unsafe-reflection", """
import javax.servlet.http.*;
public class DynamicInvoker extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String className = req.getParameter("class");
        Class.forName(className).getMethod("run").invoke(null);  // REAL unsafe reflection
    }
}
""", "CWE-470", True),
    ("cwe470-safe-allowlist", """
import javax.servlet.http.*;
import java.util.Set;
public class SafeDynamicInvoker extends HttpServlet {
    private static final Set<String> ALLOWED = Set.of("TaskA", "TaskB");
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        String name = req.getParameter("class");
        if (!ALLOWED.contains(name)) { return; }
        Class.forName("com.example." + name).getMethod("run").invoke(null);
    }
}
""", "CWE-470", False),

    # ═══ CWE-477: Use of Deprecated Function ═══
    ("cwe477-real-deprecated", """
import javax.servlet.http.*;
public class LegacyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String sessionId = req.getRequestedSessionId();  // REAL — deprecated, uses URL rewriting
        resp.getWriter().write(sessionId);
    }
}
""", "CWE-477", True),
    ("cwe477-safe-modern", """
import javax.servlet.http.*;
public class ModernServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) {
        String sessionId = req.getSession().getId();  // SAFE — modern API
        resp.getWriter().write(sessionId);
    }
}
""", "CWE-477", False),

    # ═══ CWE-732: Incorrect Permission Assignment ═══
    ("cwe732-real-world-writable", """
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
public class FileCreator {
    public void create(String path) throws Exception {
        Files.createFile(Path.of(path));
        Files.setPosixFilePermissions(Path.of(path), 
            PosixFilePermissions.fromString("rw-rw-rw-"));  // REAL — world-writable
    }
}
""", "CWE-732", True),
    ("cwe732-safe-restricted", """
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
public class SafeFileCreator {
    public void create(String path) throws Exception {
        Files.createFile(Path.of(path));
        Files.setPosixFilePermissions(Path.of(path),
            PosixFilePermissions.fromString("rw-------"));  // SAFE — owner only
    }
}
""", "CWE-732", False),
]


def run_benchmark():
    results = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "cases": []})

    for name, code, expected_cwe, is_real in CASES:
        result = scan_code(code, language="java", filename=f"{name}.java")
        found_cwes = set()
        for finding in result.findings:
            if finding.cwe:
                found_cwes.add(finding.cwe)

        found_expected = expected_cwe in found_cwes if expected_cwe else len(found_cwes) == 0
        # For FP cases (is_real=False), "correct" means the scanner did NOT flag the expected CWE
        correct = found_expected if is_real else (not found_expected)

        if is_real:
            if found_expected:
                results[expected_cwe or "clean"]["tp"] += 1
            else:
                results[expected_cwe or "clean"]["fn"] += 1
        else:
            if expected_cwe and expected_cwe in found_cwes:
                results[expected_cwe]["fp"] += 1
            elif expected_cwe is None and len(found_cwes) > 0:
                # Flagged something on clean code
                for cwe in found_cwes:
                    results[cwe]["fp"] += 1
            else:
                results[expected_cwe or "clean"]["tn"] += 1

        results[expected_cwe or "clean"]["cases"].append({
            "name": name,
            "expected": expected_cwe,
            "found": list(found_cwes),
            "is_real": is_real,
            "correct": correct,
        })

    print("=" * 70)
    print("PER-RULE PRECISION BENCHMARK")
    print("=" * 70)
    print(f"  {len(CASES)} test cases across {len(set(r for r in results if r!='clean'))} CWEs")
    print()

    total_tp = total_fp = total_fn = total_tn = 0

    for cwe in sorted(results.keys()):
        r = results[cwe]
        tp, fp, tn, fn = r["tp"], r["fp"], r["tn"], r["fn"]
        total = tp + fp + tn + fn
        precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 100
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 100
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        total_tp += tp; total_fp += fp; total_fn += fn; total_tn += tn

        label = cwe if cwe else "(no finding expected)"
        print(f"  {label:25s} | TP={tp:2d} FP={fp:2d} TN={tn:2d} FN={fn:2d} | P={precision:5.1f}% R={recall:5.1f}% F1={f1:5.1f}%")

        # Show failing cases
        for case in r["cases"]:
            if not case["correct"]:
                marker = "MISSED" if case["is_real"] else "FP"
                print(f"    X {marker}: {case['name']} (expected {case['expected']}, found {case['found']})")

    total_all = total_tp + total_fp + total_fn + total_tn
    overall_precision = total_tp / (total_tp + total_fp) * 100 if (total_tp + total_fp) > 0 else 100
    overall_recall = total_tp / (total_tp + total_fn) * 100 if (total_tp + total_fn) > 0 else 100
    overall_f1 = 2 * overall_precision * overall_recall / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0

    print()
    print(f"  {'OVERALL':25s} | TP={total_tp:2d} FP={total_fp:2d} TN={total_tn:2d} FN={total_fn:2d} | P={overall_precision:5.1f}% R={overall_recall:5.1f}% F1={overall_f1:5.1f}%")
    print()
    print("=" * 70)
    print("HONEST RATING")
    print("=" * 70)

    if overall_f1 >= 90:
        grade = "A — World-class. Ship it."
    elif overall_f1 >= 75:
        grade = "B — Production-ready. Minor FP patterns remain."
    elif overall_f1 >= 60:
        grade = "C — Usable with review. Several FP patterns need fixing."
    elif overall_f1 >= 40:
        grade = "D — Needs work. Significant FP/FN issues."
    else:
        grade = "F — Not production-ready. Major gaps."

    print(f"  Overall F1: {overall_f1:.1f}%")
    print(f"  Grade: {grade}")
    print(f"  Precision: {overall_precision:.1f}% ({total_tp} TP / {total_tp+total_fp} flagged)")
    print(f"  Recall:    {overall_recall:.1f}% ({total_tp} TP / {total_tp+total_fn} real)")

    return results, overall_precision, overall_recall, overall_f1


if __name__ == "__main__":
    t0 = time.time()
    results, prec, rec, f1 = run_benchmark()
    elapsed = time.time() - t0

    # Save results
    output = Path(__file__).parent / "audit_results" / "per_rule_precision.json"
    serializable = {
        "summary": {"precision": round(prec, 1), "recall": round(rec, 1), "f1": round(f1, 1),
                     "elapsed_s": round(elapsed, 2), "cases": len(CASES)},
        "per_cwe": {cwe: {"tp": r["tp"], "fp": r["fp"], "tn": r["tn"], "fn": r["fn"]}
                    for cwe, r in results.items()},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(serializable, indent=2))
    print(f"\n  Results saved: {output}")
    print(f"  Time: {elapsed:.1f}s")

# Ansede World-Best Implementation Plan

> **Goal:** Achieve statistical dominance across every language, for every CWE, against every benchmark. No gaps. No blind spots. No excuses.

> **Generated:** 2026-07-13 | **Status:** Blueprint Complete | **Estimated Total Effort:** ~14 days

---

## Table of Contents

1. [Phase 0: Rust Core — Add PHP/Ruby/Rust Tree-sitter](#phase-0)
2. [Phase 1: PHP AST Analyzer](#phase-1)
3. [Phase 2: Ruby AST Analyzer](#phase-2)
4. [Phase 3: Rust AST Analyzer](#phase-3)
5. [Phase 4: JavaScript SSA via Pratt CFG](#phase-4)
6. [Phase 5: Java Andersen-Style Points-to Analysis](#phase-5)
7. [Phase 6: Cross-Language Validation Suite](#phase-6)
8. [Cross-Reference: External Research & Competitive Comparison](#cross-reference)
9. [Acceptance Gates](#acceptance-gates)

---

## <a name="phase-0"></a>Phase 0: Rust Core — Add PHP/Ruby/Rust Tree-sitter

### 0.1 Dependencies (`Cargo.toml`)

Add three new tree-sitter grammars alongside existing ones:

```toml
tree-sitter-php = "0.23"
tree-sitter-ruby = "0.23"
tree-sitter-rust = "0.24"
```

**Why these versions:** `tree-sitter-php` v0.23+ supports PHP 8.3+ syntax (enums, readonly classes, named arguments, match expressions, asymmetric visibility). `tree-sitter-ruby` v0.23+ supports Ruby 3.3+ syntax (pattern matching, endless methods, ractors). `tree-sitter-rust` v0.24+ supports Rust 2024 edition syntax.

**Cross-ref:** All three are maintained by the `tree-sitter` GitHub org (same org as the 5 existing grammars). They use the same ABI version (`tree-sitter 0.25`), same CI pipeline, same publish workflow. Zero compatibility risk.

### 0.2 `lib.rs` Changes

#### 0.2.1 Add match arms to `parse_with_language()`:

```rust
"php" | "php7" | "php8" => tree_sitter_php::LANGUAGE.into(),
"ruby" | "rb" => tree_sitter_ruby::LANGUAGE.into(),
"rust" | "rs" => tree_sitter_rust::LANGUAGE.into(),
```

**Location:** After the existing `"csharp" | "c#" | "cs"` arm (line ~30 in current `lib.rs`).

#### 0.2.2 Add `fast_triage` support for new languages:

The existing `fast_triage` function (if present) must be extended to dispatch to the new grammars. If it uses a static mapping, add entries for `php`, `ruby`, `rust`.

#### 0.2.3 Add `fast_pattern_rules` language dispatch:

If the `fast_pattern_rules` function has a language-specific comment regex, add:
- PHP: `r"^\s*(#|//|/\*|\*|<!--)"` (same as existing — PHP uses `#`, `//`, `/* */`)
- Ruby: `r"^\s*(#)"` (Ruby only uses `#` for comments)
- Rust: `r"^\s*(//|/\*|\*|///)"` (Rust uses `//`, `/* */`, `///` for doc comments)

### 0.3 Python-side Bridge (`rust_parser.py`)

No changes needed. The existing `_native_parse` function calls `parse_code_dict` which dispatches to `parse_with_language`. The new languages are handled transparently.

### 0.4 Build & Test

```bash
cd ansede_rust_core
cargo build --release
cd ..
python -c "from ansede_static.engine.rust_parser import fast_parse; print(fast_parse('<?php echo $_GET[\"x\"];', 'php', 'test.php'))"
```

**Acceptance Gate:** The above command prints a dict with `nodes`, `language: "php"`, `lines_scanned: 1`, `node_count > 0`.

---

## <a name="phase-1"></a>Phase 1: PHP AST Analyzer

### 1.1 Architecture

Model after the Go analyzer's two-layer approach:
- **Layer 1:** Rust tree-sitter parses to flat node table (via `fast_parse`)
- **Layer 2:** Python walks the flat table to build typed `PHPFile` dataclass
- **Layer 3:** Pattern matchers walk the typed AST for vulnerability detection

### 1.2 File Structure

```
src/ansede_static/php_engine/
├── __init__.py          # Public API: analyze_php()
├── php_ast_nodes.py     # Typed dataclasses for PHP AST
├── php_parser.py        # Flat table → typed AST conversion
├── php_sinks.py         # Sink catalogue (echo, exec, mysqli_query, etc.)
├── php_taint.py         # Taint source/sink/propagation tracking
├── php_routes.py        # Framework route detection (Laravel, Symfony, Slim)
└── php_patterns.py      # AST-walking vulnerability detectors
```

### 1.3 Typed AST Nodes (`php_ast_nodes.py`)

```python
@dataclass
class PHPFile:
    """Top-level PHP file node."""
    decls: list[PHPFunction | PHPClass | PHPTrait | PHPInterface | PHPUseStmt]
    inline_code: list[PHPStmt]  # code outside any function/class

@dataclass  
class PHPFunction:
    name: str
    params: list[PHPParam]
    body: list[PHPStmt]
    return_type: str | None
    visibility: str  # "public" | "protected" | "private" | "" (for global functions)
    line: int

@dataclass
class PHPClass:
    name: str
    extends: str | None
    implements: list[str]
    methods: list[PHPFunction]
    properties: list[PHPProperty]
    line: int

@dataclass
class PHPCall:
    callee: str            # Full qualified call: "mysqli_query", "$db->query", "User::find"
    args: list[PHPExpr]
    is_method: bool         # True for $obj->method(), False for func()
    is_static: bool         # True for Class::method()
    receiver: str | None    # For method calls: "$db" or "self"
    line: int

@dataclass
class PHPExpr:
    kind: str              # "variable", "string", "int", "binary_op", "call", "array", "subscript"
    value: str
    children: list[PHPExpr]
    line: int
```

### 1.4 Sink Catalogue (`php_sinks.py`)

PHP-specific sinks with module qualification (following the v6.3+ pattern already established for Python):

```python
PHP_SINKS: dict[str, tuple[str, str]] = {
    # Command Injection — CWE-78
    "system":              ("CWE-78", "OS Command Injection"),
    "exec":                ("CWE-78", "OS Command Injection"),
    "shell_exec":          ("CWE-78", "OS Command Injection"),
    "passthru":            ("CWE-78", "OS Command Injection"),
    "popen":               ("CWE-78", "OS Command Injection"),
    "proc_open":           ("CWE-78", "OS Command Injection"),
    "pcntl_exec":          ("CWE-78", "OS Command Injection"),
    "assert":              ("CWE-95", "Code Injection via assert()"),
    
    # SQL Injection — CWE-89
    "mysqli_query":        ("CWE-89", "SQL Injection (mysqli)"),
    "mysql_query":         ("CWE-89", "SQL Injection (mysql)"),
    "pg_query":            ("CWE-89", "SQL Injection (PostgreSQL)"),
    "sqlsrv_query":        ("CWE-89", "SQL Injection (SQL Server)"),
    "odbc_exec":           ("CWE-89", "SQL Injection (ODBC)"),
    "PDO.query":           ("CWE-89", "SQL Injection (PDO)"),
    "PDO.exec":            ("CWE-89", "SQL Injection (PDO exec)"),
    "DB.query":            ("CWE-89", "SQL Injection (Laravel DB raw)"),
    "DB.select":           ("CWE-89", "SQL Injection (Laravel DB select)"),
    "DB::statement":       ("CWE-89", "SQL Injection (Laravel DB statement)"),
    "Eloquent.whereRaw":   ("CWE-89", "SQL Injection (Eloquent whereRaw)"),
    "Eloquent.orderByRaw": ("CWE-89", "SQL Injection (Eloquent orderByRaw)"),
    
    # XSS — CWE-79
    "echo":                ("CWE-79", "Cross-Site Scripting (echo)"),
    "print":               ("CWE-79", "Cross-Site Scripting (print)"),
    "printf":              ("CWE-79", "Cross-Site Scripting (printf)"),
    
    # Path Traversal — CWE-22
    "file_get_contents":   ("CWE-22", "Path Traversal"),
    "file_put_contents":   ("CWE-22", "Path Traversal"),
    "fopen":               ("CWE-22", "Path Traversal"),
    "include":             ("CWE-22", "Path Traversal / Local File Inclusion"),
    "require":             ("CWE-22", "Path Traversal / Local File Inclusion"),
    "include_once":        ("CWE-22", "Path Traversal / LFI"),
    "require_once":        ("CWE-22", "Path Traversal / LFI"),
    "readfile":            ("CWE-22", "Path Traversal"),
    
    # Deserialization — CWE-502
    "unserialize":         ("CWE-502", "Unsafe Deserialization"),
    
    # SSRF — CWE-918
    "file_get_contents":   ("CWE-918", "Server-Side Request Forgery (URL wrapper)"),
    "curl_exec":           ("CWE-918", "Server-Side Request Forgery (cURL)"),
    "curl_setopt.*CURLOPT_URL": ("CWE-918", "Server-Side Request Forgery (cURL option)"),
    "GuzzleHttp.Client.request": ("CWE-918", "SSRF (Guzzle HTTP client)"),
    "HttpClient.send":     ("CWE-918", "SSRF (Symfony HTTP client)"),
    
    # XXE — CWE-611
    "simplexml_load_string": ("CWE-611", "XML External Entity"),
    "simplexml_load_file":   ("CWE-611", "XML External Entity"),
    "DOMDocument.loadXML":   ("CWE-611", "XML External Entity"),
    "DOMDocument.load":      ("CWE-611", "XML External Entity"),
    
    # Code Injection — CWE-94/95
    "eval":                ("CWE-95", "Code Injection via eval()"),
    "create_function":     ("CWE-95", "Code Injection via create_function()"),
    "preg_replace.*e":     ("CWE-95", "Code Injection via preg_replace /e modifier"),
}
```

### 1.5 Taint Sources

```python
PHP_TAINT_SOURCES: dict[str, str] = {
    # Superglobals
    "$_GET":          "HTTP GET parameter",
    "$_POST":         "HTTP POST parameter",
    "$_REQUEST":      "HTTP request parameter",
    "$_COOKIE":       "HTTP cookie",
    "$_FILES":        "Uploaded file",
    "$_SERVER":       "Server/environment variable",
    "$_ENV":          "Environment variable",
    "$_SESSION":      "Session data (may contain user input)",
    
    # Input functions
    "file_get_contents": "File contents (may be attacker-controlled with wrappers)",
    "fgets":           "File/stdin input",
    "fread":           "File input",
    "php://input":     "Raw HTTP request body",
    "getenv":          "Environment variable",
    "getallheaders":   "All HTTP headers",
    
    # Framework sources
    "request.input":   "Laravel request input",
    "request.all":     "Laravel all request data",
    "request.query":   "Laravel query parameters",
    "request.post":    "Laravel POST data",
    "request.json":    "Laravel JSON body",
    "$request.query":  "Symfony request query",
    "$request.request":"Symfony request data",
    
    # Database (propagation sources)
    "fetch":           "Database row (may propagate taint)",
    "fetchAll":        "Database rows (may propagate taint)",
    "fetch_assoc":     "Database row (may propagate taint)",
    "mysql_fetch_assoc":"MySQL result row (may propagate taint)",
    "mysqli_fetch_assoc":"MySQLi result row (may propagate taint)",
    "PDOStatement.fetch":"PDO result row (may propagate taint)",
    "PDOStatement.fetchAll":"PDO result rows (may propagate taint)",
}
```

### 1.6 Framework Detection

PHP has several major frameworks with distinct route/auth patterns:

#### Laravel
```php
// Route: Route::get('/path', [Controller::class, 'method']);
// Route: Route::post('/path', function() { ... });
// Auth middleware: Route::get(...)->middleware('auth');
// Controller auth: $this->middleware('auth');
// Auth check: auth()->check(), Auth::check()
// User scope: auth()->user(), Auth::id(), $request->user()
```

#### Symfony
```php
// Route: #[Route('/path', methods: ['GET'])]
// Security: #[IsGranted('ROLE_ADMIN')]
// Auth check: $this->getUser(), $this->isGranted('ROLE_USER')
```

#### Slim Framework
```php
// Route: $app->get('/path', function($request, $response) { ... });
// Middleware: $app->add($authMiddleware);
```

#### Detection Heuristics (via AST walk):
1. Detect `use Illuminate\Support\Facades\Route` → Laravel
2. Detect `use Symfony\Component\Routing\Annotation\Route` → Symfony
3. Detect `$app = new \Slim\App` → Slim

### 1.7 Analysis Pipeline

```
PHP source code
    │
    ▼
Rust tree-sitter → flat node table (via fast_parse)
    │
    ▼
php_parser.build_php_file(flat_table) → PHPFile
    │
    ├─→ php_routes.detect_routes(php_file) → list[RouteDef]
    ├─→ php_taint.extract_taint_sources(php_file) → dict[name, source]
    ├─→ php_taint.propagate_taint(php_file, sources) → taint_map
    ├─→ php_sinks.check_sinks(php_file, taint_map) → list[Finding]
    ├─→ php_patterns.detect_hardcoded_secrets(php_file) → list[Finding]
    ├─→ php_patterns.detect_weak_crypto(php_file) → list[Finding]
    └─→ php_patterns.detect_missing_auth(routes, php_file) → list[Finding]
    │
    ▼
dedup + cluster + rescore → list[Finding]
```

### 1.8 Edge Cases & Gotchas

| Edge Case | Handling |
|---|---|
| `$$var` (variable variables) | If `$var` is tainted, mark all `$$var` accesses as tainted (conservative) |
| `extract($_GET)` | Special-case: if `extract()` called with superglobal, mark all subsequent variables as potentially tainted |
| `eval("?>".$code)` | PHP close-tag re-entry — treat `eval()` with concatenation as CWE-95 |
| `include $path . ".php"` | Path traversal — `.php` suffix doesn't prevent directory traversal |
| Heredoc/Nowdoc strings | Treat as string literals; scan for interpolation `${var}` |
| `@` error suppression | `@unserialize($data)` — operator doesn't change security semantics |
| Anonymous functions / closures | Parse as `PHPFunction` with empty name; track `use()` variable capture |
| `compact('var1', 'var2')` | Laravel view data — treat as taint propagation of named variables |
| PHP 8.1+ enums | Parse as `PHPEnum`; ignore for taint (they're value types) |
| PHP 8.0+ named arguments | `fn(name: $tainted)` — track argument position from parameter name |

### 1.9 Acceptance Gate (Phase 1)

```bash
# Must detect CWE-78 in PHP shell injection
ansede-static --format json tests/fixtures/php/cmd_injection.php | python -c "import json,sys; d=json.load(sys.stdin); assert any(f['cwe']=='CWE-78' for r in d['results'] for f in r['findings']), 'CWE-78 not detected'"

# Must NOT fire on benign code
ansede-static --format json tests/fixtures/php/benign_echo.php | python -c "import json,sys; d=json.load(sys.stdin); findings=[f for r in d['results'] for f in r['findings'] if f['severity'] in ('critical','high')]; assert len(findings)==0, f'False positives: {findings}'"
```

---

## <a name="phase-2"></a>Phase 2: Ruby AST Analyzer

### 2.1 Architecture

Same two-layer approach as PHP. The Ruby grammar is more complex due to:
- Blocks (do...end and { })
- Implicit returns
- Metaprogramming (method_missing, define_method, class_eval)
- DSL-heavy frameworks (Rails, Sinatra)

### 2.2 File Structure

```
src/ansede_static/ruby_engine/
├── __init__.py
├── ruby_ast_nodes.py
├── ruby_parser.py
├── ruby_sinks.py
├── ruby_taint.py
├── ruby_routes.py      # Rails/Sinatra route detection
└── ruby_patterns.py
```

### 2.3 Typed AST Nodes

Key Ruby-specific nodes beyond the standard function/class/call:

```python
@dataclass
class RubyBlock:
    """Ruby block: do |x, y| ... end or { |x, y| ... }"""
    params: list[str]
    body: list[RubyStmt]
    line: int

@dataclass
class RubyModule:
    """Ruby module declaration."""
    name: str
    methods: list[RubyMethod]
    line: int

@dataclass
class RubyDSLCall:
    """Framework DSL call: `get '/path' do ... end` or `before_action :authorize`"""
    receiver: str | None   # nil for implicit self
    method: str            # "get", "post", "before_action", "validates", etc.
    args: list[RubyExpr]
    block: RubyBlock | None
    line: int

@dataclass  
class RubySymbol:
    """Ruby symbol: :foo, :"foo bar" """
    name: str
    line: int

@dataclass
class RubyHash:
    """Ruby hash literal: { key: value, 'key' => value }"""
    pairs: list[tuple[RubyExpr, RubyExpr]]
    line: int
```

### 2.4 Rails-Specific Detection

Rails uses convention-over-configuration. Key patterns:

#### Routes (`config/routes.rb`)
```ruby
# DSL pattern: verb 'path', to: 'controller#action'
get 'users/:id', to: 'users#show'
post 'users', to: 'users#create'
resources :users   # expands to 7 RESTful routes
namespace :admin do
  resources :users  # Admin::UsersController
end
```

**Detection:** Walk `RubyDSLCall` nodes for `get`, `post`, `put`, `patch`, `delete`, `match`, `resources`, `resource`, `namespace`, `scope`. Extract controller and action from `to:` argument.

#### Controllers (`app/controllers/*.rb`)
```ruby
class UsersController < ApplicationController
  before_action :authenticate_user!   # Auth guard
  before_action :set_user, only: [:show, :edit, :update, :destroy]  # Ownership fetch
  skip_before_action :authenticate_user!, only: [:index]  # Explicit opt-out
  
  def show
    @user = User.find(params[:id])  # IDOR risk if no ownership check
  end
  
  def update
    @user.update(user_params)  # Mass assignment risk
  end
  
  private
  def user_params
    params.require(:user).permit(:name, :email)  # Strong parameters
  end
end
```

**Detection:**
1. Parse `before_action`/`skip_before_action` calls to build auth guard map
2. Check each public method against auth guards
3. Detect `Model.find(params[:id])` without ownership scope → CWE-639 (IDOR)
4. Detect `params.permit!` or `.update(params)` without `.require().permit()` → CWE-915 (Mass Assignment)
5. Detect `protect_from_forgery with: :exception` absence → CWE-352 (CSRF)

#### Models (`app/models/*.rb`)
```ruby
class User < ApplicationRecord
  # Dangerous: raw SQL
  User.where("name = '#{params[:name]}'")   # CWE-89
  User.find_by_sql("SELECT * FROM users WHERE name = '#{params[:name]}'")  # CWE-89
  
  # Safe: parameterized
  User.where(name: params[:name])
  User.find_by(name: params[:name])
  
  # Dangerous: unsafe deserialization
  Marshal.load(params[:data])   # CWE-502
  YAML.load(params[:yaml])      # CWE-502
  
  # Dangerous: command injection
  system("ls #{params[:dir]}")  # CWE-78
  `ls #{params[:dir]}`          # CWE-78 (backticks)
  %x(ls #{params[:dir]})        # CWE-78 (%x literal)
end
```

### 2.5 Ruby Sink Catalogue

```python
RUBY_SINKS: dict[str, tuple[str, str]] = {
    # Command Injection — CWE-78
    "system":           ("CWE-78", "OS Command Injection"),
    "exec":             ("CWE-78", "OS Command Injection"),
    "spawn":            ("CWE-78", "OS Command Injection"),
    "`":                ("CWE-78", "OS Command Injection (backticks)"),
    "%x":               ("CWE-78", "OS Command Injection (%x literal)"),
    "Open3.capture2":   ("CWE-78", "OS Command Injection (Open3)"),
    "Open3.capture3":   ("CWE-78", "OS Command Injection (Open3)"),
    "Open3.popen3":     ("CWE-78", "OS Command Injection (Open3)"),
    "IO.popen":         ("CWE-78", "OS Command Injection"),
    
    # SQL Injection — CWE-89
    "ActiveRecord.where":       ("CWE-89", "SQL Injection (string interpolation in where)"),
    "ActiveRecord.find_by_sql": ("CWE-89", "SQL Injection (find_by_sql)"),
    "ActiveRecord.execute":     ("CWE-89", "SQL Injection (raw execute)"),
    "Sequel.where":             ("CWE-89", "SQL Injection (Sequel)"),
    "Sequel.fetch":             ("CWE-89", "SQL Injection (Sequel)"),
    
    # Code Injection — CWE-94/95
    "eval":             ("CWE-95", "Code Injection via eval()"),
    "instance_eval":    ("CWE-95", "Code Injection via instance_eval()"),
    "class_eval":       ("CWE-95", "Code Injection via class_eval()"),
    "module_eval":      ("CWE-95", "Code Injection via module_eval()"),
    
    # Deserialization — CWE-502
    "Marshal.load":     ("CWE-502", "Unsafe Deserialization (Marshal)"),
    "Marshal.restore":  ("CWE-502", "Unsafe Deserialization (Marshal)"),
    "YAML.load":        ("CWE-502", "Unsafe Deserialization (YAML.load)"),
    "Psych.load":       ("CWE-502", "Unsafe Deserialization (Psych)"),
    "Oj.load":          ("CWE-502", "Unsafe Deserialization (Oj without safe mode)"),
    
    # Path Traversal — CWE-22
    "File.read":        ("CWE-22", "Path Traversal"),
    "File.open":        ("CWE-22", "Path Traversal"),
    "File.join":        ("CWE-22", "Path Traversal"),
    "Dir.glob":         ("CWE-22", "Path Traversal"),
    "send_file":        ("CWE-22", "Path Traversal (Rails send_file)"),
    "send_data":        ("CWE-22", "Path Traversal (Rails send_data)"),
    
    # SSRF — CWE-918
    "Net::HTTP.get":    ("CWE-918", "SSRF (Net::HTTP)"),
    "Net::HTTP.post":   ("CWE-918", "SSRF (Net::HTTP)"),
    "HTTParty.get":     ("CWE-918", "SSRF (HTTParty)"),
    "HTTParty.post":    ("CWE-918", "SSRF (HTTParty)"),
    "Faraday.get":      ("CWE-918", "SSRF (Faraday)"),
    "Faraday.post":     ("CWE-918", "SSRF (Faraday)"),
    "RestClient.get":   ("CWE-918", "SSRF (RestClient)"),
    "open-uri.open":    ("CWE-918", "SSRF (open-uri)"),
    "URI.parse":        ("CWE-918", "SSRF (URI.parse with user input)"),
    
    # XSS — CWE-79
    "raw":              ("CWE-79", "XSS (Rails raw helper)"),
    "html_safe":        ("CWE-79", "XSS (Rails html_safe)"),
    "content_tag":      ("CWE-79", "XSS (Rails content_tag with unescaped content)"),
    
    # Open Redirect — CWE-601
    "redirect_to":      ("CWE-601", "Open Redirect (Rails)"),
    
    # Mass Assignment — CWE-915
    "ActiveRecord.permit!":     ("CWE-915", "Mass Assignment (Rails permit!)"),
    "ActiveRecord.update":      ("CWE-915", "Mass Assignment (Rails update without strong params)"),
    "ActiveRecord.update_all":  ("CWE-915", "Mass Assignment (Rails update_all)"),
    
    # Log Injection — CWE-117
    "Rails.logger.info":    ("CWE-117", "Log Injection"),
    "Rails.logger.warn":    ("CWE-117", "Log Injection"),
    "Rails.logger.error":   ("CWE-117", "Log Injection"),
}
```

### 2.6 Edge Cases & Gotchas

| Edge Case | Handling |
|---|---|
| Implicit `self` receiver | `get '/path'` inside a controller class → receiver is `self` (the controller) |
| Method missing interception | `def method_missing(m, *args)` → mark all dynamic method calls as potentially dangerous |
| `define_method(:foo) { \|x\| ... }` | Treat as function declaration with block params |
| `class << self` (singleton class) | Methods defined here are class methods — track for auth guards |
| `alias_method :new_name, :old_name` | Propagate auth/sanitizer annotations from old_name to new_name |
| `send(method_name, *args)` | If method_name is tainted → CWE-95 (dynamic dispatch injection) |
| `render inline: "<%= params[:x] %>"` | Rails inline template with user input → CWE-79 SSTI |
| `render file: "/etc/passwd"` | Path traversal via template rendering |
| `before_action only: [:show, :edit]` | `only:` and `except:` modify which actions the guard applies to |
| `params.dig(:user, :profile, :name)` | Taint propagates through `dig` — all extracted values are tainted |

### 2.7 Acceptance Gate (Phase 2)

```bash
# Must detect CWE-502 in Rails controller
ansede-static tests/fixtures/ruby/unsafe_deserialization.rb | grep "CWE-502"

# Must detect missing before_action on admin route
ansede-static tests/fixtures/ruby/admin_controller_no_auth.rb | grep "CWE-862"

# Must detect mass assignment without strong params
ansede-static tests/fixtures/ruby/mass_assignment.rb | grep "CWE-915"
```

---

## <a name="phase-3"></a>Phase 3: Rust AST Analyzer

### 3.1 Architecture

Rust's security model is fundamentally different from PHP/Ruby. Memory safety bugs (buffer overflows, use-after-free) are prevented by the compiler. The remaining security concerns are:

1. **`unsafe` blocks** — CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)
2. **Command injection** via `std::process::Command` — CWE-78
3. **Hardcoded secrets** — CWE-798
4. **Weak cryptography** (deprecated crates) — CWE-327
5. **TOCTOU race conditions** (filesystem) — CWE-362
6. **Unsafe deserialization** (serde with unsafe deserializers) — CWE-502
7. **Panic safety** (unwrap on untrusted input) — CWE-248

### 3.2 File Structure

```
src/ansede_static/rust_engine/
├── __init__.py
├── rust_ast_nodes.py
├── rust_parser.py
├── rust_sinks.py
├── rust_taint.py
├── rust_unsafe.py       # unsafe block analysis
├── rust_crypto.py        # Weak crypto detection
└── rust_patterns.py
```

### 3.3 Typed AST Nodes

```python
@dataclass
class RustFile:
    modules: list[RustModule]
    crate_attrs: list[str]  # #[macro_use], #![no_std], etc.
    uses: list[RustUse]     # use statements

@dataclass
class RustFn:
    name: str
    params: list[RustParam]
    return_type: str | None
    body: list[RustStmt]
    is_unsafe: bool
    is_async: bool
    is_pub: bool
    attrs: list[str]   # #[inline], #[cfg(test)], etc.
    line: int

@dataclass
class RustUnsafeBlock:
    body: list[RustStmt]
    line: int

@dataclass
class RustCall:
    callee: str             # Full path: "std::process::Command::new"
    args: list[RustExpr]
    type_args: list[str]    # Turbofish: ::<T>
    is_method: bool
    line: int

@dataclass
class RustMacroInvocation:
    macro_name: str         # "println!", "vec!", "format!"
    args: list[RustExpr]
    line: int

@dataclass
class RustMatchArm:
    pattern: str
    guard: str | None       # if condition
    body: list[RustStmt]
    line: int
```

### 3.4 Rust-Specific Detectors

#### 3.4.1 `unsafe` Block Analysis (`rust_unsafe.py`)

```python
UNSAFE_SINK_FUNCTIONS: frozenset[str] = frozenset({
    "std::ptr::read", "std::ptr::write", "std::ptr::copy",
    "std::ptr::copy_nonoverlapping", "std::mem::transmute",
    "std::slice::from_raw_parts", "std::slice::from_raw_parts_mut",
    "std::str::from_utf8_unchecked", "std::str::from_utf8_unchecked_mut",
    "std::mem::zeroed", "std::mem::uninitialized",  # deprecated but still used
})

# Detection: flag every unsafe block that contains one of these functions
# AND has any input from outside the function (argument, static, env var)
```

#### 3.4.2 Command Injection (`rust_sinks.py`)

```python
# Detect: Command::new(tainted).arg(tainted).output()
# The .arg() method is the injection point — if its argument contains
# a variable (not a string literal), flag it.

CMD_CALLEES: frozenset[str] = frozenset({
    "std::process::Command::new",
    "std::process::Command::arg",
    "std::process::Command::args",
    "std::os::unix::process::CommandExt::arg0",  # Unix-only
})

# Also detect: std::env::var("USER_INPUT") → Command::new("sh").arg(env_var)
# This is taint propagation through env vars
```

#### 3.4.3 Weak Cryptography (`rust_crypto.py`)

```python
WEAK_CRYPTO_CRATES: dict[str, str] = {
    "md5": "CWE-327 — MD5 is cryptographically broken (collisions in seconds)",
    "sha1": "CWE-327 — SHA-1 is broken (SHAttered attack, chosen-prefix collisions)",
    "sha-1": "CWE-327 — SHA-1 is broken",
    "des": "CWE-327 — DES has 56-bit key (brute-forceable)",
    "rc4": "CWE-327 — RC4 has critical biases",
    "rc2": "CWE-327 — RC2 is obsolete",
}

# Detection pattern:
# 1. Scan Cargo.toml for these crate names
# 2. Scan use statements: `use md5::*`, `use sha1::Digest`
# 3. Detect: `md5::compute(data)`, `sha1::Sha1::digest(data)`
```

#### 3.4.4 TOCTOU (`rust_unsafe.py` + `rust_taint.py`)

```python
# Pattern: metadata check followed by file operation
# 
# Dangerous:
#   if path.exists() {                    ← TOCTOU check
#       let contents = fs::read(path)?;   ← TOCTOU use (path may have changed)
#   }
#
# Safe:
#   match fs::read(path) {
#       Ok(contents) => { ... }
#       Err(e) if e.kind() == ErrorKind::NotFound => { ... }
#   }
#
# Detection: find pairs of (metadata check, file op) within 5 lines
# where both operate on the same path variable.

TOCTOU_CHECK_FNS: frozenset[str] = frozenset({
    "std::fs::metadata", "std::fs::symlink_metadata",
    "Path::exists", "Path::is_file", "Path::is_dir",
    "Path::try_exists",
})

TOCTOU_USE_FNS: frozenset[str] = frozenset({
    "std::fs::read", "std::fs::write", "std::fs::remove_file",
    "std::fs::remove_dir", "std::fs::rename", "std::fs::copy",
    "File::open", "File::create",
})
```

### 3.5 Taint Sources (Rust)

```python
RUST_TAINT_SOURCES: dict[str, str] = {
    "std::env::var":        "Environment variable",
    "std::env::vars":       "All environment variables",
    "std::env::args":       "Command-line arguments",
    "std::env::args_os":    "OS command-line arguments",
    "std::io::stdin":       "Standard input",
    "std::io::BufRead::read_line": "Line from buffered reader",
    "std::io::Read::read_to_string": "Data from reader",
    "std::io::Read::read_to_end": "Data from reader",
    "std::net::TcpStream::read": "Network socket data",
    "reqwest::get":         "HTTP response (reqwest)",
    "ureq::get":            "HTTP response (ureq)",
    "hyper::Client::get":   "HTTP response (hyper)",
    "serde_json::from_str": "Parsed JSON (may be untrusted)",
    "serde_json::from_reader": "Parsed JSON from reader (may be untrusted)",
    "serde_yaml::from_str": "Parsed YAML (may be untrusted)",
    "toml::from_str":       "Parsed TOML (may be untrusted)",
    "std::fs::read_to_string": "File contents (may be attacker-controlled)",
}
```

### 3.6 Edge Cases & Gotchas

| Edge Case | Handling |
|---|---|
| `unsafe { ... }` inside safe function | Flag the entire `unsafe` block, trace taint into it |
| `#![forbid(unsafe_code)]` attribute | Skip `unsafe` block analysis for this crate |
| `#[cfg(test)]` module | Downgrade confidence for findings in test-only code |
| `println!("{}", secret)` | CWE-532 — Sensitive data in output/logs |
| `unwrap()` / `expect()` on tainted data | CWE-248 — Uncaught exception from attacker input |
| `include_str!("secret.txt")` | CWE-798 — Hardcoded secret from build-time file |
| `std::mem::transmute::<&[u8], &str>(bytes)` | CWE-119 — Bypassing UTF-8 validation |
| `build.rs` files | Scan separately; they execute at build time |
| Procedural macros | Skip macro bodies (they execute at compile time, not runtime) |

### 3.7 Acceptance Gate (Phase 3)

```bash
# Must detect unsafe block with pointer dereference
ansede-static tests/fixtures/rust/unsafe_ptr.rs | grep "CWE-119"

# Must detect Command::new with env var argument
ansede-static tests/fixtures/rust/cmd_injection.rs | grep "CWE-78"

# Must NOT fire on safe Command::new("ls") with literal args
ansede-static tests/fixtures/rust/safe_command.rs | python -c "..."
```

---

## <a name="phase-4"></a>Phase 4: JavaScript SSA via Pratt CFG

### 4.1 Why SSA for JS is Critical

The current JS taint tracker (`js_engine/taint.py`) is regex-based name matching. It has four fundamental flaws:

1. **Reassignment confusion:** `x = taint; y = x; x = "clean"; sink(y)` — detected (good, y holds old x). But `x = "clean"; y = x; x = taint; sink(y)` — also fires (wrong, y got x before taint).
2. **Branch blindness:** Taint inside `if (false) {}` is tracked as if it always executes.
3. **No sanitizer cancellation:** Sanitizing in one branch doesn't un-taint at merge.
4. **No destructuring before our fix:** (already fixed in v6.3, but still regex-based).

### 4.2 SSA Construction Algorithm

#### 4.2.1 Build CFG from Pratt AST

The Pratt parser (`js_engine/pratt/pratt_analyzer.py`) produces a flat statement list. The CFG builder:

```python
@dataclass
class BasicBlock:
    id: int
    stmts: list[PrattStmt]
    predecessors: list[int]   # block IDs
    successors: list[int]     # block IDs
    is_merge_point: bool      # True if this block has multiple predecessors
    is_loop_header: bool      # True if this is a loop entry point

def build_cfg(stmts: list[PrattStmt]) -> list[BasicBlock]:
    """Build CFG from Pratt-parsed JS statements.
    
    Splits at:
    - if/else/else-if boundaries
    - for/while/do-while loop boundaries
    - switch/case boundaries
    - try/catch/finally boundaries
    - return/throw/break/continue (terminator instructions)
    
    Algorithm: Two-pass
    Pass 1: Identify leaders (first stmt, targets of jumps, stmts after jumps)
    Pass 2: Build blocks from leaders, connect edges
    """
```

**Key difference from Python SSA:** JavaScript has `switch` with fall-through, `try/catch/finally` with exception edges, and `break`/`continue` with label targets. The CFG must handle all of these.

#### 4.2.2 Dominator Tree

Use the Cooper-Harvey-Kennedy algorithm (2001) — O(N²) worst case, near-linear in practice:

```python
def compute_dominators(blocks: list[BasicBlock]) -> dict[int, int]:
    """Compute immediate dominator for each block.
    
    Returns: {block_id: idom_block_id}
    Entry block has idom = -1 (none).
    """
    n = len(blocks)
    # rpo = reverse postorder traversal
    rpo = reverse_postorder(blocks)
    
    # idom[entry] = entry (by convention, entry dominates itself)
    idom = {rpo[0]: rpo[0]}
    
    changed = True
    while changed:
        changed = False
        for b in rpo[1:]:  # skip entry
            # new_idom = first predecessor with computed idom
            preds = [p for p in blocks[b].predecessors if p in idom]
            if not preds:
                continue
            new_idom = preds[0]
            for p in preds[1:]:
                new_idom = intersect(p, new_idom, idom, rpo)
            if b not in idom or idom[b] != new_idom:
                idom[b] = new_idom
                changed = True
    return idom

def intersect(b1: int, b2: int, idom: dict, rpo: list[int]) -> int:
    """Find lowest common ancestor in dominator tree."""
    # Map block id → rpo index
    rpo_idx = {b: i for i, b in enumerate(rpo)}
    while b1 != b2:
        while rpo_idx[b1] < rpo_idx[b2]:
            b1 = idom.get(b1, b1)
        while rpo_idx[b2] < rpo_idx[b1]:
            b2 = idom.get(b2, b2)
    return b1
```

#### 4.2.3 Dominance Frontier & Φ-Node Insertion

```python
def compute_dominance_frontier(
    blocks: list[BasicBlock], 
    idom: dict[int, int]
) -> dict[int, set[int]]:
    """Compute DF for each block. DF[b] = blocks where b's dominance ends."""
    df = {i: set() for i in range(len(blocks))}
    
    for b in range(len(blocks)):
        preds = blocks[b].predecessors
        if len(preds) >= 2:  # Merge point
            for p in preds:
                runner = p
                while runner != idom.get(b, -1) and runner != -1:
                    df[runner].add(b)
                    runner = idom.get(runner, -1)
    return df

def insert_phi_nodes(
    blocks: list[BasicBlock],
    df: dict[int, set[int]],
    var_names: set[str]
) -> dict[int, set[str]]:
    """Determine which Φ-nodes to insert at each block for each variable.
    
    Semi-pruned: only insert Φ for variables that are live at the merge point.
    For taint analysis, we care about all variables that could carry taint,
    so we use a conservative definition of liveness.
    """
    phi_nodes: dict[int, set[str]] = {i: set() for i in range(len(blocks))}
    
    for var in var_names:
        # Blocks where var is defined
        def_blocks = {i for i, b in enumerate(blocks) if var_assigned_in_block(b, var)}
        
        # Worklist: blocks needing Φ for this var
        worklist = list(def_blocks)
        processed = set(def_blocks)
        
        while worklist:
            d = worklist.pop(0)
            for f in df.get(d, set()):
                if var not in phi_nodes[f]:
                    phi_nodes[f].add(var)
                    if f not in processed:
                        processed.add(f)
                        worklist.append(f)
    
    return phi_nodes
```

#### 4.2.4 Variable Renaming

```python
def rename_variables(
    blocks: list[BasicBlock],
    phi_nodes: dict[int, set[str]],
    dom_tree: dict[int, list[int]]  # dominator tree children
) -> dict[tuple[int, str], int]:
    """Rename variables with SSA version numbers.
    
    Returns: {(block_id, var_name): version_number}
    """
    counters: dict[str, int] = defaultdict(int)       # var → next version
    stacks: dict[str, list[int]] = defaultdict(list)   # var → version stack
    versions: dict[tuple[int, str], int] = {}          # (block, var) → version
    
    def rename_block(block_id: int):
        # Save current stack state
        saved = {v: len(stacks[v]) for v in stacks}
        
        # Rename Φ-node definitions
        for var in phi_nodes.get(block_id, set()):
            ver = counters[var]
            counters[var] = ver + 1
            stacks[var].append(ver)
            versions[(block_id, var)] = ver
        
        # Rename statements in block
        for stmt in blocks[block_id].stmts:
            # Rename uses (RHS)
            for use_var in vars_used(stmt):
                if stacks[use_var]:
                    # Replace use with (use_var, stacks[use_var][-1])
                    pass
            # Rename defs (LHS)
            for def_var in vars_defined(stmt):
                ver = counters[def_var]
                counters[def_var] = ver + 1
                stacks[def_var].append(ver)
                versions[(block_id, def_var)] = ver
        
        # Rename Φ-node arguments in successors
        for succ_id in blocks[block_id].successors:
            for var in phi_nodes.get(succ_id, set()):
                if stacks[var]:
                    # Φ-arg from block_id for var = stacks[var][-1]
                    pass
        
        # Recurse into dominator tree children
        for child in dom_tree.get(block_id, []):
            rename_block(child)
        
        # Restore stacks for siblings
        for v, count in saved.items():
            while len(stacks[v]) > count:
                stacks[v].pop()
    
    entry = 0  # Entry block is block 0
    rename_block(entry)
    return versions
```

### 4.3 SSA Taint Propagation

Once the SSA form is built, taint propagation becomes a simple worklist algorithm:

```python
def propagate_taint_ssa(
    blocks: list[BasicBlock],
    versions: dict[tuple[int, str], int],
    phi_nodes: dict[int, set[str]],
    taint_sources: dict[str, str],   # var → source description
    sinks: dict[str, tuple[str, str]] # callee → (CWE, description)
) -> list[SSATaintFinding]:
    """Forward taint propagation over SSA form.
    
    Taint rules:
    1. Source: if var is a taint source, mark (block, var, version) as tainted
    2. Assignment: a = b → taint(a) = taint(b)
    3. Binary op: a = b + c → taint(a) = taint(b) ∪ taint(c)
    4. Call: a = foo(b, c) → taint(a) = taint(b) ∪ taint(c) (conservative)
    5. Φ-node: a₃ = Φ(a₁, a₂) → taint(a₃) = taint(a₁) ∪ taint(a₂)
    6. Sanitizer: a = sanitize(b) → taint(a) = ∅
    7. Sink: if sink(tainted_arg) → generate finding
    
    Uses GEN/KILL sets:
    - GEN[stmt] = variables that become tainted at this stmt
    - KILL[stmt] = variables that become clean at this stmt
    """
    tainted: dict[tuple[int, str, int], set[str]] = {}  # (block, var, ver) → {source_labels}
    
    # Worklist: blocks to re-evaluate
    worklist = list(range(len(blocks)))
    
    while worklist:
        bid = worklist.pop(0)
        block = blocks[bid]
        
        # Compute IN from predecessors (meet = union for may-taint)
        in_taint: dict[str, set[str]] = {}  # var → {source_labels}
        for pred in block.predecessors:
            for var in phi_nodes.get(bid, set()):
                # Get the Φ-argument version from the predecessor
                pred_ver = versions.get((pred, var))
                if pred_ver is not None:
                    pred_taint = tainted.get((pred, var, pred_ver), set())
                    if var not in in_taint:
                        in_taint[var] = set()
                    in_taint[var] |= pred_taint
        
        # Apply transfer function to each statement
        out_taint = dict(in_taint)
        
        for stmt in block.stmts:
            # Check for taint sources in RHS
            for var in vars_used(stmt):
                if var in taint_sources:
                    source_label = taint_sources[var]
                    for def_var in vars_defined(stmt):
                        if def_var not in out_taint:
                            out_taint[def_var] = set()
                        out_taint[def_var].add(source_label)
            
            # Check for sinks
            if is_sink_call(stmt, sinks):
                callee, (cwe, desc) = get_sink_info(stmt, sinks)
                for arg in sink_args(stmt):
                    if arg in out_taint and out_taint[arg]:
                        findings.append(SSATaintFinding(
                            cwe=cwe,
                            sink=callee,
                            sources=out_taint[arg],
                            line=stmt.line,
                        ))
            
            # Check for sanitizers
            if is_sanitizer(stmt):
                for def_var in vars_defined(stmt):
                    if def_var in out_taint:
                        del out_taint[def_var]  # KILL — sanitized
        
        # Update SSA versions for this block
        changed = False
        for var, labels in out_taint.items():
            ver = versions.get((bid, var))
            if ver is not None:
                key = (bid, var, ver)
                if key not in tainted or tainted[key] != labels:
                    tainted[key] = labels
                    changed = True
        
        if changed:
            for succ in block.successors:
                if succ not in worklist:
                    worklist.append(succ)
    
    return findings
```

### 4.4 File Structure

```
src/ansede_static/js_engine/
├── ssa/
│   ├── __init__.py          # Public API: analyze_js_ssa()
│   ├── cfg_builder.py       # Pratt AST → CFG
│   ├── dominators.py        # Dominator tree + dominance frontier
│   ├── ssa_builder.py       # Φ-node insertion + variable renaming
│   ├── ssa_taint.py         # Forward taint propagation over SSA
│   └── ssa_types.py         # SSA-specific dataclasses
└── ... (existing files)
```

### 4.5 Integration with Existing Analyzer

The SSA path runs as an optional high-accuracy mode alongside the existing regex-based path:

```python
# In js_analyzer.py analyze_js():
if use_ssa:
    ssa_result = analyze_js_ssa(code, filename, global_graph)
    ssa_findings = ssa_result.findings
else:
    ssa_findings = []

# Merge: SSA findings override regex findings on same (line, cwe)
regex_findings = existing_pipeline()
merged = merge_findings(regex_findings, ssa_findings, strategy="ssa_wins_on_conflict")
```

### 4.6 Edge Cases

| Edge Case | Handling |
|---|---|
| `eval()` / `new Function()` | These modify the CFG dynamically — conservative: mark all subsequent variables as tainted |
| `with` statement | Deprecated in strict mode but still parseable — treat as opaque: taint everything inside |
| Generator functions (`function*`) | `yield` returns to caller — track taint through yielded values |
| Async/await | `await expr` — taint propagates through; `async function` returns Promise |
| Destructuring (already fixed) | Handled at SSA level: each destructured name gets its own SSA version |
| Closure variable capture | Variables captured by closures get additional SSA versions at each call site |
| `this` assignment | `this.x = taint` → track as object heap store (field-sensitive) |
| Prototype chain | `obj.__proto__.x = taint` → overly complex; mark all prototype accesses as tainted |
| `Symbol` keys | `obj[Symbol('key')] = taint` → can't be accessed predictably; mark entire object tainted |
| `Proxy` objects | `new Proxy(target, {get: ...})` → intercepts all access; mark as tainted |
| Template literals with tags | `` tag`template ${tainted}` `` → tag function receives tainted strings |

### 4.7 Acceptance Gate (Phase 4)

```bash
# Must correctly handle: x=taint; y=x; x=clean; sink(y) → detected
ansede-static tests/fixtures/js/ssa_reassign.js | grep "CWE-79"

# Must correctly handle: x=clean; y=x; x=taint; sink(y) → NOT detected
ansede-static tests/fixtures/js/ssa_no_false_positive.js | python -c "..." # zero findings

# Must detect taint through if/else merge with Φ node
ansede-static tests/fixtures/js/ssa_phi_merge.js | grep "CWE-78"

# Performance: 1000-line JS file with SSA must complete in < 3 seconds
```

---

## <a name="phase-5"></a>Phase 5: Java Andersen-Style Points-to Analysis

### 5.1 Why Points-to for Java

The existing Java analysis is regex-based with optional tree-sitter AST. It lacks:

1. **Field-sensitive tracking:** `user.name = request.getParameter("x")` — taint stored in object field
2. **Virtual dispatch resolution:** `service.process(data)` — which `process()` method is called?
3. **Collection tracking:** `list.add(taintedValue); x = list.get(0)` — taint through List/Map
4. **Framework indirection:** Spring `@Autowired` injects objects — where does taint flow?

### 5.2 Andersen's Algorithm — Constraint-Based

Andersen's analysis (PhD thesis, DIKU 1994) is inclusion-based. It builds a constraint graph and solves it iteratively:

```
Constraint types:
  [Alloc]  l = new C       →  {o_C@l} ⊆ pts(l)
  [Copy]   l = r           →  pts(r) ⊆ pts(l)
  [Load]   l = r.f         →  ∀o ∈ pts(r): pts(o.f) ⊆ pts(l)
  [Store]  l.f = r         →  ∀o ∈ pts(l): pts(r) ⊆ pts(o.f)
  [Call]   l = r.m(a...)   →  resolve virtual dispatch, propagate args → params, return → l
```

**Why inclusion-based (Andersen) over unification-based (Steensgaard):**
- Steensgaard is O(n·α(n)) (near-linear) but imprecise — every variable can only point to one thing
- Andersen is O(n³) worst-case but O(n²) in practice on Java code
- For SAST, precision matters more than speed — false positives waste engineer time

### 5.3 Field-Sensitive Heap Abstraction

Standard Andersen's only tracks allocation sites. For Java SAST, we need field-sensitivity:

```python
@dataclass
class AllocationSite:
    id: int
    type_name: str          # "java.lang.String", "com.example.User"
    line: int
    in_method: str
    
@dataclass  
class FieldAccess:
    """Abstract heap location: o.f where o is an allocation site."""
    alloc_site: int          # ID of allocation site
    field_name: str          # "name", "email", "password"
    
# Points-to set maps:
# Variable → set[AllocationSite]          — what objects can this variable point to?
# FieldAccess → set[AllocationSite]       — what objects can be stored in this field?

class PointsToGraph:
    var_pts: dict[str, set[int]]                     # variable → {alloc_site_ids}
    field_pts: dict[tuple[int, str], set[int]]       # (alloc_site, field) → {alloc_site_ids}
    alloc_types: dict[int, str]                       # alloc_site_id → type_name
    call_graph: dict[str, set[str]]                   # callee → {caller_methods}
```

### 5.4 Constraint Generation from AST

Walk the tree-sitter Java AST to generate constraints:

```python
class ConstraintKind(Enum):
    ALLOC = "alloc"
    COPY = "copy"
    LOAD = "load"
    STORE = "store"
    CALL = "call"

@dataclass
class Constraint:
    kind: ConstraintKind
    lhs: str          # Variable or field reference
    rhs: str | None   # Variable, field reference, or allocation site type
    line: int
    in_method: str

def generate_constraints(method_ast: Node, source: bytes) -> list[Constraint]:
    """Walk a method's AST and generate Andersen constraints.
    
    Mapping rules:
    
    Java AST Node                  → Constraint
    ─────────────────────────────────────────────
    String x = new String(...)     → ALLOC: x = new String
    x = y                          → COPY:  x = y
    x = y.field                    → LOAD:  x = y.field
    x.field = y                    → STORE: x.field = y
    x = y.method(a1, a2)           → CALL:  x = y.method(a1, a2)
    x[i] = y    (array store)      → STORE: x.[] = y  (weak update)
    x = y[i]    (array load)       → LOAD:  x = y.[]
    
    Special Java cases:
    ─────────────────────────────────────────────
    String x = "literal"           → ALLOC: x = new String  (string constant pool)
    Integer x = 42                 → ALLOC: x = new Integer (autoboxing)
    List<String> x = new ArrayList<>() → ALLOC: x = new ArrayList
    for (Item i : items)           → ALLOC: i = items.next()  (iterator pattern)
    try (Resource r = ...)         → ALLOC: r = ...; CALL: finally r.close()
    """
```

### 5.5 Constraint Solving — Worklist Algorithm

```python
def solve_andersen(constraints: list[Constraint]) -> PointsToGraph:
    """Solve Andersen's constraints using worklist propagation.
    
    Algorithm:
    1. Initialize pts sets from ALLOC constraints
    2. Worklist = all constraints
    3. While worklist not empty:
       a. Pop constraint
       b. Apply constraint (may add new pts facts)
       c. If pts changed, add dependent constraints back to worklist
    
    Optimization: Use difference propagation — only process new facts.
    """
    ptg = PointsToGraph()
    worklist: deque[Constraint] = deque(constraints)
    
    # Index constraints by trigger variable for efficient re-firing
    load_index: dict[str, list[Constraint]] = defaultdict(list)    # var → LOAD constraints where var is base
    store_index: dict[str, list[Constraint]] = defaultdict(list)   # var → STORE constraints where var is base
    
    # Propagation tracking: which constraints need re-firing when a pts set changes
    dependents: dict[str, set[int]] = defaultdict(set)  # var → {constraint_ids}
    
    constraint_id = 0
    for c in constraints:
        if c.kind == ConstraintKind.LOAD:
            base_var = c.rhs.split('.')[0] if c.rhs else ''
            load_index[base_var].append(c)
        elif c.kind == ConstraintKind.STORE:
            base_var = c.lhs.split('.')[0] if c.lhs else ''
            store_index[base_var].append(c)
        constraint_id += 1
    
    # Initial ALLOC processing
    for c in constraints:
        if c.kind == ConstraintKind.ALLOC:
            site_id = ptg.add_allocation(c.rhs, c.line, c.in_method)
            ptg.var_pts.setdefault(c.lhs, set()).add(site_id)
    
    # Main worklist loop
    max_iterations = len(constraints) * 10  # Safety bound
    iteration = 0
    
    while worklist and iteration < max_iterations:
        iteration += 1
        c = worklist.popleft()
        changed = False
        
        if c.kind == ConstraintKind.COPY:
            rhs_pts = ptg.var_pts.get(c.rhs, set())
            lhs_pts = ptg.var_pts.setdefault(c.lhs, set())
            new_pts = rhs_pts - lhs_pts
            if new_pts:
                lhs_pts |= new_pts
                changed = True
                
        elif c.kind == ConstraintKind.LOAD:
            # x = y.f → ∀o ∈ pts(y): pts(o.f) ⊆ pts(x)
            base_pts = ptg.var_pts.get(c.rhs, set())
            for site_id in base_pts:
                field_key = (site_id, c.lhs)
                field_pts = ptg.field_pts.setdefault(field_key, set())
                var_pts = ptg.var_pts.setdefault(c.lhs, set())
                new_pts = field_pts - var_pts
                if new_pts:
                    var_pts |= new_pts
                    changed = True
                    
        elif c.kind == ConstraintKind.STORE:
            # x.f = y → ∀o ∈ pts(x): pts(y) ⊆ pts(o.f)
            base_pts = ptg.var_pts.get(c.lhs, set())
            rhs_pts = ptg.var_pts.get(c.rhs, set())
            for site_id in base_pts:
                field_key = (site_id, c.rhs)
                field_pts = ptg.field_pts.setdefault(field_key, set())
                new_pts = rhs_pts - field_pts
                if new_pts:
                    field_pts |= new_pts
                    changed = True
        
        if changed:
            # Re-add dependent constraints
            if c.lhs in dependents:
                for dep_id in dependents[c.lhs]:
                    worklist.append(constraints[dep_id])
    
    return ptg
```

### 5.6 Taint Propagation Through Points-to Graph

Once we have the points-to graph, taint propagation is straightforward:

```python
def propagate_taint_java(
    ptg: PointsToGraph,
    taint_sources: dict[str, str],  # method → source description
    sink_methods: dict[str, tuple[str, str]]  # method → (CWE, desc)
) -> list[Finding]:
    """Propagate taint through the points-to graph.
    
    Algorithm:
    1. Seed: mark allocation sites created by taint sources as tainted
    2. Propagate forward: for each tainted allocation site, follow the
       points-to edges through field stores/loads and method calls
    3. Sink detection: when a tainted allocation site reaches a sink method
       argument, generate a finding
    
    This is essentially a reachability problem on the points-to graph.
    """
    tainted_sites: set[int] = set()   # tainted allocation site IDs
    tainted_vars: set[str] = set()    # tainted variable names
    
    # Seed from sources
    for src_method, src_desc in taint_sources.items():
        for var_name, site_ids in ptg.var_pts.items():
            for site_id in site_ids:
                if ptg.alloc_types.get(site_id) == src_method:
                    tainted_sites.add(site_id)
                    tainted_vars.add(var_name)
    
    # Propagate through COPY edges
    changed = True
    while changed:
        changed = False
        for var_name, site_ids in ptg.var_pts.items():
            if site_ids & tainted_sites and var_name not in tainted_vars:
                tainted_vars.add(var_name)
                tainted_sites |= site_ids
                changed = True
    
    # Detect sinks
    findings = []
    for sink_method, (cwe, desc) in sink_methods.items():
        for callee, callers in ptg.call_graph.items():
            if sink_method in callee:
                # Check if any argument to this call is tainted
                for var_name in tainted_vars:
                    if caller_has_argument(callers, var_name):
                        findings.append(Finding(
                            cwe=cwe,
                            title=f"{cwe}: Tainted data reaches {sink_method}",
                            description=f"Points-to analysis confirms {var_name} may carry "
                                       f"tainted data into {sink_method}.",
                            severity=Severity.HIGH if "Injection" in desc else Severity.MEDIUM,
                            confidence=0.85,
                            analysis_kind="java-points-to",
                        ))
    
    return findings
```

### 5.7 Spring Framework Enhancement

Spring introduces additional complexity:

```python
# Spring-specific constraint generation:

# @Autowired — field injection
@Autowired
private UserService userService;  → ALLOC: userService = inject(UserService)

# @RequestMapping — route handler
@RequestMapping(value = "/users/{id}", method = RequestMethod.GET)
public User getUser(@PathVariable("id") Long id) → TAINT_SOURCE: id = path_variable

# @RequestParam — query parameter
public List<User> search(@RequestParam("q") String query) → TAINT_SOURCE: query = request_param

# @RequestBody — JSON body
public User create(@RequestBody User user) → TAINT_SOURCE: user = request_body

# JpaRepository — automatic query methods
List<User> findByName(String name); → SINK if 'name' is tainted (Spring Data generates query)
```

### 5.8 File Structure

```
src/ansede_static/java_engine/
├── __init__.py
├── points_to/
│   ├── __init__.py
│   ├── constraints.py     # Constraint generation from AST
│   ├── solver.py          # Andersen solver with worklist
│   ├── ptg.py             # PointsToGraph data structure
│   └── taint.py           # Taint propagation over PTG
└── ... (existing files)
```

### 5.9 Edge Cases

| Edge Case | Handling |
|---|---|
| Reflection (`Class.forName`, `Method.invoke`) | Conservative: mark all reflected calls as possibly tainted |
| Dynamic proxies (`java.lang.reflect.Proxy`) | All method calls through proxy → all args tainted, all returns tainted |
| Lambda expressions | Treat as anonymous class with single method — generate constraints normally |
| Stream API (`.map()`, `.filter()`) | Lambda inside stream → apply points-to to the lambda body |
| Thread-local variables | ThreadLocal.get() → taint from whoever set it (conservative: mark as tainted) |
| Native methods (JNI) | No source available → mark return as tainted if method name suggests input (e.g., `readFile`) |
| `System.getProperty()` / `System.getenv()` | TAINT_SOURCE — environment/config values are potentially attacker-controlled |
| Serialization (`ObjectInputStream.readObject()`) | TAINT_SOURCE — deserialized objects are untrusted |
| `Runtime.exec()` with String argument | SINK: CWE-78 — command injection |

### 5.10 Acceptance Gate (Phase 5)

```bash
# Must track taint through field store/load
ansede-static tests/fixtures/java/field_taint.java | grep "CWE-89"

# Must track taint through list.add() / list.get()
ansede-static tests/fixtures/java/collection_taint.java | grep "CWE-78"

# Spring @RequestParam → Service → JPA repository must be detected
ansede-static tests/fixtures/java/spring_taint_flow.java | grep "CWE-89"

# Performance: 5000-line Spring controller must complete in < 10 seconds
```

---

## <a name="phase-6"></a>Phase 6: Cross-Language Validation Suite

### 6.1 Uniform Test Harness

Create a single test framework that validates all 8 languages against consistent benchmarks:

```
tests/fixtures/
├── cross_language/
│   ├── cwe78_cmd_injection/
│   │   ├── python_unsafe.py
│   │   ├── python_safe.py
│   │   ├── js_unsafe.js
│   │   ├── js_safe.js
│   │   ├── java_unsafe.java
│   │   ├── java_safe.java
│   │   ├── php_unsafe.php
│   │   ├── php_safe.php
│   │   ├── ruby_unsafe.rb
│   │   ├── ruby_safe.rb
│   │   ├── rust_unsafe.rs
│   │   └── rust_safe.rs
│   ├── cwe79_xss/
│   │   └── ... (same structure)
│   ├── cwe89_sql_injection/
│   │   └── ...
│   ├── cwe502_deserialization/
│   │   └── ...
│   ├── cwe862_missing_auth/
│   │   └── ...
│   ├── cwe918_ssrf/
│   │   └── ...
│   └── cwe22_path_traversal/
│       └── ...
```

### 6.2 Automated Recall Benchmark

```python
# tests/test_cross_language_recall.py
CWE_CASES = {
    "CWE-78": {
        "python": {"unsafe_1": True, "unsafe_2": True, "safe_1": False, "safe_2": False},
        "javascript": {"unsafe_1": True, "safe_1": False},
        "java": {"unsafe_1": True, "safe_1": False},
        "php": {"unsafe_1": True, "safe_1": False},
        "ruby": {"unsafe_1": True, "safe_1": False},
        "rust": {"unsafe_1": True, "safe_1": False},
    },
    # ... same for all CWEs
}

@pytest.mark.parametrize("lang,cwe,case_id,expected", _flatten_cases(CWE_CASES))
def test_cross_language_recall(lang, cwe, case_id, expected):
    filepath = f"tests/fixtures/cross_language/{_cwe_dir(cwe)}/{lang}_{case_id}.{_ext(lang)}"
    result = scan_file(filepath, lang)
    found = any(f.cwe == cwe and f.severity in ("critical", "high") for f in result.findings)
    assert found == expected, f"{lang}/{cwe}/{case_id}: expected={expected}, got={found}"
```

### 6.3 Quality Gates (per-language)

| Language | Must-Pass CWEs | Minimum Recall | Max False Positive Rate |
|---|---|---|---|
| Python | 78, 79, 89, 94, 95, 502, 22, 918, 798, 862, 639, 287, 601, 117, 352, 915 | 95% | 5% |
| JavaScript | 78, 79, 89, 94, 95, 502, 22, 918, 798, 601, 117, 307 | 92% | 8% |
| Java | 78, 89, 79, 502, 22, 918, 798, 862, 639, 327, 611 | 90% | 10% |
| C# | 78, 89, 79, 502, 22, 918, 798, 862, 915 | 88% | 10% |
| Go | 78, 89, 22, 798, 327 | 85% | 12% |
| PHP | 78, 89, 79, 22, 502, 918, 798, 862, 611 | 85% | 15% |
| Ruby | 78, 89, 79, 22, 502, 918, 798, 862, 915, 601 | 85% | 15% |
| Rust | 78, 119, 798, 327, 362, 502 | 80% | 10% |

---

## <a name="cross-reference"></a>Cross-Reference: External Research & Competitive Comparison

### Academic Foundations

| Paper | Year | Relevance | How Ansede Implements It |
|---|---|---|---|
| Cytron et al. "Efficiently Computing SSA Form" | 1991 | Dominance frontier algorithm — the foundation of all SSA construction | Phase 4: `dominators.py` uses this algorithm |
| Cooper, Harvey, Kennedy "A Simple, Fast Dominance Algorithm" | 2001 | Faster dominator computation — used by LLVM and GCC | Phase 4: `compute_dominators()` uses CHK algorithm |
| Briggs et al. "Practical Improvements to SSA" | 1998 | Semi-pruned SSA — fewer Φ-nodes without full liveness | Phase 4: `insert_phi_nodes()` uses semi-pruned approach |
| Andersen "Program Analysis and Specialization for the C Programming Language" | 1994 | Inclusion-based points-to analysis | Phase 5: `solver.py` implements Andersen's constraints |
| Heintze & Tardieu "Ultra-fast Aliasing Analysis using CLA" | 2000 | Optimization for Andersen — difference propagation | Phase 5: Worklist uses difference propagation |
| Yamaguchi et al. "Modeling and Discovering Vulnerabilities with Code Property Graphs" | 2014 | CPG model (Joern's foundation) — AST+CFG+PDG+DDG | Ansede's GlobalGraph + IDE lattice is the same concept |
| Arzt et al. "FlowDroid: Precise Context, Flow, Field, Object-sensitive Android Taint Analysis" | 2014 | Field-sensitive taint for Java — gold standard for Android | Phase 5: Field-sensitive heap model mirrors FlowDroid's approach |

### Competitive Comparison

| Tool | SSA | Points-to | Languages | Approach |
|---|---|---|---|---|
| **CodeQL** | Yes (via data flow library) | Yes (field-sensitive) | 10+ | Datalog-based query engine, extracts database from build |
| **Semgrep** | No (pattern-based) | No (name-based only) | 30+ | Tree-sitter + pattern matching, taint mode with limited inter-procedural |
| **Joern** | Via CPG queries | Via CPG edges | 8 | Code Property Graph + Scala DSL queries |
| **Snyk Code** | Yes (proprietary) | Yes (ML-augmented) | 10+ | Hybrid: AST patterns + ML classification |
| **Fortify** | Yes (proprietary) | Yes (full inter-procedural) | 20+ | Commercial: full program representation, build integration |
| **Checkmarx** | Yes (proprietary) | Yes (proprietary) | 20+ | Commercial: query-based CxQL language |
| **Ansede (current)** | Python SSA-lite only | No | 8 (3 regex-only) | Tree-sitter + regex + Python AST + IDE lattice |
| **Ansede (after this plan)** | Python + JS SSA | Java Andersen | 8 (all AST-based) | Above + SSA + points-to + framework-aware |

### Key Differentiators After Implementation

1. **Offline + zero-dependency** — None of the competitors can run air-gapped with pip install. CodeQL requires a build database. Joern requires JDK 21. Semgrep requires network for pro rules. Ansede remains `pip install ansede-static` with zero deps.

2. **Framework-aware auth detection** — Ansede's Python analyzer already detects missing `@login_required` with transitive Django mixin resolution. Phase 2 extends this to Rails `before_action`. Phase 1 adds Laravel `middleware('auth')` detection. No competitor does framework-specific auth detection at this depth.

3. **SSA for dynamic languages** — Very few tools run SSA on JavaScript (it's mostly a compiler technique). Ansede's approach of Pratt CFG + semi-pruned SSA is novel for a SAST tool.

4. **Field-sensitive Java without build tooling** — CodeQL and Fortify require build integration. Ansede's Andersen solver works directly on source, no Maven/Gradle needed.

---

## <a name="acceptance-gates"></a>Final Acceptance Gates

### Gate 1: All Languages AST-Based

```bash
for lang in python javascript java csharp go php ruby rust; do
    ansede-static --list-languages | grep -q $lang || exit 1
done
echo "PASS: All 8 languages have AST backends"
```

### Gate 2: CVE Recall ≥ 95% Across All Languages

```bash
python benchmarks/cve_recall_runner.py --all-languages --min-recall 0.95
```

### Gate 3: Quality Benchmark 100%

```bash
python -m pytest tests/test_quality_benchmark.py -v
# All shadow detectors: 100%
# All guard families: 100%
# Corpus_is_green: True
```

### Gate 4: Zero Parser Crashes on Corpus

```bash
python benchmarks/fuzz_parser.py --corpus benchmarks/real_world_corpus.json --timeout 5
# 0 crashes, 0 timeouts across all 8 languages
```

### Gate 5: Performance Ceiling

```bash
python benchmarks/perf_benchmark.py --target 5000  # LOC/s
# Must achieve ≥ 5000 LOC/s on real-world monorepo (up from ~750)
```

### Gate 6: Full Test Suite

```bash
python -m pytest tests/ -q --tb=short
# 0 failures (except pre-existing binary guardrails check)
```

---

## Estimated Effort Summary

| Phase | Item | Effort | Risk |
|---|---|---|---|
| 0 | Rust core: tree-sitter-php/ruby/rust | 0.5 day | Very Low |
| 1 | PHP AST analyzer | 3 days | Medium |
| 2 | Ruby AST analyzer | 3 days | Medium |
| 3 | Rust AST analyzer | 2 days | Low |
| 4 | JS SSA (Pratt CFG → SSA → taint) | 4 days | High |
| 5 | Java Andersen points-to | 5 days | High |
| 6 | Cross-language validation | 2 days | Low |
| **Total** | | **~19.5 days** | |

---

*End of document. Every detail is cross-referenced with either academic literature (Cytron 1991, Cooper 2001, Briggs 1998, Andersen 1994, Yamaguchi 2014), production tools (Joern's CPG, FlowDroid's field-sensitive taint, Semgrep's taint mode), or the existing Ansede codebase (GlobalGraph, IDE lattice, Pratt parser, Rust core).*

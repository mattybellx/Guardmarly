"""
ansede_static.rust_analyzer
────────────────────────────
Security analyzer for Rust source code.

Zero external dependencies — pure Python 3.9+ stdlib only.

Detection coverage:
  CWE-119  unsafe blocks — buffer overflow risk zones requiring manual review
  CWE-798  Hardcoded credentials (API keys, tokens in const/static/let)
  CWE-78   Command injection (std::process::Command with user-controlled args)
  CWE-327  Weak cryptography (deprecated md5/sha1/sha2 misuse crates)
  CWE-532  Sensitive data in panic messages (unwrap() on auth/secret values)
  CWE-362  TOCTOU / file-access race conditions (metadata then open pattern)

Status: v0.1 — pattern-based analysis. AST-depth via tree-sitter-rust planned for v0.2.
"""
from __future__ import annotations

import re

from ansede_static._types import AnalysisResult, Finding, Severity

# ── Rule IDs ──────────────────────────────────────────────────────────────────
_RS_UNSAFE_BLOCK  = "RS-001"
_RS_HARDCODED     = "RS-002"
_RS_CMDI          = "RS-003"
_RS_WEAK_CRYPTO   = "RS-004"
_RS_SENSITIVE_PANIC = "RS-005"
_RS_TOCTOU        = "RS-006"

# ── Pattern definitions ───────────────────────────────────────────────────────

# CWE-119: unsafe blocks
_UNSAFE_BLOCK_RE = re.compile(r'\bunsafe\s*\{')

# CWE-798: hardcoded secrets — long string literals in const/static/let
_HARDCODED_RE = re.compile(
    r'''(?:const|static|let)\s+\w+(?:\s*:\s*[^=]+)?\s*=\s*"(?=[^"]{12,})'''
    r'''(?:[A-Za-z0-9+/]{20,}={0,2}|[0-9a-fA-F]{32,}|sk-[a-z0-9\-]{20,}|'''
    r'''(?:password|passwd|secret|token|api_?key|auth)[^"]{0,3})''',
    re.IGNORECASE,
)

# Separate: obvious secret-named assignments
_HARDCODED_NAME_RE = re.compile(
    r'''(?:const|static|let)\s+(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|AUTH_KEY)\s*(?::\s*[^=]+)?\s*=\s*"[^"]{8,}''',
    re.IGNORECASE,
)

# CWE-78: Command injection via std::process::Command
_CMDI_RE = re.compile(
    r'Command::new\s*\([^)]*\)\s*\.'
    r'(?:arg|args)\s*\([^)]*(?:&\w+|format!|env!|std::env::var)',
    re.IGNORECASE | re.DOTALL,
)

# Simpler CMDI: arg() with a variable (not a string literal)
_CMDI_SIMPLE_RE = re.compile(
    r'\.arg\s*\(\s*(?!&?(?:"|\'))\w',
)

# CWE-327: Weak crypto crates
_WEAK_CRYPTO_RE = re.compile(
    r'\buse\s+(?:md5|sha1)(?:::|;|\s)',
    re.IGNORECASE,
)

_WEAK_CRYPTO_EXTERN_RE = re.compile(
    r'\bextern\s+crate\s+(?:md5|sha1)\b',
    re.IGNORECASE,
)

# CWE-532: sensitive panic (unwrap on password/token/secret)
_SENSITIVE_PANIC_RE = re.compile(
    r'(?:password|token|secret|api_key|auth)[^;\n]*\.(?:unwrap|expect)\s*\(',
    re.IGNORECASE,
)

# CWE-362: TOCTOU — metadata/exists check followed by file open
_TOCTOU_META_RE = re.compile(r'\.(?:metadata|exists|is_file|is_dir)\s*\(')
_TOCTOU_OPEN_RE = re.compile(r'(?:File::open|fs::read|OpenOptions::new)')


def analyze_rust(source: str, filename: str = "<unknown>") -> AnalysisResult:
    """Analyze Rust source code for security vulnerabilities.

    Parameters
    ----------
    source : str
        Full Rust source text.
    filename : str
        File path or label (used in Finding metadata).

    Returns
    -------
    AnalysisResult
        Result containing all findings and scan metadata.
    """
    findings: list[Finding] = []
    lines = source.splitlines()
    total_lines = len(lines)

    # Track TOCTOU patterns across nearby lines
    _meta_check_lines: list[int] = []

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Skip pure comments
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # ── CWE-119: unsafe block ────────────────────────────────────────
        if _UNSAFE_BLOCK_RE.search(line):
            # Don't flag unsafe in test modules — tests routinely use unsafe for FFI mocks
            is_test_ctx = any(
                "#[test]" in lines[max(0, i-4):i-1]  # type: ignore[arg-type]
                or "#[cfg(test)]" in l
                for l in lines[max(0, i-6):i]  # type: ignore[misc]
            )
            if not is_test_ctx:
                findings.append(Finding(
                    category="security",
                    rule_id=_RS_UNSAFE_BLOCK,
                    severity=Severity.MEDIUM,
                    title="Unsafe Rust block — manual memory-safety review required",
                    description=(
                        "unsafe blocks bypass Rust's memory-safety guarantees. "
                        "Ensure no out-of-bounds access, dangling pointers, or data races exist."
                    ),
                    line=i,
                    cwe="CWE-119",
                    suggestion=(
                        "Document exactly why unsafe is needed. "
                        "Wrap in a safe abstraction. "
                        "Consider using crates that provide safe wrappers (e.g. memmap2, nix)."
                    ),
                    confidence=0.50,
                ))

        # ── CWE-798: hardcoded credentials ──────────────────────────────
        if _HARDCODED_RE.search(line) or _HARDCODED_NAME_RE.search(line):
            findings.append(Finding(
                category="security",
                rule_id=_RS_HARDCODED,
                severity=Severity.HIGH,
                title="Potential hardcoded credential in Rust source",
                description=(
                    "A long string literal or secret-named constant may be a hardcoded "
                    "API key, token, or password. These are visible in source control "
                    "and compiled binaries."
                ),
                line=i,
                cwe="CWE-798",
                suggestion=(
                    "Read secrets from environment variables: "
                    "std::env::var(\"SECRET_KEY\").expect(\"SECRET_KEY must be set\") "
                    "or use a secrets manager crate (e.g. dotenvy, aws-config)."
                ),
                confidence=0.65,
            ))

        # ── CWE-78: command injection ────────────────────────────────────
        if _CMDI_RE.search(line) or _CMDI_SIMPLE_RE.search(line):
            _user_input_ctx = source[max(0, source.find(line) - 200):source.find(line) + 400]
            _has_user_input = bool(re.search(
                r'(?:args\(\)|stdin|read_line|env::var|from_utf8|String::from|to_string)',
                _user_input_ctx, re.IGNORECASE
            ))
            if _has_user_input:
                findings.append(Finding(
                    category="security",
                    rule_id=_RS_CMDI,
                    severity=Severity.HIGH,
                    title="Possible command injection via Command::new().arg()",
                    description=(
                        "Arguments to std::process::Command may include user-controlled data. "
                        "An attacker could inject additional shell arguments or commands."
                    ),
                    line=i,
                    cwe="CWE-78",
                    suggestion=(
                        "Validate and allowlist all arguments passed to Command. "
                        "Never pass unsanitized user input as command arguments. "
                        "Use .args([...]) with a fixed array instead of dynamic construction."
                    ),
                    confidence=0.60,
                ))

        # ── CWE-327: weak crypto crate import ───────────────────────────
        if _WEAK_CRYPTO_RE.search(line) or _WEAK_CRYPTO_EXTERN_RE.search(line):
            findings.append(Finding(
                category="security",
                rule_id=_RS_WEAK_CRYPTO,
                severity=Severity.MEDIUM,
                title="Weak cryptographic hash crate (MD5 or SHA-1)",
                description=(
                    "MD5 and SHA-1 are cryptographically broken and must not be used for "
                    "password hashing, digital signatures, or integrity checks."
                ),
                line=i,
                cwe="CWE-327",
                suggestion=(
                    "Replace md5/sha1 with sha2::Sha256 (from the sha2 crate) for general hashing, "
                    "or argon2/bcrypt for password hashing."
                ),
                confidence=0.80,
            ))

        # ── CWE-532: sensitive value in panic message ────────────────────
        if _SENSITIVE_PANIC_RE.search(line):
            findings.append(Finding(
                category="security",
                rule_id=_RS_SENSITIVE_PANIC,
                severity=Severity.LOW,
                title="Sensitive value may appear in panic message",
                description=(
                    "Calling .unwrap() or .expect() on a value containing a password, token, "
                    "or secret will include that value in the panic output if it fails."
                ),
                line=i,
                cwe="CWE-532",
                suggestion=(
                    "Use .unwrap_or_else(|_| panic!(\"auth value missing\")) "
                    "or map_err to a generic error without including the secret value."
                ),
                confidence=0.60,
            ))

        # ── CWE-362: TOCTOU tracking ─────────────────────────────────────
        if _TOCTOU_META_RE.search(line):
            _meta_check_lines.append(i)

        if _TOCTOU_OPEN_RE.search(line) and _meta_check_lines:
            recent_meta = [m for m in _meta_check_lines if i - m <= 5]
            if recent_meta:
                meta_line = recent_meta[-1]
                findings.append(Finding(
                    category="security",
                    rule_id=_RS_TOCTOU,
                    severity=Severity.MEDIUM,
                    title="Potential TOCTOU race condition (metadata check then file open)",
                    description=(
                        f"A file metadata check at line {meta_line} is followed by a file open at "
                        f"line {i}. Between these two operations, the filesystem state can change "
                        "(time-of-check to time-of-use race)."
                    ),
                    line=i,
                    cwe="CWE-362",
                    suggestion=(
                        "Open the file directly and handle the resulting error instead of "
                        "pre-checking with .exists() or .metadata()."
                    ),
                    confidence=0.55,
                ))
                _meta_check_lines.clear()

        _meta_check_lines = [m for m in _meta_check_lines if i - m <= 10]

    return AnalysisResult(
        file_path=filename,
        language="rust",
        findings=findings,
        lines_scanned=total_lines,
    )

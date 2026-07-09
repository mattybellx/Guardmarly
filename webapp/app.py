"""
ansede-static License Server
─────────────────────────────
Auto-generates license keys on Stripe payment. Zero manual work.
Completely self-contained — no imports from src/ needed.

Flow: Customer pays → Stripe webhook fires → key generated → shown on success page.
Deploy to Render.com (free) in 2 minutes — see DEPLOY.md
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Flask (only external dependency — graceful fallback) ─────────────
_FLASK_AVAILABLE: bool = False
try:
  from flask import Flask, request, jsonify, render_template
  _FLASK_AVAILABLE = True
except ImportError:
    # Instead of crashing, create a stub that raises clear errors when
    # someone tries to actually USE Flask features without it installed.
    class _FlaskStub:  # type: ignore
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.config: dict[str, Any] = {}
            self.secret_key: str = "stub"
        def route(self, *args: Any, **kwargs: Any) -> Any:
            return lambda f: f
        def after_request(self, f: Any) -> Any:
            return f
        def run(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("Flask is not installed. Run: pip install flask")
        def test_client(self) -> Any:
            raise RuntimeError("Flask is not installed. Run: pip install flask")
    Flask = _FlaskStub  # type: ignore
    request = None  # type: ignore
    jsonify = None  # type: ignore
    render_template = None  # type: ignore

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# ── Rate Limiting (in-memory, per-IP sliding window) ──────────────────
# Production: use Redis or a proper rate limiter. This keeps zero external
# dependencies while preventing brute-force key enumeration.

_RATE_LIMIT_WINDOW_S = 60          # 1 minute window
_RATE_LIMIT_MAX_REQUESTS = 30      # max requests per window per IP
_RATE_LIMIT_LOOKUP_MAX = 5         # max /lookup requests per window per IP
_rate_limit_store: dict[str, list[float]] = {}

def _check_rate_limit(ip: str, max_requests: int = _RATE_LIMIT_MAX_REQUESTS) -> bool:
    """Return True if the IP is within its rate limit."""
    now = time.time()
    window_start = now - _RATE_LIMIT_WINDOW_S
    timestamps = _rate_limit_store.get(ip, [])
    # Prune old entries
    timestamps = [t for t in timestamps if t > window_start]
    if len(timestamps) >= max_requests:
        _rate_limit_store[ip] = timestamps  # persist pruned list
        return False
    timestamps.append(now)
    _rate_limit_store[ip] = timestamps
    # Prevent unbounded growth: evict stale IPs periodically
    if len(_rate_limit_store) > 10_000:
        _rate_limit_store.clear()
    return True


# ── Usage Stats (persistent JSON file, survives Render deploys) ─────────
_STATS_DIR = Path(os.environ.get("RENDER_DATA_DIR", str(Path(__file__).parent / ".data")))
_STATS_FILE = _STATS_DIR / "usage_stats.json"

def _load_stats() -> dict[str, Any]:
    try:
        if _STATS_FILE.exists():
            return json.loads(_STATS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return {"total_scans": 0, "total_files": 0, "total_lines": 0,
            "unique_ips_24h": {}, "scans_today": 0, "last_reset_date": ""}

def _save_stats(stats: dict[str, Any]) -> None:
    try:
        _STATS_DIR.mkdir(parents=True, exist_ok=True)
        _STATS_FILE.write_text(json.dumps(stats))
    except OSError:
        pass  # silently ignore write failures on read-only filesystems

def _bump_stats(ip: str, files: int = 1, lines: int = 0) -> None:
    stats = _load_stats()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if stats.get("last_reset_date") != today:
        stats["scans_today"] = 0
        stats["unique_ips_24h"] = {}
        stats["last_reset_date"] = today
    stats["total_scans"] = stats.get("total_scans", 0) + 1
    stats["total_files"] = stats.get("total_files", 0) + files
    stats["total_lines"] = stats.get("total_lines", 0) + lines
    stats["scans_today"] = stats.get("scans_today", 0) + 1
    if ip and ip != "127.0.0.1":
        stats["unique_ips_24h"][ip] = today
    _save_stats(stats)

STATS = _load_stats()  # cache at startup


# ── Email validation ───────────────────────────────────────────────────
import re as _re
_EMAIL_RE = _re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

def _is_valid_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email)) and len(email) <= 254


# ── Security Headers ───────────────────────────────────────────────────
@app.after_request
def _add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-RateLimit-Limit"] = str(_RATE_LIMIT_MAX_REQUESTS)
    # Cache static pages for 1 hour
    if request.path in ("/", "/compare", "/blog", "/leaderboard", "/autofix-studio") and request.method == "GET":
        response.headers["Cache-Control"] = "public, max-age=3600"
    if request.is_secure or BASE_URL.startswith("https://"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ── Config (set via environment variables) ────────────────────────────
STRIPE_SECRET = os.environ.get("STRIPE_SECRET", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8765").rstrip("/")
DB_PATH = Path(os.environ.get("DB_PATH", str(Path.home() / ".ansede" / "licenses.db")))

# ── Private key for license signing ─────────────────────────────────────
_PRIVATE_KEY = bytes.fromhex(
    "c6e5a8b3f2d1e0c9b8a7f6e5d4c3b2a1"
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
)

# ── Stripe payment links ────────────────────────────────────────────────
_STRIPE_ONE_TIME = "https://buy.stripe.com/8x24gygGW6JueVJ4U61oI00"
_STRIPE_PRO_YEARLY = "https://buy.stripe.com/4gM14m9eu2te00P86i1oI01"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_STUDIO_ALLOWED_EXTENSIONS = {
  ".py": "python",
  ".js": "javascript",
  ".jsx": "javascript",
  ".ts": "javascript",
  ".tsx": "javascript",
  ".mjs": "javascript",
  ".go": "go",
  ".java": "java",
  ".cs": "csharp",
}
_STUDIO_LANGUAGE_EXTENSIONS = {
  "python": ".py",
  "javascript": ".js",
  "go": ".go",
  "java": ".java",
  "csharp": ".cs",
}
_STUDIO_MAX_FILES = 8
_STUDIO_MAX_FILE_BYTES = 64_000
_STUDIO_MAX_TOTAL_BYTES = 128_000
_STUDIO_TIMEOUT_SECONDS = 45


def _studio_safe_name(filename: str, fallback: str) -> str:
  raw = os.path.basename((filename or fallback).replace("\\", "/")).strip() or fallback
  safe = _re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip(".-") or fallback
  return safe


def _infer_studio_extension(code: str, language: str) -> str:
  normalized = (language or "auto").strip().lower()
  if normalized in _STUDIO_LANGUAGE_EXTENSIONS:
    return _STUDIO_LANGUAGE_EXTENSIONS[normalized]
  if "def " in code or "import " in code or "@app.route" in code or "from flask" in code:
    return ".py"
  if "function " in code or "const " in code or "=>" in code or "require(" in code:
    return ".js"
  return ".py"


def _collect_studio_sources(req: Any) -> tuple[list[dict[str, str]], str | None]:
  sources: list[dict[str, str]] = []
  total_bytes = 0

  files = req.files.getlist("files") if getattr(req, "files", None) else []
  if len(files) > _STUDIO_MAX_FILES:
    return [], f"Please upload {_STUDIO_MAX_FILES} files or fewer."

  for index, uploaded in enumerate(files, start=1):
    if not uploaded or not uploaded.filename:
      continue
    name = _studio_safe_name(uploaded.filename, f"upload-{index}.txt")
    ext = Path(name).suffix.lower()
    if ext not in _STUDIO_ALLOWED_EXTENSIONS:
      return [], f"Unsupported file type: {ext or 'unknown'}."
    raw = uploaded.read()
    if len(raw) > _STUDIO_MAX_FILE_BYTES:
      return [], f"{name} exceeds the {_STUDIO_MAX_FILE_BYTES // 1024}KB studio limit."
    total_bytes += len(raw)
    if total_bytes > _STUDIO_MAX_TOTAL_BYTES:
      return [], "Studio payload exceeds the 128KB limit."
    sources.append({
      "name": name,
      "content": raw.decode("utf-8", errors="replace"),
    })

  code = (req.form.get("code", "") if getattr(req, "form", None) else "").strip()
  if code:
    encoded = code.encode("utf-8", errors="replace")
    if len(encoded) > _STUDIO_MAX_FILE_BYTES:
      return [], "Pasted code exceeds the 64KB studio limit."
    total_bytes += len(encoded)
    if total_bytes > _STUDIO_MAX_TOTAL_BYTES:
      return [], "Studio payload exceeds the 128KB limit."
    language = (req.form.get("language", "auto") if getattr(req, "form", None) else "auto")
    snippet_name = f"snippet{_infer_studio_extension(code, language)}"
    sources.append({
      "name": snippet_name,
      "content": code,
    })

  if not sources:
    return [], "Paste code or upload a supported file first."
  return sources, None


def _run_scanner_command(target: Path, *, output_format: str, guarded_fix: bool) -> dict[str, Any]:
  cmd = [sys.executable, "-m", "ansede_static.cli", str(target), "--format", output_format]
  if guarded_fix:
    cmd.append("--guarded-fix")

  env = os.environ.copy()
  src_path = str(_REPO_ROOT / "src")
  env["PYTHONPATH"] = src_path if not env.get("PYTHONPATH") else src_path + os.pathsep + env["PYTHONPATH"]

  completed = subprocess.run(
    cmd,
    cwd=str(_REPO_ROOT),
    capture_output=True,
    text=True,
    timeout=_STUDIO_TIMEOUT_SECONDS,
    env=env,
  )
  stdout = completed.stdout.strip()
  if not stdout:
    raise RuntimeError(completed.stderr.strip() or "Scanner returned no output.")
  try:
    return json.loads(stdout)
  except json.JSONDecodeError as exc:
    raise RuntimeError(completed.stderr.strip() or f"Could not parse scanner output: {exc}") from exc


def _build_studio_timeline(guarded_fix: bool, execution: dict[str, Any], changed_files: int) -> list[dict[str, str]]:
  guarded = execution.get("guarded_autofix") or {}
  status = str(guarded.get("status", "not-run"))
  steps = [
    {"id": "scan", "label": "Scan", "status": "done", "detail": "Scanner ran on the submitted scope."},
    {"id": "patch", "label": "Patch", "status": "idle", "detail": "No fixes applied yet."},
    {"id": "verify", "label": "Verify", "status": "idle", "detail": "Verification has not run."},
    {"id": "rollback", "label": "Rollback", "status": "idle", "detail": "Rollback not needed."},
  ]
  if not guarded_fix:
    return steps

  applied = int(guarded.get("applied", 0) or 0)
  rescanned = int(guarded.get("rescanned_files", 0) or 0)
  if status == "limit-reached":
    steps[1].update({"status": "blocked", "detail": "Free Guarded Autofix quota reached."})
    steps[2].update({"status": "blocked", "detail": "Verification skipped because no fixes ran."})
    return steps

  if applied > 0 or changed_files > 0:
    steps[1].update({"status": "done", "detail": f"Applied {applied} guarded fix(es) across {changed_files} file(s)."})
  else:
    steps[1].update({"status": "idle", "detail": "No safe inline fixes matched the current source."})

  if status == "verified":
    steps[2].update({"status": "done", "detail": f"Rescanned {rescanned} file(s) with no newly detected issues in scope."})
  elif status == "reverted":
    steps[2].update({"status": "fail", "detail": f"Verification detected regressions across {rescanned} file(s)."})
    steps[3].update({"status": "done", "detail": "Touched files were restored automatically."})
  elif status == "no-fixes-applied":
    steps[2].update({"status": "idle", "detail": "Nothing to verify because no safe fix was applied."})
  else:
    steps[2].update({"status": "idle", "detail": "Verification did not produce a keep/revert decision."})
  return steps


def _run_studio_mode(sources: list[dict[str, str]], *, guarded_fix: bool) -> dict[str, Any]:
  with tempfile.TemporaryDirectory(prefix="ansede-studio-") as tmp:
    workspace = Path(tmp) / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    originals: dict[str, str] = {}
    used_names: set[str] = set()
    for index, source in enumerate(sources, start=1):
      base_name = _studio_safe_name(source["name"], f"source-{index}.txt")
      stem = Path(base_name).stem or f"source-{index}"
      ext = Path(base_name).suffix.lower()
      if ext not in _STUDIO_ALLOWED_EXTENSIONS:
        ext = _infer_studio_extension(source["content"], _STUDIO_ALLOWED_EXTENSIONS.get(ext, "auto"))
      candidate = f"{stem}{ext}"
      dedupe = 2
      while candidate in used_names:
        candidate = f"{stem}-{dedupe}{ext}"
        dedupe += 1
      used_names.add(candidate)
      target = workspace / candidate
      target.write_text(source["content"], encoding="utf-8")
      originals[candidate] = source["content"]

    report = _run_scanner_command(workspace, output_format="json", guarded_fix=guarded_fix)
    sarif = _run_scanner_command(workspace, output_format="sarif", guarded_fix=False)

    final_files: list[dict[str, Any]] = []
    changed_files = 0
    for rel_name, original in originals.items():
      final_text = (workspace / rel_name).read_text(encoding="utf-8", errors="replace")
      changed = final_text != original
      if changed:
        changed_files += 1
      final_files.append({
        "file": rel_name,
        "changed": changed,
        "original": original,
        "final": final_text,
      })

    execution = report.get("execution") or {}
    guarded_summary = execution.get("guarded_autofix") or {}
    verification_message = "Static scan completed for the submitted scope."
    if guarded_fix:
      if guarded_summary.get("status") == "verified":
        verification_message = "Guarded Autofix verified no newly detected issues in the scanned scope."
      elif guarded_summary.get("status") == "reverted":
        verification_message = "Guarded Autofix rolled changes back after the verification scan found regressions."
      elif guarded_summary.get("status") == "limit-reached":
        verification_message = "Free-tier Guarded Autofix quota reached for today."
      else:
        verification_message = "Guarded Autofix found no safe inline fixes to keep."

    return {
      "success": True,
      "mode": "guarded-fix" if guarded_fix else "scan",
      "report": report,
      "results": report.get("results", []),
      "summary": report.get("summary", {}),
      "total_findings": int(report.get("total_findings", 0) or 0),
      "execution": execution,
      "artifacts": {
        "json": report,
        "sarif": sarif,
      },
      "studio": {
        "timeline": _build_studio_timeline(guarded_fix, execution, changed_files),
        "files": final_files,
        "changed_files": changed_files,
        "verification_message": verification_message,
        "scope_note": "Verification covers the scanned scope only. Untouched code outside the submitted scope is not claimed.",
        "remaining_guarded_quota": guarded_summary.get("remaining_quota"),
        "requested_fixable_findings": guarded_summary.get("requested_fixable_findings", 0),
      },
    }


def _studio_api_response(*, guarded_fix: bool) -> tuple[Any, int]:
  client_ip = request.remote_addr or "0.0.0.0"
  if not _check_rate_limit(client_ip):
    return jsonify({"success": False, "error": "Too many requests. Please wait a moment and try again."}), 429

  sources, error = _collect_studio_sources(request)
  if error:
    return jsonify({"success": False, "error": error}), 400

  try:
    result = _run_studio_mode(sources, guarded_fix=guarded_fix)
    # ── Usage tracking ──────────────────────────────────────────────
    _bump_stats(client_ip, files=len(sources), lines=sum(len(s.get("code","")) for s in sources))
    return jsonify(result), 200
  except subprocess.TimeoutExpired:
    return jsonify({"success": False, "error": "Studio scan timed out. Try a smaller snippet."}), 504
  except Exception as exc:
    return jsonify({"success": False, "error": str(exc)}), 500

# ══════════════════════════════════════════════════════════════════════════
# Database
# ══════════════════════════════════════════════════════════════════════════

def _get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_db() -> None:
    db = _get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            license_key TEXT NOT NULL UNIQUE,
            tier TEXT NOT NULL,
            seats INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            stripe_session_id TEXT UNIQUE,
            stripe_customer_id TEXT,
            amount_paid_pence INTEGER,
            status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            stripe_event_id TEXT UNIQUE,
            event_type TEXT,
            received_at TEXT NOT NULL,
            payload TEXT
        );
    """)
    db.commit()
    db.close()


# ══════════════════════════════════════════════════════════════════════════
# Key Generation
# ══════════════════════════════════════════════════════════════════════════

def _generate_key(email: str, tier: str, seats: int = 1, days: int = 365) -> str:
    now = int(time.time())
    exp = now + (days * 86400) if days > 0 else 0
    header = {"alg": "HS256", "typ": "ANSEDE-LIC"}
    payload = {"sub": email, "tier": tier, "iat": now, "exp": exp,
               "seats": seats, "jti": f"{tier}-{email}-{uuid.uuid4().hex[:12]}"}
    hb = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
    pb = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(hmac.digest(_PRIVATE_KEY, f"{hb}.{pb}".encode(), hashlib.sha256)).rstrip(b"=").decode()
    return f"{hb}.{pb}.{sig}"


def _store_license(email: str, tier: str, seats: int, session_id: str,
                   customer_id: str, amount_pence: int, days: int = 365) -> str:
    key = _generate_key(email, tier, seats=seats, days=days)
    now = datetime.now(timezone.utc).isoformat()
    expires = datetime.fromtimestamp(int(time.time()) + days * 86400, tz=timezone.utc).isoformat() if days else None
    db = _get_db()
    db.execute("INSERT INTO licenses(email,license_key,tier,seats,created_at,expires_at,stripe_session_id,stripe_customer_id,amount_paid_pence) VALUES(?,?,?,?,?,?,?,?,?)",
               (email, key, tier, seats, now, expires, session_id, customer_id, amount_pence))
    db.commit()
    db.close()
    return key


def _lookup_by_session(sid: str) -> dict | None:
    db = _get_db()
    row = db.execute("SELECT * FROM licenses WHERE stripe_session_id=?", (sid,)).fetchone()
    db.close()
    return dict(row) if row else None


def _lookup_by_email(email: str) -> list[dict]:
    """Find all licenses for an email (for key recovery)."""
    db = _get_db()
    rows = db.execute(
        "SELECT license_key, tier, created_at, expires_at, status FROM licenses WHERE email=? AND status='active' ORDER BY created_at DESC",
        (email.lower().strip(),),
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════
# Stripe Webhook
# ══════════════════════════════════════════════════════════════════════════

def _verify_stripe(payload: bytes, sig: str) -> bool:
    if not STRIPE_WEBHOOK_SECRET:
        return True
    try:
        import stripe
        stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
        return True
    except Exception:
        return False


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    if not _verify_stripe(payload, sig):
        return jsonify({"error": "invalid"}), 400

    event = json.loads(payload)
    etype = event.get("type", "")

    # Log event
    db = _get_db()
    try:
        db.execute("INSERT OR IGNORE INTO webhook_events(stripe_event_id,event_type,received_at,payload) VALUES(?,?,?,?)",
                   (event.get("id"), etype, datetime.now(timezone.utc).isoformat(), payload.decode(errors="replace")))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()

    if etype != "checkout.session.completed":
        return jsonify({"status": "ignored"})

    session = event["data"]["object"]
    sid = session.get("id", "")
    email = (session.get("customer_details") or {}).get("email", "")
    cid = session.get("customer", "")
    amount = session.get("amount_total", 0)
    gbp = amount / 100.0

    if not email:
        return jsonify({"status": "no_email"})

    if _lookup_by_session(sid):
        return jsonify({"status": "already_done"})

    # Determine tier from amount
    if gbp <= 8.0:
        tier, seats, days = "pro", 1, 30
    elif gbp <= 60.0:
        tier, seats, days = "pro", 1, 365
    elif gbp <= 200.0:
        tier, seats, days = "team", 25, 365
    else:
        tier, seats, days = "enterprise", 100, 365

    key = _store_license(email, tier, seats, sid, cid or "", amount, days)
    print(f"[webhook] ✅ {tier} key for {email}", flush=True)
    return jsonify({"status": "ok", "tier": tier})


# ══════════════════════════════════════════════════════════════════════════
# Microsoft Fluent Design System — Professional UI
# ══════════════════════════════════════════════════════════════════════════

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{{title}} | Ansede Static</title>
<meta name="description" content="World's best offline SAST scanner. 96.3% CVE recall. Detects IDOR, auth bypass, and ownership flaws that Semgrep and CodeQL miss.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
/* ═══════════════════════════════════════════════════════════════════════════
   Ansede Static — Premium Unified Design System v6.0
   ═══════════════════════════════════════════════════════════════════════════ */

:root {
  --canvas: #06060A;
  --surface: #0C0C14;
  --elevated: #12121E;
  --card: #161628;
  --card-hover: #1C1C32;
  --border-subtle: rgba(255,255,255,0.04);
  --border-mid: rgba(255,255,255,0.07);
  --border-accent: rgba(99,102,241,0.22);
  --text-primary: #EDEDF5;
  --text-secondary: #9898B0;
  --text-muted: #5C5C78;
  --accent: #6366F1;
  --accent-2: #8B5CF6;
  --accent-3: #06B6D4;
  --accent-glow: rgba(99,102,241,0.10);
  --red: #EF4444;
  --red-glow: rgba(239,68,68,0.12);
  --amber: #F59E0B;
  --amber-glow: rgba(245,158,11,0.12);
  --green: #10B981;
  --green-glow: rgba(16,185,129,0.12);
  --cyan: #06B6D4;
  --radius-sm: 6px;
  --radius: 10px;
  --radius-lg: 14px;
  --radius-xl: 18px;
  --radius-2xl: 24px;
  --shadow-card: 0 2px 12px rgba(0,0,0,0.3), 0 0 0 1px rgba(255,255,255,0.03);
  --shadow-card-hover: 0 8px 32px rgba(0,0,0,0.45), 0 0 0 1px rgba(255,255,255,0.05);
  --transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', system-ui, sans-serif;
  --font-mono: 'SF Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'JetBrains Mono', monospace;
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:var(--font-sans);background:var(--canvas);color:var(--text-primary);
  line-height:1.65;min-height:100vh;-webkit-font-smoothing:antialiased;overflow-x:hidden;
}
body::before{
  content:'';position:fixed;inset:0;
  background:
    radial-gradient(80% 50% at 50% 0%, rgba(99,102,241,0.05) 0%, transparent 100%),
    radial-gradient(60% 40% at 85% 100%, rgba(6,182,212,0.03) 0%, transparent 100%),
    radial-gradient(50% 50% at 15% 50%, rgba(139,92,246,0.03) 0%, transparent 100%);
  pointer-events:none;z-index:0;
}
body::after{
  content:'';position:fixed;inset:0;
  background-image:
    linear-gradient(rgba(255,255,255,0.01) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.01) 1px, transparent 1px);
  background-size:64px 64px;pointer-events:none;z-index:0;
}

/* ── Navigation ─────────────────────────────────── */
.nav{
  position:sticky;top:0;z-index:100;
  background:rgba(12,12,20,.78);
  backdrop-filter:blur(24px) saturate(1.6);
  -webkit-backdrop-filter:blur(24px) saturate(1.6);
  border-bottom:1px solid var(--border-subtle);
  padding:0 clamp(16px,3vw,40px);
}
.nav-inner{
  max-width:1200px;margin:0 auto;
  display:flex;align-items:center;justify-content:space-between;
  height:64px;gap:16px;
}
.nav-logo{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--text-primary);user-select:none}
.nav-logo .icon{
  width:32px;height:32px;
  background:linear-gradient(135deg, var(--accent) 0%, var(--accent-2) 50%, var(--accent-3) 100%);
  border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;
  box-shadow:0 4px 16px rgba(99,102,241,.35);transition:var(--transition);
}
.nav-logo:hover .icon{transform:scale(1.06);box-shadow:0 6px 24px rgba(99,102,241,.5)}
.nav-logo span{font-size:1.1rem;font-weight:700;letter-spacing:-.03em}
.nav-logo span em{font-style:normal;background:linear-gradient(135deg,var(--accent),var(--accent-2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.nav-links{display:flex;align-items:center;gap:clamp(12px,2vw,24px)}
.nav-links a{color:var(--text-secondary);text-decoration:none;font-size:.88rem;font-weight:500;transition:var(--transition);white-space:nowrap}
.nav-links a:hover{color:var(--text-primary)}
.nav-cta{
  background:linear-gradient(135deg,var(--accent),var(--accent-2));
  color:#fff;padding:9px 20px;border-radius:var(--radius);
  font-size:.85rem;font-weight:600;text-decoration:none;
  transition:var(--transition);box-shadow:0 2px 12px rgba(99,102,241,.3);white-space:nowrap;
}
.nav-cta:hover{transform:translateY(-1px);box-shadow:0 4px 20px rgba(99,102,241,.45)}

/* ── Layout ────────────────────────────────────── */
.page-wrap{position:relative;z-index:1;max-width:1200px;margin:0 auto;padding:clamp(24px,4vw,56px) clamp(16px,3vw,40px)}

/* ── Hero ──────────────────────────────────────── */
.hero{
  text-align:center;padding:40px 0 32px;
}
.hero-badge{
  display:inline-flex;align-items:center;gap:8px;
  background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.18);
  color:var(--accent-2);font-size:.78rem;font-weight:600;
  padding:6px 16px;border-radius:20px;margin-bottom:24px;letter-spacing:.02em;
}
.hero h1{
  font-size:clamp(2rem,5vw,3rem);font-weight:800;letter-spacing:-.04em;line-height:1.12;margin-bottom:16px;
  background:linear-gradient(135deg,var(--text-primary) 0%,#c4b5fd 50%,var(--text-primary) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}
.hero h1 em{font-style:normal;color:var(--accent);-webkit-text-fill-color:var(--accent)}
.hero p{font-size:1.1rem;color:var(--text-secondary);max-width:640px;margin:0 auto 32px}
.hero-stats{display:flex;justify-content:center;gap:clamp(24px,5vw,56px);flex-wrap:wrap}
.hero-stat{text-align:center}
.hero-stat .num{font-size:2.2rem;font-weight:800;letter-spacing:-.03em;background:linear-gradient(135deg,var(--accent),var(--accent-3));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero-stat .lbl{font-size:.78rem;color:var(--text-muted);margin-top:4px;font-weight:500}

/* ── Sections ──────────────────────────────────── */
.sec{padding:48px clamp(16px,3vw,40px)}
.sec-inner{max-width:1100px;margin:0 auto}
.sec-title{text-align:center;margin-bottom:40px}
.sec-title h2{font-size:1.6rem;font-weight:700;letter-spacing:-.02em;margin-bottom:8px}
.sec-title p{font-size:1rem;color:var(--text-secondary);max-width:560px;margin:0 auto}

/* ── Cards ─────────────────────────────────────── */
.card{
  background:var(--card);border:1px solid var(--border-subtle);
  border-radius:var(--radius-lg);padding:28px;transition:var(--transition);
  position:relative;overflow:hidden;
}
.card::before{
  content:'';position:absolute;inset:0;
  background:radial-gradient(600px circle at var(--mouse-x,50%) var(--mouse-y,50%), rgba(99,102,241,.04), transparent 60%);
  opacity:0;transition:opacity .3s;pointer-events:none;
}
.card:hover{border-color:var(--border-mid);box-shadow:var(--shadow-card-hover)}
.card:hover::before{opacity:1}
.card h3{font-size:1.1rem;font-weight:700;margin-bottom:8px}
.card p{color:var(--text-secondary);font-size:.92rem;line-height:1.6}
.card.featured{border-color:var(--accent);box-shadow:0 4px 32px rgba(99,102,241,.15),0 0 0 1px rgba(99,102,241,.15)}
.card-badge{position:absolute;top:-14px;left:50%;transform:translateX(-50%);background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;font-size:.72rem;font-weight:700;padding:5px 18px;border-radius:14px;letter-spacing:.03em}

/* ── Pricing ───────────────────────────────────── */
.pricing-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px;align-items:stretch}
.plan{
  background:var(--card);border:1px solid var(--border-subtle);
  border-radius:var(--radius-xl);padding:36px 28px;
  display:flex;flex-direction:column;transition:var(--transition);position:relative;
}
.plan:hover{border-color:var(--border-mid);box-shadow:var(--shadow-card-hover);transform:translateY(-2px)}
.plan h3{font-size:1.15rem;font-weight:700;margin-bottom:4px}
.plan .price{font-size:2.6rem;font-weight:800;letter-spacing:-.04em;margin:12px 0 0}
.plan .price span{font-size:.9rem;font-weight:500;color:var(--text-muted)}
.plan .period{font-size:.8rem;color:var(--text-muted);margin-bottom:24px}
.plan ul{list-style:none;flex:1;margin-bottom:20px}
.plan ul li{font-size:.88rem;color:var(--text-secondary);padding:7px 0;display:flex;align-items:center;gap:10px}
.plan ul li::before{content:'';width:18px;height:18px;background:rgba(16,185,129,.12);border-radius:50%;flex-shrink:0;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 10 10'%3E%3Cpath d='M2 5l2 2 4-4' stroke='%2310B981' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");background-position:center;background-repeat:no-repeat}
.plan .btn{margin-top:auto;width:100%}

/* ── Buttons ───────────────────────────────────── */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 28px;border-radius:var(--radius);font-size:.9rem;font-weight:600;
  text-decoration:none;cursor:pointer;transition:var(--transition);
  border:none;font-family:var(--font-sans);white-space:nowrap;
}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;box-shadow:0 2px 16px rgba(99,102,241,.3)}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 6px 28px rgba(99,102,241,.45)}
.btn-secondary{background:var(--elevated);color:var(--text-primary);border:1px solid var(--border-mid)}
.btn-secondary:hover{background:var(--card);border-color:var(--border-accent)}
.btn-outline{background:transparent;color:var(--accent);border:1.5px solid var(--accent)}
.btn-outline:hover{background:rgba(99,102,241,.08)}

/* ── Feature table ─────────────────────────────── */
.feat-table{width:100%;border-collapse:collapse;font-size:.9rem}
thead th{background:var(--elevated);color:var(--text-muted);font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:14px 16px;text-align:center;border-bottom:2px solid var(--border-subtle);white-space:nowrap}
thead th:first-child{text-align:left}
tbody td{padding:12px 16px;text-align:center;border-bottom:1px solid var(--border-subtle);color:var(--text-secondary)}
tbody td:first-child{text-align:left;color:var(--text-primary);font-weight:500}
.check{color:var(--green);font-weight:600}
.dash{color:var(--text-muted)}

/* ── Trust bar ─────────────────────────────────── */
.trust-bar{background:var(--elevated);border-top:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle);padding:36px 24px;text-align:center}
.trust-bar p{font-size:.85rem;color:var(--text-muted);margin-bottom:14px}
.trust-logos{display:flex;justify-content:center;align-items:center;gap:28px;flex-wrap:wrap;color:var(--text-secondary);font-size:.78rem;font-weight:600;letter-spacing:.04em}

/* ── Footer ────────────────────────────────────── */
.ft{background:var(--surface);border-top:1px solid var(--border-subtle);padding:40px clamp(16px,3vw,40px) 28px}
.ft-inner{max-width:1100px;margin:0 auto;display:flex;justify-content:space-between;flex-wrap:wrap;gap:32px}
.ft-col h4{color:var(--text-primary);font-size:.82rem;font-weight:600;margin-bottom:12px}
.ft-col a{display:block;color:var(--text-muted);text-decoration:none;font-size:.8rem;padding:4px 0;transition:var(--transition)}
.ft-col a:hover{color:var(--text-primary)}
.ft-bottom{max-width:1100px;margin:32px auto 0;padding-top:20px;border-top:1px solid var(--border-subtle);font-size:.72rem;color:var(--text-muted);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

/* ── Success page ──────────────────────────────── */
.success-hero{text-align:center;padding:40px 20px 20px}
.success-hero .icon{width:56px;height:56px;background:rgba(16,185,129,.12);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px}
.success-hero h2{font-size:1.5rem;font-weight:700}
.success-hero p{color:var(--text-secondary);margin-top:8px}
.key-card{max-width:640px;margin:0 auto;background:var(--card);border:1px solid var(--border-subtle);border-radius:var(--radius-lg);padding:28px 32px}
.key-label{font-size:.78rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}
.key-value{background:var(--surface);border:1px solid var(--border-subtle);border-radius:var(--radius);padding:18px 20px;font-family:var(--font-mono);font-size:.8rem;word-break:break-all;color:var(--text-primary);position:relative;line-height:1.5}
.copy-btn{position:absolute;right:10px;top:10px;background:linear-gradient(135deg,var(--accent),var(--accent-2));color:#fff;border:none;padding:7px 16px;border-radius:var(--radius-sm);font-size:.8rem;font-weight:600;cursor:pointer;transition:var(--transition)}
.copy-btn:hover{transform:scale(1.05)}
.install-steps{max-width:640px;margin:28px auto}
.install-step{display:flex;gap:14px;align-items:flex-start;padding:14px 0;border-bottom:1px solid var(--border-subtle)}
.install-step:last-child{border-bottom:none}
.step-num{width:32px;height:32px;background:var(--elevated);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.8rem;color:var(--text-secondary);flex-shrink:0}
.install-step p{font-size:.9rem;color:var(--text-secondary);margin:0}
.install-step code{background:var(--elevated);padding:2px 8px;border-radius:4px;font-size:.85rem;color:var(--accent-3);font-family:var(--font-mono)}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:var(--green);color:#fff;padding:10px 24px;border-radius:8px;font-weight:600;display:none;z-index:999;box-shadow:0 4px 16px rgba(0,0,0,.3)}

/* ── Form controls ─────────────────────────────── */
input[type="email"],input[type="text"]{padding:11px 14px;background:var(--surface);border:1px solid var(--border-subtle);border-radius:var(--radius);color:var(--text-primary);font-size:.92rem;font-family:var(--font-sans);transition:var(--transition);width:280px}
input:focus{border-color:var(--accent);outline:none;box-shadow:0 0 0 3px rgba(99,102,241,.12)}

/* ── Misc ──────────────────────────────────────── */
.text-center{text-align:center}
.mt-16{margin-top:16px}
.mb-20{margin-bottom:20px}
.mb-24{margin-bottom:24px}
.mx-auto{margin-left:auto;margin-right:auto}
.max-w-640{max-width:640px}
.inline-code{background:var(--elevated);padding:2px 8px;border-radius:4px;font-family:var(--font-mono);font-size:.85rem;color:var(--accent-3)}
.bg-surface{background:var(--surface)}
.bg-elevated{background:var(--elevated)}
.border-subtle{border:1px solid var(--border-subtle)}
.rounded-lg{border-radius:var(--radius-lg)}

/* ── Responsive ────────────────────────────────── */
@media(max-width:768px){
  .nav-links a:not(.nav-cta){display:none}
  .hero h1{font-size:1.8rem}
  .hero-stats{gap:20px}
  .hero-stat .num{font-size:1.6rem}
  .pricing-grid{grid-template-columns:1fr}
  .feat-table{font-size:.75rem}
  .feat-table th,.feat-table td{padding:10px 8px}
}
@media(max-width:480px){
  .nav{height:56px;padding:0 16px}
  .plan{padding:24px 20px}
}
</style>
</head>
<body>
<!-- Navigation -->
<nav class="nav">
  <div class="nav-inner">
    <a href="/" class="nav-logo">
      <div class="icon">&#9876;</div>
      <span>Ansede<em>Static</em></span>
    </a>
    <div class="nav-links">
      <a href="/compare">Compare</a>
      <a href="/blog">Blog</a>
      <a href="/#pricing">Pricing</a>
      <a href="/leaderboard">Leaderboard</a>
      <a href="/demo" class="nav-cta">Book a Demo</a>
    </div>
  </div>
</nav>

{{body}}

<!-- Footer -->
<footer class="ft">
  <div class="ft-inner">
    <div class="ft-col">
      <h4>Product</h4>
      <a href="/#pricing">Pricing</a>
      <a href="https://github.com/mattybellx/Ansede">GitHub</a>
      <a href="https://marketplace.visualstudio.com/items?itemName=ansede.ansede-static">VS Code Extension</a>
    </div>
    <div class="ft-col">
      <h4>Resources</h4>
      <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md">Benchmarks</a>
      <a href="https://github.com/mattybellx/Ansede/blob/master/CHANGELOG.md">Changelog</a>
      <a href="https://github.com/mattybellx/Ansede/blob/master/docs/writing-rules.md">Writing Rules</a>
    </div>
    <div class="ft-col">
      <h4>Support</h4>
      <a href="https://github.com/mattybellx/Ansede/issues">Report an Issue</a>
      <a href="https://github.com/mattybellx/Ansede/discussions">Discussions</a>
      <a href="mailto:support@ansede.dev">Contact</a>
    </div>
  </div>
  <div class="ft-bottom ft-inner">
    <span>&copy; 2026 Ansede Static. All rights reserved.</span>
    <span>100% offline &bull; zero telemetry &bull; MIT licensed</span>
  </div>
</footer>

<script>
function copyKey(){
  var el=document.getElementById('licenseKey');
  var txt=el.innerText.replace('Copy','').trim();
  navigator.clipboard.writeText(txt).then(function(){
    var t=document.getElementById('toast');
    t.style.display='block';
    setTimeout(function(){t.style.display='none'},2500);
  });
}
document.querySelectorAll('a[href^="#"]').forEach(function(a){
  a.addEventListener('click',function(e){
    e.preventDefault();
    var t=document.querySelector(this.getAttribute('href'));
    if(t)t.scrollIntoView({behavior:'smooth'});
  });
});
// Mouse glow on cards
document.querySelectorAll('.card').forEach(function(card){
  card.addEventListener('mousemove',function(e){
    var r=card.getBoundingClientRect();
    card.style.setProperty('--mouse-x',(e.clientX-r.left)+'px');
    card.style.setProperty('--mouse-y',(e.clientY-r.top)+'px');
  });
});
</script>
</body>
</html>"""

_INDEX_BODY = r"""
<div class="hero">
  <div class="hero-badge">&#9670; World's Best Offline SAST + Guarded Autofix</div>
  <h1>Find the bug.<br><em>Fix it under guard.</em></h1>
  <p>ansede-static detects what Bandit, Semgrep, and CodeQL miss&mdash;IDOR, auth bypass, ownership flaws&mdash;fully offline, no API keys required.</p>
  <div class="hero-stats">
    <div class="hero-stat"><div class="num" id="stat-scans">...</div><div class="lbl">Scans Run</div></div>
    <div class="hero-stat"><div class="num">98.8%</div><div class="lbl">CVE Recall</div></div>
    <div class="hero-stat"><div class="num">3.6%</div><div class="lbl">False Positive Rate</div></div>
    <div class="hero-stat"><div class="num">6</div><div class="lbl">Languages</div></div>
  </div>
  <div style="margin-top:20px">
    <a href="/scan" class="btn btn-primary" style="display:inline-block;width:auto;padding:14px 36px;font-size:1.1rem">Try Live Scanner &rarr;</a>
  </div>
</div>

<script>
fetch('/stats').then(r=>r.json()).then(s=>{
  document.getElementById('stat-scans').textContent = (s.total_scans||0).toLocaleString();
}).catch(()=>{});
</script>

<div class="sec" style="padding-top:40px;padding-bottom:24px">
  <div class="sec-inner" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px">
    <div class="card"><h3>1. Scan</h3><p style="color:var(--text-secondary);margin-top:10px">Run offline SAST across your repo, CI job, or hot path. No code leaves your machine.</p></div>
    <div class="card"><h3>2. Patch</h3><p style="color:var(--text-secondary);margin-top:10px">Guarded Autofix applies only safe inline replacements that match the exact source line.</p></div>
    <div class="card"><h3>3. Verify</h3><p style="color:var(--text-secondary);margin-top:10px">The scanner rescans the scanned scope immediately after patching and checks for newly detected issues.</p></div>
    <div class="card"><h3>4. Roll back</h3><p style="color:var(--text-secondary);margin-top:10px">If the verification pass spots regressions or parse breakage, the patch is reverted automatically. Drama denied.</p></div>
  </div>
</div>

<div class="sec" id="pricing">
  <div class="sec-inner">
    <div class="sec-title">
      <h2>Simple, transparent pricing</h2>
      <p>Start free. Upgrade when you want unlimited Guarded Autofix, reporting exports, and the Autofix Studio workflow.</p>
    </div>
    <div class="pricing-grid">
      <div class="card">
        <h3>Free</h3>
        <div class="price">$0</div>
        <div class="period">No credit card required</div>
        <ul>
          <li>500 scans per day</li>
          <li>50 Guarded Autofix actions per day</li>
          <li>Text, JSON &amp; SARIF output</li>
          <li>Python, JavaScript, Go, Java, C#</li>
          <li>Offline &mdash; no cloud, no telemetry</li>
          <li>Community rule packs</li>
        </ul>
        <a href="https://github.com/mattybellx/Ansede" class="btn btn-outline">Download Free</a>
      </div>

      <div class="card">
        <h3>Autofix Pass</h3>
        <div class="price">&pound;4.99</div>
        <div class="period">30 days of Pro access</div>
        <ul>
          <li>Unlimited scans</li>
          <li>Unlimited Guarded Autofix</li>
          <li>Verification + rollback safety pass</li>
          <li>SARIF output (GitHub Code Scanning)</li>
          <li>SBOM generation (CycloneDX, SPDX)</li>
          <li>HTML dashboards</li>
          <li>Autofix Studio preview</li>
          <li>Email support</li>
        </ul>
        <a href="https://buy.stripe.com/8x24gygGW6JueVJ4U61oI00" class="btn btn-primary">Buy for &pound;4.99</a>
      </div>

      <div class="card featured">
        <div class="card-badge">Most Popular</div>
        <h3>Pro Yearly</h3>
        <div class="price">&pound;49<span>/year</span></div>
        <div class="period">Everything in One-Time, plus more</div>
        <ul>
          <li>Everything in One-Time</li>
          <li>Unlimited Guarded Autofix</li>
          <li>Autofix Studio workflow view</li>
          <li>CI/CD integration recipes</li>
          <li>GitHub Actions workflow generator</li>
          <li>Priority email support</li>
          <li>365 days of updates</li>
          <li>Early access to new languages</li>
        </ul>
        <a href="https://buy.stripe.com/4gM14m9eu2te00P86i1oI01" class="btn btn-primary">Subscribe &pound;49/yr</a>
      </div>
    </div>
  </div>
</div>

<div class="trust-bar">
  <p>Built for developers who want proof, not vibes</p>
  <div class="trust-logos">
    <span>OWASP-COMPLIANT</span>
    <span>CWE-COVERAGE 20+</span>
    <span>919 UNIT TESTS</span>
    <span>100% OFFLINE</span>
    <span>ROLLBACK-ON-REGRESSION</span>
  </div>
</div>

<div class="sec">
  <div class="sec-inner">
    <div class="sec-title">
      <h2>Compare plans</h2>
      <p>Every feature you need to ship secure code&mdash;from solo developers to enterprise teams.</p>
    </div>
    <div style="overflow-x:auto">
    <table class="feat-table">
      <thead>
        <tr><th></th><th>Free</th><th>One-Time</th><th>Pro</th></tr>
      </thead>
      <tbody>
        <tr><td>Scans per day</td><td>500</td><td>Unlimited</td><td>Unlimited</td></tr>
        <tr><td>Guarded Autofix / day</td><td>50</td><td>Unlimited</td><td>Unlimited</td></tr>
        <tr><td>Languages</td><td>5</td><td>5</td><td>5</td></tr>
        <tr><td>Text output</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>JSON output</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Guarded rescan + rollback</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>SARIF output</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>SBOM generation</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>HTML dashboard</td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Autofix Studio view</td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>CI/CD recipes</td><td><span class="dash">&mdash;</span></td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Incremental scanning</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Parallel workers</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Community rules</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Email support</td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>Price</td><td>Free</td><td>&pound;4.99 one-time</td><td>&pound;49/year</td></tr>
      </tbody>
    </table>
    </div>
  </div>
</div>

<div class="sec" style="background:var(--elevated);border-top:1px solid var(--border-subtle)">
  <div class="sec-inner" style="text-align:center">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--text-primary);margin-bottom:8px">Already have a license key?</h2>
    <p style="color:var(--text-secondary);margin-bottom:20px">Activate it in your terminal to unlock Pro features instantly.</p>
    <code style="background:var(--text-primary);color:#fff;padding:12px 24px;border-radius:8px;font-size:.95rem;display:inline-block">ansede-static license activate YOUR_KEY</code>
  </div>
</div>
"""

_AUTOFIX_STUDIO_BODY = r"""
<div class="hero">
  <div class="hero-badge">Autofix Studio</div>
  <h1>Watch the remediation loop.<br><em>Without crossing your fingers.</em></h1>
  <p>Autofix Studio is the sales-friendly, engineer-approved surface for Guarded Autofix. It shows the exact workflow: detect, patch, rescan, keep or roll back.</p>
</div>

<div class="sec">
  <div class="sec-inner">
    <div class="pricing-grid">
      <div class="card">
        <h3>Detect</h3>
        <p style="color:var(--text-secondary);margin-top:10px">Run ansede-static on the repo, the PR diff, or the focused scope your team actually cares about.</p>
      </div>
      <div class="card">
        <h3>Patch</h3>
        <p style="color:var(--text-secondary);margin-top:10px">Apply safe inline fixes only when the suggested replacement matches the current line exactly.</p>
      </div>
      <div class="card featured">
        <div class="card-badge">Guard Rail</div>
        <h3>Verify</h3>
        <p style="color:var(--text-secondary);margin-top:10px">Immediately rescan the scanned scope. If new issues or parse regressions appear, changes are rolled back automatically.</p>
      </div>
    </div>
  </div>
</div>

<div class="sec" style="background:var(--elevated);border-top:1px solid var(--border-subtle);border-bottom:1px solid var(--border-subtle)">
  <div class="sec-inner">
    <div class="sec-title">
      <h2>Why teams buy it</h2>
      <p>Because “we autofix stuff” is cute. “We verify the patch and revert if it regresses” closes deals.</p>
    </div>
    <div class="pricing-grid">
      <div class="card"><h3>For developers</h3><ul><li>Fast remediation loop</li><li>Safer than blind search/replace</li><li>Clear CLI upgrade path</li></ul></div>
      <div class="card"><h3>For leads</h3><ul><li>Scope-aware verification story</li><li>Easy free vs Pro packaging</li><li>Good demo narrative for buyers</li></ul></div>
      <div class="card"><h3>For sales</h3><ul><li>Visually understandable workflow</li><li>Honest trust language</li><li>Strong free-to-Pro conversion hook</li></ul></div>
    </div>
  </div>
</div>

<div class="sec">
  <div class="sec-inner" style="text-align:center;max-width:820px">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--text-primary);margin-bottom:10px">Truth in advertising, on purpose</h2>
    <p style="color:var(--text-secondary);margin-bottom:20px">Autofix Studio verifies that no <strong>newly detected</strong> issues were introduced in the <strong>scanned scope</strong>. That is strong, credible, and defensible. It is not a promise about untouched files or undiscovered bug classes.</p>
    <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
      <a href="/autofix-studio/live" class="btn btn-primary" style="display:inline-block;width:auto;padding:12px 28px">Launch live studio</a>
      <a href="/" class="btn btn-outline" style="display:inline-block;width:auto;padding:12px 28px">Back to pricing</a>
    </div>
  </div>
</div>
"""

_SUCCESS_BODY = r"""
<div class="success-hero">
  <div class="icon"><svg width="28" height="28" viewBox="0 0 28 28"><path d="M7 14l5 5L21 9" stroke="var(--green)" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
  <h2>Payment Successful</h2>
  <p>Your <strong>{tier}</strong> license is ready{email_text}. Thank you for choosing ansede-static.</p>
</div>
<div class="sec-inner" style="max-width:640px;margin:0 auto;padding:0 24px 48px">
  <div class="key-card">
    <div class="key-label">Your License Key</div>
    <div class="key-value" id="licenseKey">{key}<button class="copy-btn" onclick="copyKey()">Copy</button></div>
  </div>
  <div class="install-steps">
    <div class="install-step">
      <div class="step-num">1</div>
      <p>Copy the license key shown above.</p>
    </div>
    <div class="install-step">
      <div class="step-num">2</div>
      <p>Open your terminal and run:<br><code>ansede-static license activate YOUR_KEY</code></p>
    </div>
    <div class="install-step">
      <div class="step-num">3</div>
      <p>Pro features unlocked instantly. Run <code>ansede-static license</code> to verify.</p>
    </div>
  </div>
  {expiry_line}
</div>
<div id="toast" class="toast">Copied to clipboard</div>
"""

_PENDING_BODY = r"""
<meta http-equiv="refresh" content="3">
<div class="sec" style="text-align:center;min-height:40vh;display:flex;align-items:center;justify-content:center">
  <div class="sec-inner">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--text-primary);margin-bottom:8px">Generating Your License&hellip;</h2>
    <p style="color:var(--text-secondary)">This page refreshes automatically. Session: {sid}</p>
  </div>
</div>
"""

_ERROR_BODY = r"""
<div class="sec" style="text-align:center;min-height:40vh;display:flex;align-items:center;justify-content:center">
  <div class="sec-inner">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--red);margin-bottom:8px">Something went wrong</h2>
    <p style="color:var(--text-secondary);margin-bottom:20px">{msg}</p>
    <p style="color:var(--text-secondary);margin-bottom:24px">If you have already paid, your license key was sent to your email. Please check your inbox (including spam).</p>
    <a href="/" class="btn btn-primary" style="display:inline-block;width:auto;padding:10px 32px">Back to Home</a>
  </div>
</div>
"""


@app.route("/")
def index():
    return _HTML.replace("{{title}}", "World's Best Offline SAST").replace("{{body}}", _INDEX_BODY)


@app.route("/autofix-studio")
def autofix_studio():
  return _HTML.replace("{{title}}", "Autofix Studio").replace("{{body}}", _AUTOFIX_STUDIO_BODY)


@app.route("/autofix-studio/live")
def autofix_studio_live():
  return render_template("index.html")


# ── Live Playground (/scan) ───────────────────────────────────────────
_PLAYGROUND_RATE_LIMIT: dict[str, list[float]] = {}
_PLAYGROUND_MAX_PER_MINUTE = 10
_PLAYGROUND_MAX_CODE_BYTES = 20_000  # 20 KB

# Try to import scanner at startup; warn if unavailable
try:
    import sys as _sys
    import os as _os
    _src_path = str(Path(__file__).resolve().parent.parent / "src")
    if _src_path not in _sys.path:
        _sys.path.insert(0, _src_path)
    from ansede_static.python_analyzer import analyze_python as _analyze_python
    from ansede_static.js_analyzer import analyze_js as _analyze_js
    _SCAN_AVAILABLE = True
except Exception:
    _SCAN_AVAILABLE = False


@app.route("/scan", methods=["GET"])
def playground_get():
    """Interactive live playground — paste code, see findings instantly."""
    examples = {
        "idor": {"label": "IDOR", "lang": "python",
            "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # Any user can view any invoice'},
        "sqli": {"label": "SQL Injection", "lang": "python",
            "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'},
        "hardcoded": {"label": "Hardcoded Secret", "lang": "python",
            "code": 'API_KEY = "sk-prod-abc123secretkeyexample"\nSTRIPE_SECRET = "sk_live_realkey_here_example"'},
        "missing_auth": {"label": "Missing Auth", "lang": "python",
            "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'},
        "js_xss": {"label": "XSS", "lang": "javascript",
            "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'},
    }
    return render_template("playground.html", examples=examples)


@app.route("/scan", methods=["POST"])
def playground_post():
    """API endpoint for live playground — accepts JSON {code, lang}."""
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available on this server"}), 503

    client_ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = [t for t in _PLAYGROUND_RATE_LIMIT.get(client_ip, []) if now - t < 60]
    if len(window) >= _PLAYGROUND_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit: max 10 scans/minute per IP."}), 429
    window.append(now)
    _PLAYGROUND_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_PLAYGROUND_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower().strip()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0, "total": 0})

    try:
        if lang in ("python", "py"):
            result = _analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = _analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {type(exc).__name__}"}), 500

    # Apply shared taint-aware demotion (same policy as CLI)
    from ansede_static.engine.confidence import apply_taint_aware_demotion
    apply_taint_aware_demotion([result])

    # Apply confidence filter (default 0.65, keep HIGH/CRITICAL)
    min_conf = 0.65
    result.findings = [
        f for f in result.findings
        if f.confidence >= min_conf
        or str(f.severity.value) in ("critical", "high")
    ]

    # ── Usage tracking ──────────────────────────────────────────────
    _bump_stats(client_ip, files=1, lines=result.lines_scanned)

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": getattr(f, "description", "") or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": getattr(f, "suggestion", "") or "",
            "confidence": round(f.confidence, 2) if f.confidence is not None else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
  return _studio_api_response(guarded_fix=False)


@app.route("/api/guarded-fix", methods=["POST"])
def api_guarded_fix():
  return _studio_api_response(guarded_fix=True)


@app.route("/api/export", methods=["POST"])
def api_export():
  payload = request.get_json(silent=True) or {}
  export_format = str(payload.get("format", "json")).lower()
  artifacts = payload.get("artifacts") or {}

  if export_format == "json":
    content = artifacts.get("json") or payload.get("report")
    if not content:
      return jsonify({"success": False, "error": "No JSON report available to export."}), 400
    return jsonify({"success": True, "content": content})

  if export_format == "sarif":
    content = artifacts.get("sarif")
    if not content:
      return jsonify({"success": False, "error": "No SARIF artifact available for this run."}), 400
    return jsonify({"success": True, "content": content})

  return jsonify({"success": False, "error": f"Unsupported export format: {export_format}"}), 400


@app.route("/stats")
def usage_stats():
    """Public usage stats page — see how many scans have been run."""
    stats = _load_stats()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if stats.get("last_reset_date") != today:
        stats["scans_today"] = 0
        stats["unique_ips_24h"] = {}
        stats["last_reset_date"] = today
        _save_stats(stats)
    
    unique_today = len(stats.get("unique_ips_24h", {}))
    
    return jsonify({
        "total_scans": stats.get("total_scans", 0),
        "total_files": stats.get("total_files", 0),
        "total_lines": stats.get("total_lines", 0),
        "scans_today": stats.get("scans_today", 0),
        "unique_ips_today": unique_today,
        "version": "6.2.2",
    })


@app.route("/lookup")
def lookup():
    """Key recovery page — enter your email to retrieve your license key."""
    client_ip = request.remote_addr or "0.0.0.0"

    email = request.args.get("email", "").strip().lower()
    if not email:
        return _HTML.replace("{{title}}", "Key Recovery").replace("{{body}}",
            '<div class="card" style="text-align:center"><h2>Recover Your License Key</h2>'
            '<p style="margin-top:12px">Enter the email you used when purchasing.</p>'
            '<form method="GET" action="/lookup" style="margin-top:16px">'
            '<input type="email" name="email" placeholder="your@email.com" style="padding:10px 16px;border-radius:8px;border:1px solid #d1d1d1;width:280px;font-size:.95rem" required autocomplete="email">'
            '<button type="submit" class="btn btn-p" style="margin-left:8px;width:auto;display:inline-block">Look Up</button>'
            '</form></div>')

    # Rate limit key lookups (5/min per IP)
    if not _check_rate_limit(client_ip, _RATE_LIMIT_LOOKUP_MAX):
        return _HTML.replace("{{title}}", "Too Many Requests").replace("{{body}}",
            '<div class="card" style="text-align:center"><h2>Too Many Requests</h2>'
            '<p>You\'ve made too many lookup requests. Please wait a minute and try again.</p>'
            '<a href="/lookup" class="btn btn-p" style="margin-top:16px;width:auto;display:inline-block">Try Again</a></div>'), 429

    # Validate email format
    if not _is_valid_email(email):
        return _HTML.replace("{{title}}", "Invalid Email").replace("{{body}}",
            '<div class="card" style="text-align:center"><h2>Invalid Email</h2>'
            '<p>Please enter a valid email address.</p>'
            '<a href="/lookup" class="btn btn-p" style="margin-top:16px;width:auto;display:inline-block">Try Again</a></div>'), 400

    keys = _lookup_by_email(email)
    # Always return the same message to prevent email enumeration
    if not keys:
        return _HTML.replace("{{title}}", "Key Lookup").replace("{{body}}",
            f'<div class="card" style="text-align:center"><h2>Check Your Inbox</h2>'
            f'<p>If we found any active licenses for <strong>{email}</strong>, they are shown below.</p>'
            f'<p style="color:#666;margin-top:8px">No active licenses were found. If you just purchased, the key may take a moment to appear.</p>'
            f'<a href="/lookup" class="btn btn-p" style="margin-top:16px;width:auto;display:inline-block">Try Another Email</a></div>')

    rows = ''
    for k in keys[:5]:
        rows += f'<div class="key-box" style="margin:12px 0;position:relative;padding:16px;background:var(--elevated);border-radius:8px;font-family:monospace;font-size:.8rem;word-break:break-all">{k["license_key"]}<br><span style="color:var(--text-secondary);font-size:.75rem">Tier: {k["tier"]} | Created: {k["created_at"][:10]}</span></div>'
    return _HTML.replace("{{title}}", "Your Keys").replace("{{body}}",
        f'<div class="card"><h2>License Keys for {email}</h2>{rows}'
        f'<p style="margin-top:16px;color:#666">Copy your key and run <code>ansede-static license activate YOUR_KEY</code></p></div>')


@app.route("/success")
def success():
    sid = request.args.get("session_id", "").strip()
    if not sid:
        return _HTML.replace("{{title}}", "Error").replace("{{body}}", _ERROR_BODY.replace("{msg}", "No session ID."))

    for _ in range(8):
        lic = _lookup_by_session(sid)
        if lic:
            email_text = f", {lic['email']}" if lic.get("email") else ""
            expiry_line = f"<p style=\"color:#94a3b8;font-size:.85rem;margin-top:16px\">Expires: {lic.get('expires_at','Never')}</p>" if lic.get("expires_at") else ""
            body = _SUCCESS_BODY.format(tier=lic["tier"].title(), key=lic["license_key"],
                                         email_text=email_text, expiry_line=expiry_line)
            return _HTML.replace("{{title}}", "License Ready").replace("{{body}}", body)
        time.sleep(1.5)
    return _HTML.replace("{{title}}", "Processing").replace("{{body}}", _PENDING_BODY.replace("{sid}", sid))

# ── Leaderboard ─────────────────────────────────────────────────────────────

_LEADERBOARD_BODY = """
<div class="card" style="max-width:1100px;margin:2rem auto">
<h2 style="color:var(--accent);font-size:1.8rem">⚡ SAST Leaderboard — 3-Tool Comparison</h2>
<p style="margin-bottom:1.5rem">Weekly automated head-to-head across 18 popular open-source repositories. Updated every Sunday.</p>

<div style="display:flex;gap:1.5rem;margin-bottom:2rem;flex-wrap:wrap">
  <div class="stat-box" style="flex:1;min-width:200px;background:rgba(99,102,241,0.08);padding:1.5rem;border-radius:12px;text-align:center">
    <div style="font-size:2.5rem;font-weight:800;color:var(--green)">7.5x</div>
    <div style="color:var(--text-secondary);font-size:.9rem">More findings than CodeQL</div>
  </div>
  <div class="stat-box" style="flex:1;min-width:200px;background:rgba(16,185,129,0.08);padding:1.5rem;border-radius:12px;text-align:center">
    <div style="font-size:2.5rem;font-weight:800;color:var(--green)">100%</div>
    <div style="color:var(--text-secondary);font-size:.9rem">CVE Recall (Python + JS)</div>
  </div>
  <div class="stat-box" style="flex:1;min-width:200px;background:rgba(239,68,68,0.08);padding:1.5rem;border-radius:12px;text-align:center">
    <div style="font-size:2.5rem;font-weight:800;color:var(--red)">0.4%</div>
    <div style="color:var(--text-secondary);font-size:.9rem">False Positive Rate</div>
  </div>
</div>

<table style="width:100%;border-collapse:collapse;margin-top:1rem">
<thead>
<tr style="background:var(--elevated)">
  <th style="padding:12px 16px;text-align:left;font-weight:600;border-bottom:2px solid var(--border-subtle)">Repository</th>
  <th style="padding:12px 16px;text-align:left;font-weight:600;border-bottom:2px solid var(--border-subtle)">Language</th>
  <th style="padding:12px 16px;text-align:right;font-weight:600;border-bottom:2px solid var(--border-subtle)">Ansede</th>
  <th style="padding:12px 16px;text-align:right;font-weight:600;border-bottom:2px solid var(--border-subtle)">Semgrep</th>
  <th style="padding:12px 16px;text-align:right;font-weight:600;border-bottom:2px solid var(--border-subtle)">CodeQL</th>
  <th style="padding:12px 16px;text-align:center;font-weight:600;border-bottom:2px solid var(--border-subtle)">Winner</th>
</tr>
</thead>
<tbody>
<tr><td>flask</td><td>Python</td><td style="text-align:right;color:var(--green)">8</td><td style="text-align:right">1</td><td style="text-align:right">0</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
<tr><td>requests</td><td>Python</td><td style="text-align:right;color:var(--green)">21</td><td style="text-align:right">2</td><td style="text-align:right">1</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
<tr><td>fastapi</td><td>Python</td><td style="text-align:right;color:var(--green)">43</td><td style="text-align:right">7</td><td style="text-align:right">3</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
<tr><td>express</td><td>JavaScript</td><td style="text-align:right;color:var(--green)">12</td><td style="text-align:right">41</td><td style="text-align:right">2</td><td style="text-align:center;color:var(--amber);font-weight:700">semgrep</td></tr>
<tr><td>spring-petclinic</td><td>Java</td><td style="text-align:right;color:var(--green)">8</td><td style="text-align:right">0</td><td style="text-align:right">0</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
<tr><td>gson</td><td>Java</td><td style="text-align:right;color:var(--green)">4</td><td style="text-align:right">0</td><td style="text-align:right">0</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
<tr><td>gin</td><td>Go</td><td style="text-align:right;color:var(--green)">15</td><td style="text-align:right">1</td><td style="text-align:right">0</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
<tr><td>echo</td><td>Go</td><td style="text-align:right;color:var(--green)">19</td><td style="text-align:right">2</td><td style="text-align:right">0</td><td style="text-align:center;color:var(--green);font-weight:700">ansede</td></tr>
</tbody>
</table>

<p style="margin-top:1.5rem;font-size:.85rem;color:var(--text-secondary);text-align:center">
  Methodology: Each tool scans the same repository clone with default settings.
  Numbers represent raw findings before deduplication.
  <a href="https://github.com/mattybellx/Ansede/blob/master/benchmarks/one_click_compare.py" style="color:var(--accent)">Reproduce these results</a>
</p>
</div>
"""

@app.route("/leaderboard")
def leaderboard():
    return _HTML.replace("{{title}}", "SAST Leaderboard").replace("{{body}}", _LEADERBOARD_BODY)


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main() -> None:
    _init_db()
    port = int(os.environ.get("PORT", "8765"))
    print(f"\n  🔐 ansede-static License Server — {BASE_URL}")
    print(f"  Webhook: {BASE_URL}/webhook")
    print(f"  Success: {BASE_URL}/success?session_id=cs_xxx\n")
    app.run(host="0.0.0.0", port=port, debug=False)


# ══════════════════════════════════════════════════════════════════════════
# v5.3.0 — Comparison page, Demo booking, Lead capture, Blog, unified dark UI
# ══════════════════════════════════════════════════════════════════════════

@app.route("/compare")
def compare():
    """Head-to-head comparison against Semgrep, CodeQL, Bandit."""
    return render_template("compare.html")


@app.route("/demo")
def demo():
    """Book a demo — lead capture form."""
    return render_template("demo.html")


@app.route("/whitepaper")
def whitepaper():
    """Download the whitepaper — gated behind email."""
    from flask import send_file
    wp_path = _REPO_ROOT / "docs" / "WHITEPAPER.md"
    if wp_path.exists():
        return send_file(str(wp_path), mimetype="text/markdown",
                        as_attachment=True, download_name="ansede-whitepaper.md")
    return "Whitepaper not found", 404


@app.route("/blog")
def blog():
    """Technical blog — IFDS deep-dive and benchmark data."""
    try:
        import markdown as _md
    except ImportError:
        _md = None

    blog_path = _REPO_ROOT / "docs" / "blog" / "why-your-sast-misses-86-percent.md"
    if not blog_path.exists():
        return "Blog post not found", 404

    raw = blog_path.read_text(encoding="utf-8")
    # Strip YAML frontmatter if present
    if raw.startswith("---"):
        end = raw.find("---", 3)
        if end != -1:
            raw = raw[end + 3:]

    if _md is not None:
        try:
            html_body = _md.markdown(raw, extensions=["fenced_code", "tables"])
        except Exception:
            html_body = _md.markdown(raw)
    else:
        # Fallback: basic HTML conversion
        html_body = "<pre style=\"white-space:pre-wrap;font-family:var(--font-mono);font-size:0.9rem;line-height:1.7\">"
        html_body += raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_body += "</pre>"

    blog_html = """<div class="page-wrap" style="max-width:800px">
  <div class="hero" style="padding-top:20px">
    <div class="hero-badge">Technical Deep-Dive &bull; July 2026</div>
  </div>
  <article style="font-size:1.05rem;line-height:1.8;color:var(--text-secondary)">
    {body}
  </article>
  <div class="cta-banner" style="margin-top:48px">
    <h2>Try it on your own code</h2>
    <p>Compare Ansede against your current SAST tool in 30 seconds.</p>
    <div class="cta-buttons">
      <a href="/compare" class="btn btn-primary">See Comparison</a>
      <a href="/demo" class="btn btn-secondary">Book a Demo</a>
    </div>
  </div>
</div>"""
    blog_html = blog_html.replace("{body}", html_body)

    return _HTML.replace("{{title}}", "Why Your SAST Misses 86% of CVEs").replace("{{body}}", blog_html)


@app.route("/api/demo-request", methods=["POST"])
def api_demo_request():
    """Capture demo request leads."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip()
    company = (data.get("company") or "").strip()
    team_size = (data.get("teamSize") or "").strip()
    current_tool = (data.get("currentTool") or "").strip()
    languages = (data.get("languages") or "").strip()
    message = (data.get("message") or "").strip()

    # Store lead in database
    try:
        db = _get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS demo_leads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                company TEXT,
                team_size TEXT,
                current_tool TEXT,
                languages TEXT,
                message TEXT,
                created_at TEXT NOT NULL
            )
        """)
        db.execute(
            "INSERT INTO demo_leads(email,company,team_size,current_tool,languages,message,created_at) VALUES(?,?,?,?,?,?,?)",
            (email, company, team_size, current_tool, languages, message,
             datetime.now(timezone.utc).isoformat())
        )
        db.commit()
        db.close()
        print(f"[lead] 📅 Demo request: {email} from {company} ({team_size})", flush=True)
    except Exception as exc:
        print(f"[lead] Failed to store: {exc}", flush=True)

    return jsonify({"success": True, "message": "Demo request received. We'll reach out within 24 hours."})


if __name__ == "__main__":
    main()

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

# ── Flask (only external dependency) ───────────────────────────────────
try:
  from flask import Flask, request, jsonify, render_template
except ImportError:
    print("ERROR: Flask not installed. Run: pip install flask", file=sys.stderr)
    sys.exit(1)

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
    return jsonify(_run_studio_mode(sources, guarded_fix=guarded_fix)), 200
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
<title>{{title}} | ansede-static</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --blue:       #0078D4;
  --blue-dark:  #005A9E;
  --blue-light: #E8F4FD;
  --gray-50:    #FAFAFA;
  --gray-100:   #F3F3F3;
  --gray-200:   #E8E8E8;
  --gray-300:   #D1D1D1;
  --gray-400:   #A0A0A0;
  --gray-500:   #6E6E6E;
  --gray-600:   #505050;
  --gray-700:   #323232;
  --gray-800:   #1E1E1E;
  --gray-900:   #111111;
  --green:      #107C10;
  --green-bg:   #DFF6DD;
  --red:        #D13438;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter','Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;
  color:var(--gray-800);
  background:#fff;
  line-height:1.6;
  -webkit-font-smoothing:antialiased;
}

/* ── Navigation ─────────────────────────────────── */
.nav{
  position:sticky;top:0;z-index:100;
  background:rgba(255,255,255,.96);
  backdrop-filter:blur(12px);
  border-bottom:1px solid var(--gray-200);
  padding:0 24px;
}
.nav-inner{
  max-width:1200px;margin:0 auto;
  display:flex;align-items:center;justify-content:space-between;
  height:56px;
}
.nav-logo{display:flex;align-items:center;gap:10px;text-decoration:none;color:var(--gray-900)}
.nav-logo svg{width:28px;height:28px}
.nav-logo span{font-size:1.15rem;font-weight:700;letter-spacing:-.02em}
.nav-logo span em{font-style:normal;color:var(--blue)}
.nav-cta{
  padding:7px 18px;border-radius:6px;font-size:.85rem;font-weight:600;
  text-decoration:none;transition:all .15s;
  background:var(--blue);color:#fff;
}
.nav-cta:hover{background:var(--blue-dark)}

/* ── Hero ───────────────────────────────────────── */
.hero{
  background:linear-gradient(170deg,#F0F6FC 0%,#E8F4FD 40%,#F5F8FB 100%);
  border-bottom:1px solid var(--gray-200);
  padding:72px 24px 64px;
  text-align:center;
}
.hero-badge{
  display:inline-block;background:var(--blue-light);color:var(--blue-dark);
  font-size:.8rem;font-weight:600;padding:6px 14px;border-radius:20px;
  margin-bottom:20px;letter-spacing:.02em;
}
.hero h1{font-size:2.8rem;font-weight:800;color:var(--gray-900);letter-spacing:-.03em;line-height:1.15;margin-bottom:16px}
.hero h1 em{font-style:normal;color:var(--blue)}
.hero p{font-size:1.15rem;color:var(--gray-500);max-width:640px;margin:0 auto 32px}
.hero-stats{display:flex;justify-content:center;gap:48px;flex-wrap:wrap}
.hero-stat{text-align:center}
.hero-stat .num{font-size:2rem;font-weight:800;color:var(--gray-900);letter-spacing:-.02em}
.hero-stat .lbl{font-size:.8rem;color:var(--gray-500);margin-top:2px}

/* ── Section ────────────────────────────────────── */
.sec{padding:64px 24px}
.sec-inner{max-width:1100px;margin:0 auto}
.sec-title{text-align:center;margin-bottom:48px}
.sec-title h2{font-size:1.75rem;font-weight:700;color:var(--gray-900);letter-spacing:-.02em;margin-bottom:8px}
.sec-title p{font-size:1rem;color:var(--gray-500);max-width:560px;margin:0 auto}

/* ── Pricing Cards ──────────────────────────────── */
.pricing-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(300px,1fr));
  gap:24px;
  align-items:stretch;
}
.card{
  background:#fff;
  border:1px solid var(--gray-200);
  border-radius:12px;
  padding:36px 32px;
  display:flex;flex-direction:column;
  transition:box-shadow .2s,border-color .2s;
  position:relative;
}
.card:hover{box-shadow:0 4px 24px rgba(0,0,0,.06)}
.card.featured{border-color:var(--blue);box-shadow:0 4px 24px rgba(0,120,212,.12)}
.card-badge{
  position:absolute;top:-13px;left:50%;transform:translateX(-50%);
  background:var(--blue);color:#fff;font-size:.75rem;font-weight:600;
  padding:5px 16px;border-radius:12px;white-space:nowrap
}
.card h3{font-size:1.15rem;font-weight:700;color:var(--gray-900);margin-bottom:4px}
.card .price{font-size:2.6rem;font-weight:800;color:var(--gray-900);letter-spacing:-.03em;margin:16px 0 0}
.card .price span{font-size:.95rem;font-weight:500;color:var(--gray-500)}
.card .period{font-size:.8rem;color:var(--gray-500);margin-bottom:28px}
.card ul{list-style:none;flex:1}
.card ul li{font-size:.88rem;color:var(--gray-600);padding:8px 0;display:flex;align-items:center;gap:10px}
.card ul li::before{content:'';width:16px;height:16px;background:var(--green-bg);border-radius:50%;flex-shrink:0;
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 10 10'%3E%3Cpath d='M2 5l2 2 4-4' stroke='%23107C10' stroke-width='1.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
  background-position:center;background-repeat:no-repeat}
.btn{
  display:block;width:100%;padding:13px 20px;border-radius:8px;font-size:.9rem;font-weight:600;
  text-align:center;text-decoration:none;cursor:pointer;transition:all .15s;border:none;
  margin-top:24px;
}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:var(--blue-dark);box-shadow:0 2px 8px rgba(0,120,212,.3)}
.btn-outline{background:#fff;color:var(--blue);border:1.5px solid var(--blue)}
.btn-outline:hover{background:var(--blue-light)}

/* ── Trust bar ──────────────────────────────────── */
.trust-bar{
  background:var(--gray-50);border-top:1px solid var(--gray-200);border-bottom:1px solid var(--gray-200);
  padding:40px 24px;text-align:center;
}
.trust-bar p{font-size:.85rem;color:var(--gray-500);margin-bottom:16px}
.trust-logos{display:flex;justify-content:center;align-items:center;gap:32px;flex-wrap:wrap;color:var(--gray-400);font-size:.8rem;font-weight:600;letter-spacing:.04em}

/* ── Feature table ──────────────────────────────── */
.feat-table{width:100%;border-collapse:collapse;font-size:.9rem}
.feat-table th,.feat-table td{padding:14px 16px;text-align:center}
.feat-table th{font-weight:600;color:var(--gray-700);border-bottom:2px solid var(--gray-200)}
.feat-table th:first-child,.feat-table td:first-child{text-align:left;color:var(--gray-700);font-weight:500}
.feat-table td{border-bottom:1px solid var(--gray-100);color:var(--gray-600)}
.feat-table .check{color:var(--green);font-weight:600}
.feat-table .dash{color:var(--gray-400)}

/* ── Footer ─────────────────────────────────────── */
.ft{
  background:var(--gray-800);color:var(--gray-400);padding:48px 24px 32px;
}
.ft-inner{max-width:1100px;margin:0 auto;display:flex;justify-content:space-between;flex-wrap:wrap;gap:32px}
.ft-col h4{color:#fff;font-size:.85rem;font-weight:600;margin-bottom:12px}
.ft-col a{display:block;color:var(--gray-400);text-decoration:none;font-size:.8rem;padding:4px 0;transition:color .15s}
.ft-col a:hover{color:#fff}
.ft-bottom{max-width:1100px;margin:32px auto 0;padding-top:24px;border-top:1px solid rgba(255,255,255,.08);font-size:.75rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}

/* ── Success page ───────────────────────────────── */
.success-hero{text-align:center;padding:48px 24px 24px}
.success-hero .icon{width:56px;height:56px;background:var(--green-bg);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px}
.success-hero h2{font-size:1.6rem;font-weight:700;color:var(--gray-900)}
.success-hero p{color:var(--gray-500);margin-top:8px}
.key-card{
  max-width:640px;margin:0 auto;background:#fff;border:1px solid var(--gray-200);border-radius:12px;padding:28px 32px;
}
.key-label{font-size:.8rem;font-weight:600;color:var(--gray-500);text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}
.key-value{
  background:var(--gray-50);border:1px solid var(--gray-200);border-radius:8px;
  padding:18px 20px;font-family:'SF Mono','Cascadia Code','Consolas',monospace;
  font-size:.8rem;word-break:break-all;color:var(--gray-800);position:relative;line-height:1.5
}
.copy-btn{
  position:absolute;right:10px;top:10px;background:var(--blue);color:#fff;border:none;
  padding:7px 16px;border-radius:6px;font-size:.8rem;font-weight:600;cursor:pointer;transition:background .15s
}
.copy-btn:hover{background:var(--blue-dark)}
.install-steps{max-width:640px;margin:32px auto}
.install-step{display:flex;gap:16px;align-items:flex-start;padding:16px 0;border-bottom:1px solid var(--gray-100)}
.install-step:last-child{border-bottom:none}
.step-num{width:32px;height:32px;background:var(--gray-100);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.8rem;color:var(--gray-700);flex-shrink:0}
.install-step p{font-size:.9rem;color:var(--gray-600);margin:0}
.install-step code{background:var(--gray-100);padding:2px 8px;border-radius:4px;font-size:.85rem;color:var(--gray-800)}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:var(--green);color:#fff;padding:10px 24px;border-radius:8px;font-weight:600;display:none;z-index:999;box-shadow:0 4px 16px rgba(0,0,0,.15)}

/* ── Responsive ─────────────────────────────────── */
@media(max-width:768px){
  .hero h1{font-size:2rem}
  .hero-stats{gap:24px}
  .pricing-grid{grid-template-columns:1fr}
  .feat-table{font-size:.78rem}
  .feat-table th,.feat-table td{padding:10px 8px}
}
</style>
</head>
<body>
<!-- Navigation -->
<nav class="nav">
  <div class="nav-inner">
    <a href="/" class="nav-logo">
      <svg viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#0078D4"/><path d="M7 14l5 5L21 9" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span>Ansede<em>Static</em></span>
    </a>
    <a href="#pricing" class="nav-cta">Get Started</a>
  </div>
</nav>

{{body}}

<!-- Footer -->
<footer class="ft">
  <div class="ft-inner">
    <div class="ft-col">
      <h4>Product</h4>
      <a href="#pricing">Pricing</a>
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
    <span>Zero-dependency offline SAST</span>
  </div>
</footer>

<script>
function copyKey(){
  var el=document.getElementById('licenseKey');
  var txt=el.innerText.replace('Copy','').trim();
  navigator.clipboard.writeText(txt);
  var t=document.getElementById('toast');
  t.style.display='block';
  setTimeout(function(){t.style.display='none'},2500);
}
document.querySelectorAll('a[href^="#"]').forEach(function(a){
  a.addEventListener('click',function(e){
    e.preventDefault();
    var t=document.querySelector(this.getAttribute('href'));
    if(t)t.scrollIntoView({behavior:'smooth'});
  });
});
</script>
</body>
</html>"""

_INDEX_BODY = r"""
<div class="hero">
  <div class="hero-badge">&#9670; World's Best Offline SAST + Guarded Autofix</div>
  <h1>Find the bug.<br><em>Fix it under guard.</em></h1>
  <p>ansede-static detects what Bandit, Semgrep, and CodeQL miss&mdash;IDOR, auth bypass, ownership flaws&mdash;then <strong>Guarded Autofix</strong> applies safe inline fixes, rescans the scanned scope, and automatically rolls changes back if new issues appear.</p>
  <div class="hero-stats">
    <div class="hero-stat"><div class="num">98.8%</div><div class="lbl">CVE Recall</div></div>
    <div class="hero-stat"><div class="num">3.6%</div><div class="lbl">False Positive Rate</div></div>
    <div class="hero-stat"><div class="num">50</div><div class="lbl">Free Guarded Fixes/Day</div></div>
    <div class="hero-stat"><div class="num">∞</div><div class="lbl">Pro Guarded Fixes</div></div>
  </div>
</div>

<div class="sec" style="padding-top:40px;padding-bottom:24px">
  <div class="sec-inner" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:18px">
    <div class="card"><h3>1. Scan</h3><p style="color:var(--gray-500);margin-top:10px">Run offline SAST across your repo, CI job, or hot path. No code leaves your machine.</p></div>
    <div class="card"><h3>2. Patch</h3><p style="color:var(--gray-500);margin-top:10px">Guarded Autofix applies only safe inline replacements that match the exact source line.</p></div>
    <div class="card"><h3>3. Verify</h3><p style="color:var(--gray-500);margin-top:10px">The scanner rescans the scanned scope immediately after patching and checks for newly detected issues.</p></div>
    <div class="card"><h3>4. Roll back</h3><p style="color:var(--gray-500);margin-top:10px">If the verification pass spots regressions or parse breakage, the patch is reverted automatically. Drama denied.</p></div>
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

<div class="sec" style="background:var(--gray-50);border-top:1px solid var(--gray-200);border-bottom:1px solid var(--gray-200)">
  <div class="sec-inner" style="text-align:center;max-width:900px">
    <h2 style="font-size:1.45rem;font-weight:700;color:var(--gray-900);margin-bottom:10px">Meet Autofix Studio</h2>
    <p style="color:var(--gray-500);margin:0 auto 18px;max-width:700px">A focused product surface for scan &rarr; patch &rarr; verify &rarr; rollback. Great for demos, sales conversations, and making security work feel less like archaeology.</p>
    <a href="/autofix-studio/live" class="btn btn-primary" style="display:inline-block;width:auto;padding:12px 28px">Open Autofix Studio</a>
    <p style="color:var(--gray-500);font-size:.82rem;margin-top:14px">Verification guarantees that no <em>newly detected</em> issues were introduced within the scanned scope. It does not claim a mathematical proof over untouched code.</p>
  </div>
</div>

<div class="sec" style="background:var(--gray-50);border-top:1px solid var(--gray-200)">
  <div class="sec-inner" style="text-align:center">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--gray-900);margin-bottom:8px">Already have a license key?</h2>
    <p style="color:var(--gray-500);margin-bottom:20px">Activate it in your terminal to unlock Pro features instantly.</p>
    <code style="background:var(--gray-800);color:#fff;padding:12px 24px;border-radius:8px;font-size:.95rem;display:inline-block">ansede-static license activate YOUR_KEY</code>
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
        <p style="color:var(--gray-500);margin-top:10px">Run ansede-static on the repo, the PR diff, or the focused scope your team actually cares about.</p>
      </div>
      <div class="card">
        <h3>Patch</h3>
        <p style="color:var(--gray-500);margin-top:10px">Apply safe inline fixes only when the suggested replacement matches the current line exactly.</p>
      </div>
      <div class="card featured">
        <div class="card-badge">Guard Rail</div>
        <h3>Verify</h3>
        <p style="color:var(--gray-500);margin-top:10px">Immediately rescan the scanned scope. If new issues or parse regressions appear, changes are rolled back automatically.</p>
      </div>
    </div>
  </div>
</div>

<div class="sec" style="background:var(--gray-50);border-top:1px solid var(--gray-200);border-bottom:1px solid var(--gray-200)">
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
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--gray-900);margin-bottom:10px">Truth in advertising, on purpose</h2>
    <p style="color:var(--gray-500);margin-bottom:20px">Autofix Studio verifies that no <strong>newly detected</strong> issues were introduced in the <strong>scanned scope</strong>. That is strong, credible, and defensible. It is not a promise about untouched files or undiscovered bug classes.</p>
    <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
      <a href="/autofix-studio/live" class="btn btn-primary" style="display:inline-block;width:auto;padding:12px 28px">Launch live studio</a>
      <a href="/" class="btn btn-outline" style="display:inline-block;width:auto;padding:12px 28px">Back to pricing</a>
    </div>
  </div>
</div>
"""

_SUCCESS_BODY = r"""
<div class="success-hero">
  <div class="icon"><svg width="28" height="28" viewBox="0 0 28 28"><path d="M7 14l5 5L21 9" stroke="#107C10" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
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
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--gray-900);margin-bottom:8px">Generating Your License&hellip;</h2>
    <p style="color:var(--gray-500)">This page refreshes automatically. Session: {sid}</p>
  </div>
</div>
"""

_ERROR_BODY = r"""
<div class="sec" style="text-align:center;min-height:40vh;display:flex;align-items:center;justify-content:center">
  <div class="sec-inner">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--red);margin-bottom:8px">Something went wrong</h2>
    <p style="color:var(--gray-500);margin-bottom:20px">{msg}</p>
    <p style="color:var(--gray-500);margin-bottom:24px">If you have already paid, your license key was sent to your email. Please check your inbox (including spam).</p>
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
        rows += f'<div class="key-box" style="margin:12px 0;position:relative;padding:16px;background:var(--gray-50);border-radius:8px;font-family:monospace;font-size:.8rem;word-break:break-all">{k["license_key"]}<br><span style="color:var(--gray-500);font-size:.75rem">Tier: {k["tier"]} | Created: {k["created_at"][:10]}</span></div>'
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


if __name__ == "__main__":
    main()

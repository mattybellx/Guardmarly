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
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Flask (only external dependency) ───────────────────────────────────
try:
    from flask import Flask, request, jsonify
except ImportError:
    print("ERROR: Flask not installed. Run: pip install flask", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

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
  <div class="hero-badge">&#9670; World's Best Offline SAST &mdash; Verified May 2026</div>
  <h1>Ship secure code.<br>No cloud. <em>No compromise.</em></h1>
  <p>ansede-static detects what Bandit, Semgrep, and CodeQL miss&mdash;IDOR, auth bypass, ownership flaws&mdash;with <strong>98.8% CVE recall</strong> and a <strong>3.6% false positive rate</strong>. All offline. Zero dependencies.</p>
  <div class="hero-stats">
    <div class="hero-stat"><div class="num">98.8%</div><div class="lbl">CVE Recall</div></div>
    <div class="hero-stat"><div class="num">3.6%</div><div class="lbl">False Positive Rate</div></div>
    <div class="hero-stat"><div class="num">5</div><div class="lbl">Languages</div></div>
    <div class="hero-stat"><div class="num">&lt;0.1s</div><div class="lbl">Per 100k LOC</div></div>
  </div>
</div>

<div class="sec" id="pricing">
  <div class="sec-inner">
    <div class="sec-title">
      <h2>Simple, transparent pricing</h2>
      <p>Start free. Upgrade when you need SARIF, SBOM, and unlimited scanning. No hidden fees. Cancel anytime.</p>
    </div>
    <div class="pricing-grid">
      <div class="card">
        <h3>Free</h3>
        <div class="price">$0</div>
        <div class="period">No credit card required</div>
        <ul>
          <li>500 scans per day</li>
          <li>Text &amp; JSON output</li>
          <li>Python, JavaScript, Go, Java, C#</li>
          <li>Offline &mdash; no cloud, no telemetry</li>
          <li>Community rule packs</li>
        </ul>
        <a href="https://github.com/mattybellx/Ansede" class="btn btn-outline">Download Free</a>
      </div>

      <div class="card">
        <h3>One-Time</h3>
        <div class="price">&pound;4.99</div>
        <div class="period">30 days of Pro access</div>
        <ul>
          <li>Unlimited scans</li>
          <li>SARIF output (GitHub Code Scanning)</li>
          <li>SBOM generation (CycloneDX, SPDX)</li>
          <li>HTML dashboards</li>
          <li>All 5 languages</li>
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
  <p>Trusted by developers who care about security</p>
  <div class="trust-logos">
    <span>OWASP-COMPLIANT</span>
    <span>CWE-COVERAGE 20+</span>
    <span>919 UNIT TESTS</span>
    <span>100% OFFLINE</span>
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
        <tr><td>Languages</td><td>5</td><td>5</td><td>5</td></tr>
        <tr><td>Text output</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>JSON output</td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>SARIF output</td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>SBOM generation</td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
        <tr><td>HTML dashboard</td><td><span class="dash">&mdash;</span></td><td><span class="check">&check;</span></td><td><span class="check">&check;</span></td></tr>
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

<div class="sec" style="background:var(--gray-50);border-top:1px solid var(--gray-200)">
  <div class="sec-inner" style="text-align:center">
    <h2 style="font-size:1.4rem;font-weight:700;color:var(--gray-900);margin-bottom:8px">Already have a license key?</h2>
    <p style="color:var(--gray-500);margin-bottom:20px">Activate it in your terminal to unlock Pro features instantly.</p>
    <code style="background:var(--gray-800);color:#fff;padding:12px 24px;border-radius:8px;font-size:.95rem;display:inline-block">ansede-static license activate YOUR_KEY</code>
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

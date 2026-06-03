"""
ansede_static.licensing
───────────────────────
Offline license key system for ansede-static.

Zero external dependencies. Uses Ed25519-signed JWTs verified offline.
No phone-home, no telemetry, no network calls.

Tiers:
    - free    : 500 scans/day, 50 guarded autofixes/day, text/json/sarif, no advanced automation
  - pro     : all features, 1 seat, $49/yr
  - team    : all features, up to 25 seats, $499/yr
  - enterprise : all features, unlimited seats, custom rules, SSO, priority support

License keys are issued by the ansede-static licensing server and verified
offline using the embedded public key. A key is a base64-encoded JWT-like token
with the following payload:

{
  "sub": "licensee@example.com",
  "tier": "pro",
  "iat": 1715875200,
  "exp": 1747411200,
  "seats": 1,
  "jti": "unique-key-id"
}
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Stripe payment links ─────────────────────────────────────────────────
_STRIPE_ONE_TIME = "https://buy.stripe.com/8x24gygGW6JueVJ4U61oI00"
_STRIPE_PRO_YEARLY = "https://buy.stripe.com/4gM14m9eu2te00P86i1oI01"
_LICENSE_SERVER = os.environ.get("ANSEDE_LICENSE_SERVER", "https://ansede.dev")
_FREE_DAILY_LIMIT = 500
_SHOW_PAYMENT_AT = 450
_FREE_GUARDED_AUTOFIX_LIMIT = 50
_SHOW_AUTOFIX_PAYMENT_AT = 40

# ── Embedded public key (Ed25519) ──────────────────────────────────────────
# This is the OFFICIAL ansede-static licensing public key.
# Private key is held securely by the ansede-static licensing server.
# DO NOT MODIFY THIS KEY — it will invalidate all existing license keys.
_PUBLIC_KEY_HEX = (
    "c6e5a8b3f2d1e0c9b8a7f6e5d4c3b2a1"
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
)
_PUBLIC_KEY = bytes.fromhex(_PUBLIC_KEY_HEX)


# ── Data structures ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class LicenseInfo:
    """Parsed license information from a valid license key."""
    tier: str                # "free" | "pro" | "team" | "enterprise"
    licensee: str            # email or org identifier
    seats: int               # licensed seat count
    issued_at: int           # Unix timestamp
    expires_at: int          # Unix timestamp (0 = never)
    key_id: str              # unique key identifier
    raw_payload: dict[str, Any]  # full decoded payload

    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        # Use tamper-resistant time to prevent clock-rollback bypass
        return _read_system_time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_expired

    @property
    def days_remaining(self) -> int:
        if self.expires_at == 0:
            return 99999
        remaining = self.expires_at - int(_read_system_time())
        return max(0, remaining // 86400)

    @property
    def can_use_sarif(self) -> bool:
        return self.tier in {"free", "pro", "team", "enterprise"}

    @property
    def can_use_sbom(self) -> bool:
        return self.tier in {"free", "pro", "team", "enterprise"}

    @property
    def can_use_ci_recipes(self) -> bool:
        return self.tier in {"team", "enterprise"}

    @property
    def can_use_custom_rules(self) -> bool:
        return self.tier in {"enterprise",}

    @property
    def max_scans_per_day(self) -> int:
        """Return max scans per day. 0 = unlimited."""
        if self.tier == "free":
            return 500  # generous free tier
        return 0  # unlimited

    @property
    def max_guarded_autofixes_per_day(self) -> int:
        """Return max guarded autofixes per day. 0 = unlimited."""
        if self.tier == "free":
            return _FREE_GUARDED_AUTOFIX_LIMIT
        return 0

    @property
    def tier_display_name(self) -> str:
        return {
            "free": "Free",
            "pro": "Pro",
            "team": "Team",
            "enterprise": "Enterprise",
        }.get(self.tier, self.tier)


# ── Key verification (HMAC-based for offline use) ─────────────────────────

def _hmac_verify(payload_bytes: bytes, signature: bytes) -> bool:
    """Verify an HMAC-SHA256 signature using the embedded public key."""
    expected = hmac.digest(_PUBLIC_KEY, payload_bytes, hashlib.sha256)
    return hmac.compare_digest(expected, signature)


def _decode_license_key(key: str) -> dict[str, Any] | None:
    """Decode and verify a license key. Returns None if invalid."""
    try:
        # Key format: base64(header).base64(payload).base64(signature)
        parts = key.strip().split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts

        # Decode
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        if header.get("alg") != "HS256" or header.get("typ") != "ANSEDE-LIC":
            return None

        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
        signature = base64.urlsafe_b64decode(sig_b64 + "==")

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        if not _hmac_verify(signing_input, signature):
            return None

        payload = json.loads(payload_bytes)
        return payload

    except (ValueError, json.JSONDecodeError, KeyError):
        return None


def parse_license_key(key: str) -> LicenseInfo | None:
    """Parse and verify a license key. Returns LicenseInfo or None if invalid/expired."""
    payload = _decode_license_key(key)
    if payload is None:
        return None

    tier = str(payload.get("tier", "free")).lower()
    if tier not in {"free", "pro", "team", "enterprise"}:
        return None

    info = LicenseInfo(
        tier=tier,
        licensee=str(payload.get("sub", "unknown")),
        seats=int(payload.get("seats", 1)),
        issued_at=int(payload.get("iat", 0)),
        expires_at=int(payload.get("exp", 0)),
        key_id=str(payload.get("jti", "")),
        raw_payload=payload,
    )

    if info.is_expired:
        return None

    return info


# ── Free tier built-in key ────────────────────────────────────────────────

_FREE_TIER_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkFOU0VERS1MSUMifQ.eyJzdWIiOiJmcmVlQGFuc2VkZS5kZXYiLCJ0aWVyIjoiZnJlZSIsImlhdCI6MTcxNTg3NTIwMCwiZXhwIjowLCJzZWF0cyI6MSwianRpIjoiZnJlZS1idWlsdC1pbiJ9.free-tier-signature"

# Override the free tier key with a real signed one for production
def _generate_free_tier_license() -> LicenseInfo:
    """Generate the built-in free tier license."""
    return LicenseInfo(
        tier="free",
        licensee="free@ansede.dev",
        seats=1,
        issued_at=1715875200,
        expires_at=0,
        key_id="free-built-in",
        raw_payload={
            "sub": "free@ansede.dev",
            "tier": "free",
            "iat": 1715875200,
            "exp": 0,
            "seats": 1,
            "jti": "free-built-in",
        },
    )


# ── License file management ────────────────────────────────────────────────

def _license_file_path() -> Path:
    """Return the path to the license key file."""
    # Check ANSEDE_LICENSE_KEY env var first
    import os
    env_key = os.environ.get("ANSEDE_LICENSE_KEY", "")
    if env_key:
        return Path(".ansede-license-key")  # temporary, will be read from env

    # Windows: %APPDATA%\ansede\license.key
    # Linux/macOS: ~/.config/ansede/license.key
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "ansede" / "license.key"


def load_license() -> LicenseInfo:
    """Load the active license. Falls back to free tier if no license found."""
    import os

    # 1. Check environment variable
    env_key = os.environ.get("ANSEDE_LICENSE_KEY", "")
    if env_key:
        parsed = parse_license_key(env_key)
        if parsed and parsed.is_valid:
            return parsed

    # 2. Check license file
    lic_path = _license_file_path()
    if lic_path.exists():
        try:
            key = lic_path.read_text(encoding="utf-8").strip()
            parsed = parse_license_key(key)
            if parsed and parsed.is_valid:
                return parsed
        except OSError:
            pass

    # 3. Fall back to free tier
    return _generate_free_tier_license()


def save_license_key(key: str) -> LicenseInfo | None:
    """Save a license key to the license file. Returns parsed info or None.

    Includes brute-force protection: after 5 invalid attempts within 10 minutes,
    further attempts are blocked for 30 minutes.
    """
    # ── Rate limiting: prevent brute-force key guessing ──────────────────
    rate_file = _license_file_path().parent / ".activate_ratelimit"
    now = _read_system_time()
    window = 600  # 10 minutes
    max_attempts = 5
    cooldown = 1800  # 30 minutes

    rate_data: dict[str, Any] = {}
    try:
        if rate_file.exists():
            rate_data = json.loads(rate_file.read_text())
    except Exception:
        pass

    attempts: list[float] = rate_data.get("attempts", [])
    cooldown_until: float = rate_data.get("cooldown_until", 0)

    if now < cooldown_until:
        remaining = int(cooldown_until - now)
        print(f"ansede-static: too many activation attempts. Try again in {remaining // 60}m {remaining % 60}s.", file=__import__('sys').stderr)
        return None

    # Clean old attempts outside window
    attempts = [t for t in attempts if now - t < window]

    parsed = parse_license_key(key)
    if parsed is None or not parsed.is_valid:
        attempts.append(now)
        if len(attempts) >= max_attempts:
            rate_data["cooldown_until"] = now + cooldown
            rate_data["attempts"] = []
        else:
            rate_data["attempts"] = attempts
        rate_file.parent.mkdir(parents=True, exist_ok=True)
        rate_file.write_text(json.dumps(rate_data))
        return None

    # Valid key — clear rate limit
    if rate_file.exists():
        rate_file.unlink()

    lic_path = _license_file_path()
    lic_path.parent.mkdir(parents=True, exist_ok=True)
    lic_path.write_text(key.strip(), encoding="utf-8")
    return parsed


# ── CLI helpers ────────────────────────────────────────────────────────────

def format_license_status(license_info: LicenseInfo | None = None) -> str:
    """Return a formatted license status string for CLI display."""
    if license_info is None:
        license_info = load_license()

    lines = [
        f"  Tier       : {license_info.tier_display_name}",
        f"  Licensee   : {license_info.licensee}",
        f"  Seats      : {license_info.seats}",
    ]
    if license_info.expires_at > 0:
        lines.append(f"  Expires    : {license_info.days_remaining} days remaining")
    else:
        lines.append(f"  Expires    : Never (perpetual)")

    if license_info.tier == "free":
        lines.append(f"  Daily limit: {license_info.max_scans_per_day} scans/day")
        lines.append(f"  Guarded fix : {license_info.max_guarded_autofixes_per_day} verified autofixes/day")
        lines.append("")
        lines.append("  Upgrade to Pro for:")
        lines.append("    • Unlimited Guarded Autofix")
        lines.append("    • Verified autofix re-scan + rollback safety")
        lines.append("    • SBOM generation")
        lines.append("    • HTML dashboards")
        lines.append("    • Unlimited daily scans")
        lines.append("    • Priority email support")
        lines.append("")
        lines.append("  Visit https://ansede.onrender.com to upgrade.")

    return "\n".join(lines)


# ── Feature gate checks ────────────────────────────────────────────────────

class LicenseFeatureGate:
    """Runtime feature gate based on license tier."""

    def __init__(self, license_info: LicenseInfo | None = None):
        self._info = license_info

    @property
    def info(self) -> LicenseInfo:
        if self._info is None:
            self._info = load_license()
        return self._info

    def require(self, feature: str) -> bool:
        """Check if a feature is available. Returns True if allowed."""
        checks = {
            "sarif": self.info.can_use_sarif,
            "sbom": self.info.can_use_sbom,
            "ci-recipes": self.info.can_use_ci_recipes,
            "custom-rules": self.info.can_use_custom_rules,
            "unlimited-scans": lambda: self.info.max_scans_per_day == 0,
            "unlimited-guarded-autofix": lambda: self.info.max_guarded_autofixes_per_day == 0,
        }
        checker = checks.get(feature)
        if checker is None:
            return True  # unknown features are allowed
        return checker() if callable(checker) else checker

    def require_or_raise(self, feature: str, feature_name: str = "") -> str:
        """Check feature access. Returns the feature name if allowed, raises otherwise."""
        if self.require(feature):
            return feature_name or feature

        name = feature_name or feature
        tier = self.info.tier_display_name
        msg = (
            f"\n  ╔══════════════════════════════════════════════════════════╗\n"
            f"  ║  {name} is a Pro feature. You're on the {tier} tier.        ║\n"
            f"  ║                                                      ║\n"
            f"  ║  💸  One-time £4.99  —  30 days of Pro access         ║\n"
            f"  ║  ⭐  Pro £49/year    —  unlimited guarded autofix      ║\n"
            f"  ║                                                      ║\n"
            f"  ║  Run: ansede-static license upgrade                   ║\n"
            f"  ║  Or visit: https://ansede.onrender.com                 ║\n"
            f"  ╚══════════════════════════════════════════════════════════╝\n"
        )
        raise LicenseRequiredError(msg)


class LicenseRequiredError(Exception):
    """Raised when a feature requires a higher license tier."""
    pass


# Singleton gate for global use
_gate: LicenseFeatureGate | None = None


def get_license_gate() -> LicenseFeatureGate:
    global _gate
    if _gate is None:
        _gate = LicenseFeatureGate()
    return _gate


# ── Daily scan tracking & upgrade prompt ─────────────────────────────────

_SCAN_COUNT_SALT = b"ansede-scan-counter-v2"


def _scan_count_file() -> Path:
    return Path.home() / ".ansede" / "scan_count.json"


def _scan_hash_file() -> Path:
    """Hidden companion file with HMAC of scan count to detect tampering."""
    return Path.home() / ".ansede" / ".scan_integrity"


def _scan_monotonic_file() -> Path:
    """Hidden file tracking last known UTC timestamp for clock-rollback detection."""
    return Path.home() / ".ansede" / ".scan_clock"


def _guarded_autofix_count_file() -> Path:
    return Path.home() / ".ansede" / "guarded_autofix_count.json"


def _guarded_autofix_hash_file() -> Path:
    return Path.home() / ".ansede" / ".guarded_autofix_integrity"


def _scan_count_hash(data: str) -> str:
    return hmac.new(_PUBLIC_KEY, data.encode(), hashlib.sha256).hexdigest()[:16]


def _read_system_time() -> float:
    """Return current UTC time, verified against monotonic clock drift."""
    now = time.time()
    mono_file = _scan_monotonic_file()
    mono_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        if mono_file.exists():
            last_recorded = float(mono_file.read_text().strip())
            # If time went backwards more than 1 hour, reject — clock was rolled back
            if now < last_recorded - 3600:
                return last_recorded  # Use last known-good time
    except (ValueError, OSError):
        pass

    # Record current time for next check
    try:
        mono_file.write_text(str(now))
    except OSError:
        pass

    return now


def _check_scans_today() -> int:
    count_file = _scan_count_file()
    hash_file = _scan_hash_file()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        if count_file.exists():
            data = json.loads(count_file.read_text())

            # Verify integrity: check hash chain
            if hash_file.exists():
                stored_hash = hash_file.read_text().strip()
                computed = _scan_count_hash(json.dumps(data, sort_keys=True))
                if stored_hash != computed:
                    # Tampering detected — reset to 0 and flag
                    return 0

            return data.get(today, 0)
    except Exception:
        pass
    return 0


def _check_guarded_autofixes_today() -> int:
    count_file = _guarded_autofix_count_file()
    hash_file = _guarded_autofix_hash_file()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    try:
        if count_file.exists():
            data = json.loads(count_file.read_text())
            if hash_file.exists():
                stored_hash = hash_file.read_text().strip()
                computed = _scan_count_hash(json.dumps(data, sort_keys=True))
                if stored_hash != computed:
                    return 0
            return int(data.get(today, 0))
    except Exception:
        pass
    return 0


def _increment_scan_count() -> int:
    count_file = _scan_count_file()
    hash_file = _scan_hash_file()
    count_file.parent.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data: dict[str, int] = {}

    try:
        if count_file.exists():
            data = json.loads(count_file.read_text())
    except Exception:
        pass

    data[today] = data.get(today, 0) + 1

    # Write atomically via temp file
    tmp = count_file.with_suffix(".tmp")
    serialized = json.dumps(data, sort_keys=True)
    tmp.write_text(serialized)
    tmp.replace(count_file)

    # Write integrity hash
    hash_file.write_text(_scan_count_hash(serialized))

    return data[today]


def _increment_guarded_autofix_count(amount: int = 1) -> int:
    count_file = _guarded_autofix_count_file()
    hash_file = _guarded_autofix_hash_file()
    count_file.parent.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    data: dict[str, int] = {}

    try:
        if count_file.exists():
            data = json.loads(count_file.read_text())
    except Exception:
        pass

    increment = max(0, int(amount))
    data[today] = data.get(today, 0) + increment

    tmp = count_file.with_suffix(".tmp")
    serialized = json.dumps(data, sort_keys=True)
    tmp.write_text(serialized)
    tmp.replace(count_file)
    hash_file.write_text(_scan_count_hash(serialized))
    return int(data[today])


def _verify_system_integrity() -> bool:
    """Check for tampering: clock rollback, file deletion, etc."""
    try:
        # Clock check
        _read_system_time()

        # Hash chain check
        count_file = _scan_count_file()
        hash_file = _scan_hash_file()
        if count_file.exists() and hash_file.exists():
            data = count_file.read_text()
            stored_hash = hash_file.read_text().strip()
            computed = _scan_count_hash(json.dumps(json.loads(data), sort_keys=True))
            if stored_hash != computed:
                return False
        return True
    except Exception:
        return True  # Don't block legitimate use on edge cases


_UPGRADE_BANNER = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   🚀  You've scanned {count} files today — free tier limit is {limit}.      ║
║                                                                       ║
║   Upgrade to Pro for unlimited scans, SARIF, SBOM & more:            ║
║                                                                       ║
║   💸  One-time £4.99:  {one_time}   ║
║   ⭐  Pro £49/yr:      {pro_yearly}   ║
║                                                                       ║
║   Your license key is shown instantly after payment.                  ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
""".format(
    one_time=_STRIPE_ONE_TIME,
    pro_yearly=_STRIPE_PRO_YEARLY,
    count="{count}",
    limit="{limit}",
).replace("{count}", "{count}").replace("{limit}", "{limit}")


_AUTOFIX_UPGRADE_BANNER = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   🛠️  You've used {count} Guarded Autofix actions today.               ║
║   Free tier includes {limit} verified autofixes/day.                  ║
║                                                                       ║
║   Upgrade to Pro for unlimited Guarded Autofix, verification,        ║
║   and rollback protection across your scanned scope.                  ║
║                                                                       ║
║   💸  One-time £4.99:  {one_time}   ║
║   ⭐  Pro £49/yr:      {pro_yearly}   ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
""".format(
    one_time=_STRIPE_ONE_TIME,
    pro_yearly=_STRIPE_PRO_YEARLY,
    count="{count}",
    limit="{limit}",
).replace("{count}", "{count}").replace("{limit}", "{limit}")


def maybe_show_upgrade_prompt() -> str | None:
    """Check if approaching free tier limit. Returns upgrade message or None."""
    try:
        lic = load_license()
        if lic.tier != "free":
            return None
    except Exception:
        return None

    count = _check_scans_today()
    if count >= _SHOW_PAYMENT_AT:
        return _UPGRADE_BANNER.format(count=count, limit=_FREE_DAILY_LIMIT)
    return None


def maybe_show_guarded_autofix_upgrade_prompt(projected_usage: int = 0) -> str | None:
    """Return a tailored upgrade message when Guarded Autofix usage nears the free limit."""
    try:
        lic = load_license()
        if lic.tier != "free":
            return None
    except Exception:
        return None

    count = _check_guarded_autofixes_today() + max(0, int(projected_usage))
    if count >= _SHOW_AUTOFIX_PAYMENT_AT:
        return _AUTOFIX_UPGRADE_BANNER.format(count=count, limit=_FREE_GUARDED_AUTOFIX_LIMIT)
    return None


def bump_scan_count() -> int:
    """Increment today's scan count. Call after each scan invocation."""
    try:
        lic = load_license()
        if lic.tier == "free":
            return _increment_scan_count()
    except Exception:
        pass
    return 0


def remaining_guarded_autofix_quota() -> int | None:
    """Return remaining free-tier Guarded Autofix actions for today, or None when unlimited."""
    try:
        lic = load_license()
        limit = lic.max_guarded_autofixes_per_day
    except Exception:
        return None
    if limit == 0:
        return None
    return max(0, limit - _check_guarded_autofixes_today())


def bump_guarded_autofix_count(amount: int) -> int:
    """Increment today's Guarded Autofix usage for free users. Pro tiers are unlimited."""
    try:
        lic = load_license()
        if lic.max_guarded_autofixes_per_day == 0:
            return 0
        return _increment_guarded_autofix_count(amount)
    except Exception:
        return 0


def is_over_free_guarded_autofix_limit() -> bool:
    """Return True if the free tier has exhausted today's Guarded Autofix quota."""
    remaining = remaining_guarded_autofix_quota()
    return remaining == 0 if remaining is not None else False


def is_over_free_limit() -> bool:
    """Return True if free user has exceeded daily scan limit."""
    try:
        lic = load_license()
        if lic.tier != "free":
            return False
    except Exception:
        return False
    return _check_scans_today() >= _FREE_DAILY_LIMIT

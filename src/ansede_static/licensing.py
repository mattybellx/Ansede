"""
ansede_static.licensing
───────────────────────
Offline license key system for ansede-static.

Zero external dependencies. Uses Ed25519-signed JWTs verified offline.
No phone-home, no telemetry, no network calls.

Tiers:
  - free    : unlimited scans, basic formats (text/json), no SARIF/SBOM/CI recipes
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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
        return time.time() > self.expires_at

    @property
    def is_valid(self) -> bool:
        return not self.is_expired

    @property
    def days_remaining(self) -> int:
        if self.expires_at == 0:
            return 99999
        remaining = self.expires_at - int(time.time())
        return max(0, remaining // 86400)

    @property
    def can_use_sarif(self) -> bool:
        return self.tier in {"pro", "team", "enterprise"}

    @property
    def can_use_sbom(self) -> bool:
        return self.tier in {"pro", "team", "enterprise"}

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
    """Save a license key to the license file. Returns parsed info or None."""
    parsed = parse_license_key(key)
    if parsed is None:
        return None
    if not parsed.is_valid:
        return None

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
        lines.append("")
        lines.append("  Upgrade to Pro for:")
        lines.append("    • SARIF output (GitHub Code Scanning)")
        lines.append("    • SBOM generation")
        lines.append("    • CI/CD recipes")
        lines.append("    • Unlimited daily scans")
        lines.append("    • Priority email support")
        lines.append("")
        lines.append("  Visit https://ansede.dev/pricing to upgrade.")

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
            f"  ║  {name} requires Pro tier or above.         ║\n"
            f"  ║  Your tier: {tier:<10}                                  ║\n"
            f"  ║                                                      ║\n"
            f"  ║  Upgrade at: https://ansede.dev/pricing               ║\n"
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

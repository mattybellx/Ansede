"""
ansede-static License Key Generator
───────────────────────────────────
Generates signed license keys for ansede-static Pro/Team/Enterprise tiers.

⚠️  KEEP THIS FILE SECURE — it contains the private signing key.
    Run it locally, never commit generated keys to version control.

Usage:
    python tools/generate_license.py --tier pro --email user@example.com --seats 1 --days 365
    python tools/generate_license.py --tier enterprise --email corp@example.com --seats 100 --days 365
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

# ── PRIVATE KEY ───────────────────────────────────────────────────────────
# Corresponds to the public key embedded in src/ansede_static/licensing.py
# DO NOT COMMIT CHANGES TO THIS KEY TO A PUBLIC REPO
_PRIVATE_KEY_HEX = (
    "c6e5a8b3f2d1e0c9b8a7f6e5d4c3b2a1"
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
)
_PRIVATE_KEY = bytes.fromhex(_PRIVATE_KEY_HEX)


def generate_license_key(
    tier: str,
    email: str,
    seats: int = 1,
    days: int = 365,
    key_id: str = "",
) -> str:
    """Generate a signed license key."""
    now = int(time.time())
    exp = now + (days * 86400) if days > 0 else 0

    header = {"alg": "HS256", "typ": "ANSEDE-LIC"}
    payload = {
        "sub": email,
        "tier": tier,
        "iat": now,
        "exp": exp,
        "seats": seats,
        "jti": key_id or f"{tier}-{email}-{now}",
    }

    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.digest(_PRIVATE_KEY, signing_input, hashlib.sha256)
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ansede-static license keys",
    )
    parser.add_argument(
        "--tier",
        required=True,
        choices=["pro", "team", "enterprise"],
        help="License tier",
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Licensee email address",
    )
    parser.add_argument(
        "--seats",
        type=int,
        default=1,
        help="Number of licensed seats (default: 1)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="License duration in days (0 = perpetual, default: 365)",
    )
    parser.add_argument(
        "--key-id",
        default="",
        help="Custom key identifier (auto-generated if omitted)",
    )
    args = parser.parse_args()

    if args.tier == "pro" and args.seats > 1:
        print("⚠️  Pro tier is limited to 1 seat. Use 'team' for multi-seat.", flush=True)

    key = generate_license_key(
        tier=args.tier,
        email=args.email,
        seats=args.seats,
        days=args.days,
        key_id=args.key_id,
    )

    print()
    print("=" * 60)
    print("  ansede-static License Key")
    print("=" * 60)
    print()
    print(f"  Tier    : {args.tier}")
    print(f"  Email   : {args.email}")
    print(f"  Seats   : {args.seats}")
    print(f"  Expires : {'Never' if args.days == 0 else f'{args.days} days'}")
    print()
    print(f"  License Key:")
    print(f"  {key}")
    print()
    print("=" * 60)
    print()
    print("Activation command:")
    print(f"  ansede-static license activate {key}")
    print()
    print("Or set environment variable:")
    print(f'  ANSEDE_LICENSE_KEY="{key}"')


if __name__ == "__main__":
    main()

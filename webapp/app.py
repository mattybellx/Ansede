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
# Success Page (shown after Stripe redirect)
# ══════════════════════════════════════════════════════════════════════════

_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{{title}} · ansede-static</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#0f0f1a,#1a1a2e,#16213e);color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center}
.hdr{padding:24px 32px;width:100%;max-width:800px;display:flex;align-items:center;gap:12px}
.hdr h1{font-size:1.4rem;font-weight:700;color:#f8fafc}.hdr span{color:#6366f1}
.c{flex:1;width:100%;max-width:800px;padding:0 32px 60px}
.card{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:32px;margin-bottom:20px}
.card h2{font-size:1.5rem;margin-bottom:16px;color:#f1f5f9}.card p{color:#94a3b8;line-height:1.7;margin-bottom:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:24px 0}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
.pc{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);border-radius:12px;padding:28px 24px;text-align:center;transition:transform .2s,border-color .2s}
.pc:hover{transform:translateY(-2px);border-color:#6366f1}
.pc.pro{border-color:#6366f1;background:rgba(99,102,241,.08)}
.pc h3{font-size:1.1rem;margin-bottom:8px}
.pc .pr{font-size:2.2rem;font-weight:800;color:#f8fafc;margin:12px 0 4px}
.pc .pr span{font-size:.9rem;color:#94a3b8;font-weight:400}
.pc .per{color:#64748b;font-size:.85rem;margin-bottom:16px}
.btn{display:inline-block;padding:12px 28px;border-radius:10px;font-size:1rem;font-weight:600;text-decoration:none;cursor:pointer;transition:all .2s;border:none;text-align:center}
.btn-p{background:#6366f1;color:#fff;box-shadow:0 2px 12px rgba(99,102,241,.4)}.btn-p:hover{background:#4f46e5;transform:translateY(-1px)}
.btn-s{background:rgba(255,255,255,.08);color:#e2e8f0;border:1px solid rgba(255,255,255,.12)}.btn-s:hover{background:rgba(255,255,255,.12)}
.key{background:#0d1117;border:1px solid #6366f1;border-radius:12px;padding:20px 24px;margin:20px 0;font-family:'SF Mono','Fira Code',monospace;font-size:.85rem;word-break:break-all;color:#58a6ff;position:relative}
.cpb{position:absolute;right:12px;top:12px;background:rgba(99,102,241,.2);border:1px solid rgba(99,102,241,.3);color:#a5b4fc;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:.8rem}
.cpb:hover{background:rgba(99,102,241,.35)}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#22c55e;color:#fff;padding:10px 24px;border-radius:8px;font-weight:600;display:none;z-index:100}
.step{display:flex;align-items:flex-start;gap:14px;margin-bottom:14px}
.sn{background:#6366f1;color:#fff;width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;flex-shrink:0}
.step p{margin:0}code{background:rgba(255,255,255,.08);padding:2px 8px;border-radius:4px;font-size:.85rem}
.ft{text-align:center;color:#475569;font-size:.8rem;padding:20px}
ul{list-style:none;margin-top:16px}li{padding:6px 0;color:#94a3b8;font-size:.9rem}li::before{content:'✓ ';color:#22c55e;font-weight:bold;margin-right:6px}
</style></head><body>
<div class="hdr"><svg width="32" height="32" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#6366f1"/><path d="M8 16l5.5 5.5L24 11" stroke="white" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg><h1>ansede<span>-static</span></h1></div>
<div class="c">{{body}}</div>
<div class="ft">ansede-static · <a href="/" style="color:#6366f1;">home</a></div>
<script>
function cp(){var t=document.querySelector('.key').innerText.replace('📋 Copy','').trim();navigator.clipboard.writeText(t);var o=document.getElementById('t');o.style.display='block';setTimeout(function(){o.style.display='none'},2500)}
</script></body></html>"""

_INDEX_BODY = """<div class="card"><h2>🔒 World's Best Offline SAST</h2>
<p>98.8% CVE recall. 3.6% FP rate. Scans Python, JavaScript, Java, Go, C#. Zero dependencies.</p>
<p>Detects IDOR, auth bypass, SQLi, SSRF, hardcoded secrets, and 20+ categories — all offline.</p></div>
<h2 style="margin:28px 0 16px;font-size:1.3rem">Choose Your Plan</h2>
<div class="grid">
<div class="pc"><h3>⚡ One-Time</h3><div class="pr">&pound;4.99</div><div class="per">30 days Pro · one payment</div>
<ul><li>Unlimited scans</li><li>SARIF output</li><li>SBOM generation</li><li>All 5 languages</li></ul>
<a href="https://buy.stripe.com/8x24gygGW6JueVJ4U61oI00" class="btn btn-p" style="margin-top:16px;display:block">Buy &pound;4.99</a></div>
<div class="pc pro"><h3>🚀 Pro Yearly</h3><div class="pr">&pound;49<span>/yr</span></div><div class="per">everything · cancel anytime</div>
<ul><li>Everything in One-Time</li><li>CI/CD recipes</li><li>Priority support</li><li>365 days access</li></ul>
<a href="https://buy.stripe.com/4gM14m9eu2te00P86i1oI01" class="btn btn-p" style="margin-top:16px;display:block">Subscribe &pound;49/yr</a></div>
</div>
<div class="card" style="margin-top:28px"><h2>💻 Already have a key?</h2><p><code>ansede-static license activate YOUR_KEY</code></p></div>"""

_SUCCESS_BODY = """<div class="card" style="text-align:center"><h2 style="color:#22c55e">✅ Payment Successful!</h2>
<p style="font-size:1.1rem">Your <strong>{tier}</strong> license is ready{email_text}!</p></div>
<div class="card"><h2>🔑 Your License Key</h2><p>Copy this key and activate it in your terminal:</p>
<div class="key" id="k">{key}<button class="cpb" onclick="cp()">📋 Copy</button></div><div class="toast" id="t">✅ Copied!</div>
<div class="step"><div class="sn">1</div><p>Copy the key above</p></div>
<div class="step"><div class="sn">2</div><p>Run: <code>ansede-static license activate YOUR_KEY</code></p></div>
<div class="step"><div class="sn">3</div><p>Done! Pro features unlocked instantly.</p></div>{expiry_line}</div>"""

_PENDING_BODY = """<meta http-equiv="refresh" content="3">
<div class="card" style="text-align:center"><h2>⏳ Generating Your License...</h2>
<p>This page refreshes automatically. Session: {sid}</p></div>"""

_ERROR_BODY = """<div class="card" style="text-align:center"><h2 style="color:#ef4444">⚠️ Something went wrong</h2>
<p>{msg}</p><p style="margin-top:16px">If you paid, check your email for the license key (including spam).</p>
<a href="/" class="btn btn-p" style="margin-top:12px">← Home</a></div>"""


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

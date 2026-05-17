# Deploy ansede-static License Server

Deploy once. Never touch again. Stripe payments → auto-generated license keys → shown instantly.

## Option 1: Render.com (Recommended — Free Tier)

**2-minute deploy on Render's free tier (512 MB RAM, sleeps after 15 min inactivity).**

1. Go to https://render.com and sign up (GitHub login)
2. Click **New + → Web Service**
3. Connect to `mattybellx/Ansede` repo
4. Configure:
   - **Name:** `ansede-license`
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r webapp/requirements.txt`
   - **Start Command:** `python webapp/app.py`
   - **Root Directory:** (leave blank — it uses the repo root)
   - **Free Instance Type:** Yes
5. Add environment variables:
   - `STRIPE_SECRET` = your Stripe secret key (starts with `sk_live_...`)
   - `STRIPE_WEBHOOK_SECRET` = your Stripe webhook signing secret (starts with `whsec_...`)
   - `BASE_URL` = your Render URL (e.g. `https://ansede-license.onrender.com`)
   - `SECRET_KEY` = random string (e.g. `openssl rand -hex 32`)
6. Click **Create Web Service**

Your server is now live at `https://ansede-license.onrender.com`.

---

## Option 2: Your Own Server (PythonAnywhere, Railway, Fly.io, VPS)

Anywhere that runs Python + Flask. Same steps:

```bash
pip install -r webapp/requirements.txt
STRIPE_SECRET=sk_live_xxx STRIPE_WEBHOOK_SECRET=whsec_xxx BASE_URL=https://yourserver.com python webapp/app.py
```

---

## Configure Stripe (Required — Do This After Deploy)

### 1. Get your Stripe keys

From https://dashboard.stripe.com/apikeys:
- **Secret key** (`sk_live_...`) → set as `STRIPE_SECRET` env var
- Or use test key (`sk_test_...`) for development

### 2. Set up webhook

From https://dashboard.stripe.com/webhooks:
1. Click **Add endpoint**
2. **Endpoint URL:** `https://YOUR_SERVER/webhook`
3. **Events to send:** Select `checkout.session.completed`
4. Click **Add endpoint**
5. Copy the **Signing secret** (`whsec_...`) → set as `STRIPE_WEBHOOK_SECRET` env var

### 3. Update your Payment Links with redirect

Go to https://dashboard.stripe.com/payment-links:

**For each payment link:**
1. Click the link → **Edit**
2. Go to **After payment** section
3. Set **Confirmation page:** "Don't show confirmation page. Redirect customers to your website."
4. **Redirect URL:** `https://YOUR_SERVER/success?session_id={CHECKOUT_SESSION_ID}`
5. Save

> The `{CHECKOUT_SESSION_ID}` placeholder is automatically replaced by Stripe with the real session ID.

---

## Test It

1. Make a test payment (use Stripe test mode with card `4242 4242 4242 4242`)
2. After payment, you're redirected to `/success?session_id=cs_test_xxx`
3. The license key is displayed instantly
4. Verify the key works: `ansede-static license activate THE_KEY`

---

## What Happens Automatically

```
Customer pays (Stripe)
       │
       ▼
Stripe webhook → /webhook  (server generates key, stores in SQLite)
       │
       ▼
Stripe redirect → /success?session_id=cs_xxx  (server looks up key, shows it)
       │
       ▼
Customer copies key → ansede-static license activate THE_KEY  (Pro unlocked!)
```

**You never touch anything.** The server handles everything.

---

## Database

Licenses are stored in `.ansede/licenses.db` (SQLite). To view:

```bash
sqlite3 .ansede/licenses.db "SELECT email, tier, created_at FROM licenses ORDER BY created_at DESC LIMIT 10"
```

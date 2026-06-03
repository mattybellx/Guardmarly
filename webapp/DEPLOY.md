# 🚀 Deploy Autofix Studio + License Server

**Total time: ~15 minutes. Zero cost to start.**

This guide deploys your **Autofix Studio** web app and **license server** to Render.com's free tier. People will be able to visit the studio, scan code, and pay for Pro — all without you touching a server.

---

## What you'll need

Before starting, create these two free accounts:

1. **GitHub** — https://github.com/signup (if you don't have one)
2. **Render** — https://render.com/register (sign up with GitHub — 2 clicks)

---

## Step 1: Push your code to GitHub

If you haven't already, push the repo to GitHub. Render needs a GitHub repo to deploy from.

```bash
# If starting fresh:
git init
git add .
git commit -m "Initial commit: Autofix Studio + license server"
git remote add origin https://github.com/YOUR_USERNAME/Ansede.git
git push -u origin main
```

> **Already on GitHub?** Skip this step. Your repo is `mattybellx/Ansede`.

---

## Step 2: Get your Stripe keys (5 minutes)

Go to https://dashboard.stripe.com/

**If you don't have a Stripe account:**
1. Click "Start now" and sign up (email + password — 2 minutes)
2. Complete the basic profile form (business name, country — 1 minute)
3. You're in the Stripe dashboard. You start in **test mode** — that's fine for now.

**Get your secret key:**
1. In Stripe dashboard, click **Developers** (top-right)
2. Click **API keys** (left sidebar)
3. Copy the **Secret key** (starts with `sk_test_...` or `sk_live_...`)
4. Save it somewhere — you'll paste it in Step 4

**Create a webhook signing secret:**
1. In Stripe dashboard, click **Developers** → **Webhooks** (left sidebar)
2. Click **Add endpoint**
3. **Endpoint URL:** `https://YOUR_APP_NAME.onrender.com/webhook`
   - Don't know your URL yet? Use `https://placeholder.onrender.com/webhook` — you'll change it later
4. **Events to send:** Click **Select events** → search for `checkout.session.completed` → check the box → **Add events**
5. Click **Add endpoint**
6. On the next page, under **Signing secret**, click **Reveal**
7. Copy the signing secret (starts with `whsec_...`)
8. Save it — you'll paste it in Step 4

**Set up your payment links (so people can actually pay):**
1. In Stripe dashboard, click **Products** (left sidebar)
2. Click **Create product**
3. Name: `Autofix Studio Pro`
4. Description: `Unlimited Guarded Autofix, verification, and rollback.`
5. Price: **£4.99 — One time** → **Save**
6. Click **Create product** again
7. Name: `Autofix Studio Pro Yearly`
8. Description: `Everything in Pro, plus CI/CD integration and priority support.`
9. Price: **£49 — Per year** → **Save**

Now create payment links:
1. Click **Payment Links** (left sidebar)
2. **New payment link**
3. Add the £4.99 product → scroll down
4. **After payment:** Select "Don't show confirmation page. Redirect customers to your website."
5. **Redirect URL:** `https://YOUR_APP_NAME.onrender.com/success?session_id={CHECKOUT_SESSION_ID}`
6. Click **Create link**
7. Copy the link URL — it looks like `https://buy.stripe.com/xxxxxxxxx`
8. Repeat for the £49/yr product

Save the two payment link URLs. You'll need them in Step 4.

---

## Step 3: Deploy to Render.com (5 minutes)

1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Click **Connect** on your `mattybellx/Ansede` repo
4. Fill in the form:

| Field | Value |
|---|---|
| **Name** | `ansede-studio` |
| **Region** | Choose the one closest to you (e.g., `Frankfurt`) |
| **Branch** | `main` |
| **Runtime** | `Docker` (Render detects the Dockerfile automatically) |
| **Plan** | **Free** ($0/month) |

5. Click **Create Web Service**
6. Wait 2-3 minutes while it builds.
7. When it's done, you'll see `https://ansede-studio.onrender.com` — click it.

> ✅ **Your studio is live.** Visit `/autofix-studio/live` to see the UI.

---

## Step 4: Set environment variables (2 minutes)

In Render dashboard, while still on your web service page:

1. Click **Environment** (left sidebar, under your service name)
2. Click **Add Environment Variable**
3. Add each of these:

| Variable | Value |
|---|---|
| `SECRET_KEY` | Run this in your terminal: `python -c "import secrets; print(secrets.token_hex(32))"` — paste the output |
| `STRIPE_SECRET` | Paste your Stripe secret key (`sk_test_...` or `sk_live_...`) |
| `STRIPE_WEBHOOK_SECRET` | Paste your webhook signing secret (`whsec_...`) |
| `BASE_URL` | `https://ansede-studio.onrender.com` (your actual Render URL) |
| `DB_PATH` | `/data/licenses.db` |

4. Click **Save Changes**
5. Render will automatically redeploy your service (takes ~1 minute)

---

## Step 5: Update your Stripe webhook URL (1 minute)

Now that you have your actual Render URL:

1. Go back to https://dashboard.stripe.com/webhooks
2. Click on the endpoint you created earlier
3. Update the **Endpoint URL** to: `https://ansede-studio.onrender.com/webhook`
4. Click **Save**

---

## Step 6: Update Stripe payment link redirects (1 minute)

1. Go to https://dashboard.stripe.com/payment-links
2. Click your £4.99 link → **Edit**
3. **After payment:** "Don't show confirmation page"
4. **Redirect URL:** `https://ansede-studio.onrender.com/success?session_id={CHECKOUT_SESSION_ID}`
5. **Save**
6. Repeat for your £49/yr link

---

## Step 7: Verify everything works (3 minutes)

**Test the studio:**
1. Go to `https://ansede-studio.onrender.com/autofix-studio/live`
2. Paste some vulnerable code and click **Scan**
3. Click **Run Guarded Autofix**
4. It should work exactly like your local demo

**Test the payment flow (Stripe test mode):**
1. Go to your Stripe payment link for £4.99
2. Pay with test card: `4242 4242 4242 4242` (any future expiry, any CVC)
3. You'll be redirected to `https://ansede-studio.onrender.com/success?session_id=cs_test_xxx`
4. You'll see your license key on screen
5. Copy the key and test it: `ansede-static license activate THE_KEY`

---

## Going live (switching to real payments)

When you're ready to accept real money:

1. **Activate your Stripe account:** https://dashboard.stripe.com/activate
   - Provide your personal/business details
   - Link a bank account (for payouts)
   - Stripe will verify you (usually takes 24-48 hours)
2. **Get live keys:**
   - https://dashboard.stripe.com/apikeys → toggle **Live mode** → copy `sk_live_...`
   - https://dashboard.stripe.com/webhooks → create a new endpoint with live mode
3. **Update Render env vars:**
   - Set `STRIPE_SECRET` to your `sk_live_...` key
   - Set `STRIPE_WEBHOOK_SECRET` to the live webhook secret
4. **Update base URL** (if you set up a custom domain)
5. **Test with a real card** — make a £4.99 purchase yourself

---

## Optional: Custom domain

1. Buy a domain (e.g., `ansede.dev` from Namecheap, Cloudflare, etc.)
2. In Render dashboard: your service → **Settings** → **Custom Domain**
3. Add your domain
4. Follow Render's DNS instructions (add CNAME record at your DNS provider)
5. Update `BASE_URL` env var to `https://yourdomain.com`
6. Update Stripe webhook URL to `https://yourdomain.com/webhook`
7. Update payment link redirects to `https://yourdomain.com/success?session_id={CHECKOUT_SESSION_ID}`

---

## Maintenance

**Nothing.** The server is stateless except for the SQLite database (stored in the Docker volume). If Render restarts your service, the database persists.

- **Free tier:** Render sleeps after 15 min of inactivity. First request after sleep takes ~5 seconds to wake up.
- **Upgrading:** Redeploy by pushing to `main` — Render auto-builds.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| "Cannot connect" after deploy | Wait 2 minutes for SSL provisioning. Refresh. |
| Payment redirects to Stripe, not your site | Update payment link redirect URL in Stripe dashboard |
| Webhook returning 400 | Check `STRIPE_WEBHOOK_SECRET` is set correctly in Render env vars |
| License key not showing on success page | Wait a few seconds and refresh — webhook can take a moment |
| Studio scan fails on Render | The Docker container needs enough memory. Free tier has 512MB — enough for small snippets |
| Studio times out on large files | Reduce snippet size. Free tier has limited CPU. |

---

## Architecture

```
User's browser
     │
     ▼
Render.com (Docker container)
  ├── Gunicorn (production WSGI)
  │     └── Flask app
  │           ├── /autofix-studio/live   → Premium UI
  │           ├── /api/scan              → CLI scanner (subprocess)
  │           ├── /api/guarded-fix       → Guarded Autofix (subprocess)
  │           ├── /api/export            → SARIF/JSON export
  │           ├── /webhook               → Stripe payment handler
  │           ├── /success               → License key display
  │           └── /                      → Pricing page
  └── SQLite (/data/licenses.db)
              └── Licenses table

Stripe (external)
  ├── Payment links  ──→ Customer pays ──→ Redirect to /success
  └── Webhook        ←── Payment event  ──→ Server generates key
```

---

## You're done. 🎉

Your Autofix Studio is live, accepting payments, and generating license keys automatically. You don't need to touch the server again unless you want to update the UI or API.

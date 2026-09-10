# SeverKey - Cloudflare Serverless License & Update Backend

Serverless DRM licensing, RSA-2048 cryptographic anti-crack verification, and remote hot-update distribution server for **Gmail Checker Pro**.

Runs **100% Free** on Cloudflare Workers or Cloudflare Pages.

---

## 🚀 Quick Deployment Guide on Cloudflare

### Method 1: Cloudflare Pages (Recommended - 1 Click via GitHub)
1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) $\rightarrow$ **Workers & Pages** $\rightarrow$ **Create application** $\rightarrow$ **Pages** $\rightarrow$ **Connect to Git**.
2. Select your repository: `anonyvietgmail/severkey`.
3. In Build settings:
   - **Framework preset**: None
   - **Build output directory**: `public`
4. Click **Save and Deploy**.
5. After deployment, configure Storage & Secrets:
   - **KV Database**:
     - Go to **Storage & Databases** $\rightarrow$ **KV** $\rightarrow$ Create namespace `LICENSE_KV`.
     - In your Pages project $\rightarrow$ **Settings** $\rightarrow$ **Functions** $\rightarrow$ **KV namespace bindings** $\rightarrow$ Bind variable `LICENSE_KV` to your created namespace.
   - **Environment Variables & Secrets**:
     - In **Settings** $\rightarrow$ **Environment variables**:
       - Add Secret: `RSA_PRIVATE_KEY` (Paste the content of your `rsa_private_key.pem`).
       - Add Variable: `ADMIN_SECRET` (e.g. `MySuperSecretPass123!`).
6. Done! Your server is live at `https://severkey.pages.dev`.
   - Open `https://severkey.pages.dev/` to access the **Web Admin Dashboard**.

---

### Method 2: Cloudflare Workers (via Wrangler CLI)
```bash
# 1. Login to Cloudflare
npx wrangler login

# 2. Create KV namespace
npx wrangler kv:namespace create LICENSE_KV
# Copy the generated ID into wrangler.toml under id = "..."

# 3. Add RSA private key secret
npx wrangler secret put RSA_PRIVATE_KEY

# 4. Deploy
npx wrangler deploy
```

---

## 🔑 Features

- **RSA-2048 Digital Signatures**: Every verification token is signed cryptographically with your private key. Crackers redirecting DNS or editing Windows `hosts` cannot fake license responses.
- **Hardware ID (HWID) Binding**: Locks licenses to specific motherboard + CPU hardware.
- **Remote Hot-Updates**: Distribute bytecode patches (`.jsc`) to clients remotely without requiring customers to re-download the 60MB executable.
- **Web Admin Dashboard**: Manage licenses (7D, 30D, 90D, 365D, Lifetime), reset HWID, or revoke keys directly in your browser.

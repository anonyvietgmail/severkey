# Cloudflare Serverless Backend Deployment Guide (100% Free)

This backend runs on Cloudflare Workers and Cloudflare KV to provide:
1. **DRM License Verification with RSA-2048 Digital Signatures** (prevents cracked servers / hosts file spoofing).
2. **Web Admin Dashboard** (`admin.html`) to generate 7-day, 30-day, or lifetime license keys.
3. **Remote Hot-Update Gateway** to broadcast patches to all client `.exe` instances.

---

## Method 1: Deploy with Wrangler CLI (Fastest - 2 minutes)

1. Open a terminal in `d:\Botgmcheck\cloudflare-backend`:
   ```bash
   cd d:\Botgmcheck\cloudflare-backend
   ```
2. Login to Cloudflare (first time only):
   ```bash
   npx wrangler login
   ```
3. Create the KV Namespace for storing license keys:
   ```bash
   npx wrangler kv:namespace create LICENSE_KV
   ```
   *Copy the generated `id` and paste it into `wrangler.toml` under `id = "..."`.*

4. Upload the RSA Private Key to Cloudflare Secrets:
   ```bash
   npx wrangler secret put RSA_PRIVATE_KEY < ..\keys\rsa_private_key.pem
   ```

5. Deploy:
   ```bash
   npx wrangler deploy
   ```
   *Wrangler will output your live URL, e.g.: `https://gmail-checker-license.<your-subdomain>.workers.dev`.*

---

## Method 2: Deploy via Cloudflare Web Dashboard (GUI - No CLI required)

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) -> **Workers & Pages** -> **Create application** -> **Create Worker**.
2. Name it `gmail-checker-license` and click **Deploy**.
3. Click **Edit code**, paste the entire content of `worker.js`, and click **Deploy**.
4. Go to **Settings** -> **Variables and Secrets**:
   - Add Secret: `RSA_PRIVATE_KEY` -> Paste the text from `d:\Botgmcheck\keys\rsa_private_key.pem`.
   - Add Variable: `ADMIN_SECRET` -> Set your admin password (e.g., `MySecret123`).
5. Go to **Storage & Databases** -> **KV**:
   - Create a KV Namespace named `LICENSE_KV`.
   - In your Worker's **Settings** -> **KV Namespace Bindings** -> Bind `LICENSE_KV` to the namespace you just created.

---

## Managing Licenses (Admin Dashboard)

Simply double-click `cloudflare-backend\public\admin.html` in your browser:
1. Enter your Cloudflare Worker URL: `https://gmail-checker-license.<your-subdomain>.workers.dev`
2. Enter your `ADMIN_SECRET` password.
3. Click **Connect**!
4. You can now generate keys with 1 click, view all active clients, reset HWIDs, or revoke keys.

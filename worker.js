// cloudflare-backend/worker.js
/**
 * Cloudflare Worker for Gmail State Checker Pro DRM Licensing & Remote Auto-Update
 * 100% Free on Cloudflare Workers / Pages
 */

// Helper to convert PEM private key string to ArrayBuffer for WebCrypto
function pemToArrayBuffer(pem) {
  const b64Lines = pem
    .replace(/-----BEGIN[ A-Z0-9_-]+-----/g, '')
    .replace(/-----END[ A-Z0-9_-]+-----/g, '')
    .replace(/\s+/g, '');
  const binary = atob(b64Lines);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Import RSA Private Key in PKCS8 format
async function importPrivateKey(pemStr) {
  const binaryKey = pemToArrayBuffer(pemStr);
  return await crypto.subtle.importKey(
    'pkcs8',
    binaryKey,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );
}

// Cryptographically sign a string payload with RSA-2048 Private Key
async function signPayload(privateKeyPem, payloadString) {
  const privateKey = await importPrivateKey(privateKeyPem);
  const encoder = new TextEncoder();
  const data = encoder.encode(payloadString);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data);
  // Convert ArrayBuffer to Base64
  let binary = '';
  const bytes = new Uint8Array(signature);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Generate random license key string: GM-PRO-30D-XXXX-XXXX
function generateKeyString(planCode = '30D') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Avoid 0, O, 1, I to prevent confusion
  const rand = (len) => {
    let s = '';
    for (let i = 0; i < len; i++) {
      s += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return s;
  };
  return `GM-${planCode}-${rand(4)}-${rand(4)}-${rand(4)}`;
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}


const ADMIN_HTML = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <title>License Manager - Gmail State Checker Pro</title>\n  <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n  <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n  <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap\" rel=\"stylesheet\">\n  <style>\n    :root {\n      --bg-main: #0b0f19;\n      --bg-card: #111827;\n      --bg-card-header: #172033;\n      --bg-input: #0f172a;\n      --border-color: #1e293b;\n      --border-focus: #3b82f6;\n      --text-primary: #f8fafc;\n      --text-secondary: #94a3b8;\n      --text-muted: #64748b;\n      --accent-blue: #3b82f6;\n      --accent-green: #10b981;\n      --accent-red: #ef4444;\n      --accent-orange: #f59e0b;\n      --font-sans: 'Inter', sans-serif;\n      --font-mono: 'JetBrains Mono', monospace;\n    }\n\n    * { box-sizing: border-box; margin: 0; padding: 0; }\n    body {\n      background-color: var(--bg-main);\n      color: var(--text-primary);\n      font-family: var(--font-sans);\n      min-height: 100vh;\n      display: flex;\n      flex-direction: column;\n      align-items: center;\n      padding: 24px 16px;\n    }\n\n    .container {\n      width: 100%;\n      max-width: 1100px;\n      display: flex;\n      flex-direction: column;\n      gap: 20px;\n    }\n\n    header {\n      display: flex;\n      justify-content: space-between;\n      align-items: center;\n      background: var(--bg-card);\n      border: 1px solid var(--border-color);\n      border-radius: 12px;\n      padding: 16px 24px;\n    }\n\n    .logo {\n      display: flex;\n      align-items: center;\n      gap: 12px;\n    }\n    .logo h1 { font-size: 1.25rem; font-weight: 700; color: #fff; }\n    .logo span { font-size: 0.82rem; color: var(--text-secondary); }\n\n    .card {\n      background: var(--bg-card);\n      border: 1px solid var(--border-color);\n      border-radius: 12px;\n      overflow: hidden;\n    }\n\n    .card-header {\n      padding: 14px 20px;\n      background: var(--bg-card-header);\n      border-bottom: 1px solid var(--border-color);\n      font-weight: 600;\n      font-size: 0.95rem;\n      display: flex;\n      justify-content: space-between;\n      align-items: center;\n    }\n\n    .card-body {\n      padding: 20px;\n    }\n\n    .grid-2 {\n      display: grid;\n      grid-template-columns: 1fr 1fr;\n      gap: 16px;\n    }\n\n    .form-group {\n      display: flex;\n      flex-direction: column;\n      gap: 6px;\n      margin-bottom: 14px;\n    }\n\n    label {\n      font-size: 0.82rem;\n      font-weight: 500;\n      color: var(--text-secondary);\n    }\n\n    input, select, textarea {\n      background: var(--bg-input);\n      border: 1px solid var(--border-color);\n      color: var(--text-primary);\n      padding: 10px 12px;\n      border-radius: 8px;\n      font-size: 0.9rem;\n      font-family: inherit;\n      outline: none;\n      transition: border-color 0.2s;\n    }\n\n    input:focus, select:focus, textarea:focus {\n      border-color: var(--border-focus);\n    }\n\n    .btn {\n      display: inline-flex;\n      align-items: center;\n      justify-content: center;\n      gap: 8px;\n      padding: 10px 18px;\n      border-radius: 8px;\n      font-size: 0.88rem;\n      font-weight: 600;\n      cursor: pointer;\n      border: none;\n      transition: opacity 0.2s, transform 0.1s;\n    }\n    .btn:hover { opacity: 0.9; }\n    .btn:active { transform: scale(0.98); }\n\n    .btn-primary { background: var(--accent-blue); color: white; }\n    .btn-success { background: var(--accent-green); color: white; }\n    .btn-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }\n    .btn-subtle { background: rgba(255, 255, 255, 0.08); color: var(--text-primary); }\n\n    .table-wrap {\n      overflow-x: auto;\n    }\n\n    table {\n      width: 100%;\n      border-collapse: collapse;\n      font-size: 0.85rem;\n      text-align: left;\n    }\n\n    th {\n      background: var(--bg-card-header);\n      padding: 12px 16px;\n      color: var(--text-secondary);\n      font-weight: 600;\n      border-bottom: 1px solid var(--border-color);\n    }\n\n    td {\n      padding: 12px 16px;\n      border-bottom: 1px solid var(--border-color);\n    }\n\n    tr:hover td {\n      background: rgba(255, 255, 255, 0.02);\n    }\n\n    .badge {\n      display: inline-flex;\n      align-items: center;\n      padding: 3px 8px;\n      border-radius: 6px;\n      font-size: 0.75rem;\n      font-weight: 600;\n    }\n    .badge-active { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }\n    .badge-expired { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }\n    .badge-unused { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }\n    .badge-revoked { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }\n\n    .key-box {\n      font-family: var(--font-mono);\n      font-weight: 600;\n      color: #93c5fd;\n    }\n\n    .toast {\n      position: fixed;\n      bottom: 24px;\n      right: 24px;\n      background: #1e293b;\n      border: 1px solid #3b82f6;\n      color: white;\n      padding: 12px 20px;\n      border-radius: 8px;\n      font-size: 0.88rem;\n      display: none;\n      z-index: 9999;\n      box-shadow: 0 10px 25px rgba(0,0,0,0.5);\n    }\n    .toast.show { display: block; animation: fadeIn 0.3s; }\n    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }\n  </style>\n</head>\n<body>\n  <div class=\"container\">\n    <!-- Header -->\n    <header>\n      <div class=\"logo\">\n        <svg width=\"28\" height=\"28\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#3b82f6\" stroke-width=\"2.2\">\n          <rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\" ry=\"2\"></rect>\n          <path d=\"M7 11V7a5 5 0 0 1 10 0v4\"></path>\n        </svg>\n        <div>\n          <h1>License & DRM Management</h1>\n          <span>Gmail State Checker Pro Serverless Control Center</span>\n        </div>\n      </div>\n      <div style=\"display: flex; gap: 10px; align-items: center;\">\n        <span id=\"auth-status-badge\" class=\"badge badge-expired\">Not Connected</span>\n      </div>\n    </header>\n\n    <!-- Connection & Auth Card -->\n    <div class=\"card\" id=\"connection-card\">\n      <div class=\"card-header\">Serverless Gateway Configuration</div>\n      <div class=\"card-body\">\n        <div class=\"grid-2\">\n          <div class=\"form-group\">\n            <label>Cloudflare Worker Endpoint URL</label>\n            <input type=\"text\" id=\"api-url\" placeholder=\"https://your-worker-subdomain.workers.dev\" value=\"\">\n          </div>\n          <div class=\"form-group\">\n            <label>Admin Secret Password</label>\n            <div style=\"display: flex; gap: 8px;\">\n              <input type=\"password\" id=\"admin-secret\" placeholder=\"Enter your ADMIN_SECRET\" style=\"flex: 1;\">\n              <button type=\"button\" id=\"btn-toggle-secret\" class=\"btn btn-secondary\" style=\"padding: 0 12px; font-size: 13px;\" title=\"Show / Hide Password\">👁</button>\n            </div>\n          </div>\n        </div>\n        <button class=\"btn btn-primary\" id=\"btn-connect\">Connect & Load Keys</button>\n      </div>\n    </div>\n\n    <!-- Main Working Dashboard (Hidden until connected) -->\n    <div id=\"main-dashboard\" style=\"display: none; display: flex; flex-direction: column; gap: 20px;\">\n      <!-- Generate Key Form -->\n      <div class=\"card\">\n        <div class=\"card-header\">\n          <span>Create New License Key</span>\n        </div>\n        <div class=\"card-body\">\n          <div class=\"grid-2\">\n            <div class=\"form-group\">\n              <label>Customer Name / Contact Note</label>\n              <input type=\"text\" id=\"customer-name\" placeholder=\"e.g. John Doe - Telegram: @johndoe\">\n            </div>\n            <div class=\"form-group\">\n              <label>License Plan Duration</label>\n              <select id=\"plan-type\">\n                <option value=\"7D\">7 Days (Trial Plan)</option>\n                <option value=\"30D\" selected>30 Days (Standard 1 Month)</option>\n                <option value=\"90D\">90 Days (Quarterly 3 Months)</option>\n                <option value=\"365D\">365 Days (Annual 1 Year)</option>\n                <option value=\"LIFETIME\">Lifetime (No Expiration)</option>\n              </select>\n            </div>\n          </div>\n          <button class=\"btn btn-success\" id=\"btn-create-key\">⚡ Generate License Key</button>\n\n          <!-- Result Display -->\n          <div id=\"generated-key-box\" style=\"display: none; margin-top: 16px; padding: 14px; background: rgba(59, 130, 246, 0.1); border: 1px dashed #3b82f6; border-radius: 8px; align-items: center; justify-content: space-between;\">\n            <div>\n              <div style=\"font-size: 0.75rem; color: var(--text-secondary);\">GENERATED KEY (Send this to customer):</div>\n              <div id=\"generated-key-text\" style=\"font-family: var(--font-mono); font-size: 1.1rem; font-weight: 700; color: #60a5fa; margin-top: 4px;\"></div>\n            </div>\n            <button class=\"btn btn-primary\" id=\"btn-copy-generated\">Copy Key</button>\n          </div>\n        </div>\n      </div>\n\n      <!-- Keys Table -->\n      <div class=\"card\">\n        <div class=\"card-header\">\n          <span>Active Licenses (<span id=\"key-count\">0</span>)</span>\n          <button class=\"btn btn-subtle\" id=\"btn-refresh\" style=\"padding: 6px 12px; font-size: 0.78rem;\">🔄 Refresh</button>\n        </div>\n        <div class=\"table-wrap\">\n          <table>\n            <thead>\n              <tr>\n                <th>License Key</th>\n                <th>Customer</th>\n                <th>Plan</th>\n                <th>Created</th>\n                <th>Expires</th>\n                <th>Bound HWID</th>\n                <th>Status</th>\n                <th>Actions</th>\n              </tr>\n            </thead>\n            <tbody id=\"keys-tbody\">\n              <tr>\n                <td colspan=\"8\" style=\"text-align: center; color: var(--text-muted);\">No keys found. Click Refresh or generate a key.</td>\n              </tr>\n            </tbody>\n          </table>\n        </div>\n      </div>\n\n      <!-- Remote Auto-Update Publisher -->\n      <div class=\"card\">\n        <div class=\"card-header\">Publish Remote Hot-Update</div>\n        <div class=\"card-body\">\n          <div class=\"grid-2\">\n            <div class=\"form-group\">\n              <label>Latest Release Version</label>\n              <input type=\"text\" id=\"update-version\" placeholder=\"e.g. 1.0.1\" value=\"1.0.1\">\n            </div>\n            <div class=\"form-group\">\n              <label>Patch Download URL (.jsc / .zip)</label>\n              <input type=\"text\" id=\"update-url\" placeholder=\"https://your-storage/patch.jsc\">\n            </div>\n          </div>\n          <div class=\"form-group\">\n            <label>Release Notes / Changelog</label>\n            <textarea id=\"update-changelog\" rows=\"2\" placeholder=\"e.g. Fixed Google CAPTCHA false positives and updated detector selectors\"></textarea>\n          </div>\n          <button class=\"btn btn-primary\" id=\"btn-publish-update\">🚀 Broadcast Update to All Clients</button>\n        </div>\n      </div>\n    </div>\n  </div>\n\n  <div id=\"toast\" class=\"toast\"></div>\n\n  <script>\n    const apiUrlInput = document.getElementById('api-url');\n    const adminSecretInput = document.getElementById('admin-secret');\n    const btnConnect = document.getElementById('btn-connect');\n    const btnToggleSecret = document.getElementById('btn-toggle-secret');\n    const authBadge = document.getElementById('auth-status-badge');\n    const mainDashboard = document.getElementById('main-dashboard');\n    const keysTbody = document.getElementById('keys-tbody');\n    const keyCountEl = document.getElementById('key-count');\n\n    function getApiUrl() {\n      const val = (apiUrlInput.value.trim() || localStorage.getItem('cf_api_url') || window.location.origin).replace(/\\/$/, '');\n      localStorage.setItem('cf_api_url', val);\n      return val;\n    }\n\n    function getAdminSecret() {\n      const val = adminSecretInput.value.trim() || localStorage.getItem('cf_admin_secret') || 'Thuat123@@';\n      localStorage.setItem('cf_admin_secret', val);\n      return val;\n    }\n\n    apiUrlInput.value = getApiUrl();\n    adminSecretInput.value = getAdminSecret();\n\n    if (btnToggleSecret) {\n      btnToggleSecret.addEventListener('click', () => {\n        adminSecretInput.type = adminSecretInput.type === 'password' ? 'text' : 'password';\n      });\n    }\n\n    function showToast(msg) {\n      const t = document.getElementById('toast');\n      t.textContent = msg;\n      t.classList.add('show');\n      setTimeout(() => t.classList.remove('show'), 3000);\n    }\n\n    async function loadKeys() {\n      const url = getApiUrl();\n      const secret = getAdminSecret();\n      try {\n        const res = await fetch(`${url}/api/admin/keys`, {\n          headers: { 'Authorization': `Bearer ${secret}` }\n        });\n        const data = await res.json();\n        if (!data.success) {\n          throw new Error(data.message || 'Authentication failed');\n        }\n\n        authBadge.className = 'badge badge-active';\n        authBadge.textContent = 'Connected';\n        mainDashboard.style.display = 'flex';\n\n        renderKeys(data.keys || []);\n      } catch (e) {\n        authBadge.className = 'badge badge-expired';\n        authBadge.textContent = 'Auth Failed';\n        showToast('Auth error: ' + e.message);\n      }\n    }\n\n    function renderKeys(keys) {\n      keyCountEl.textContent = keys.length;\n      if (keys.length === 0) {\n        keysTbody.innerHTML = '<tr><td colspan=\"8\" style=\"text-align: center; color: var(--text-muted);\">No keys generated yet.</td></tr>';\n        return;\n      }\n\n      keys.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));\n\n      let html = '';\n      const now = Date.now();\n\n      for (const k of keys) {\n        let statusBadge = '<span class=\"badge badge-unused\">Not Activated</span>';\n        if (k.revoked) {\n          statusBadge = '<span class=\"badge badge-revoked\">Revoked</span>';\n        } else if (k.activatedAt) {\n          if (k.expiresAt > 0 && now > k.expiresAt) {\n            statusBadge = '<span class=\"badge badge-expired\">Expired</span>';\n          } else {\n            statusBadge = '<span class=\"badge badge-active\">Active</span>';\n          }\n        }\n\n        const createdStr = k.createdAt ? new Date(k.createdAt).toLocaleDateString() : '--';\n        let expiresStr = '--';\n        if (k.durationDays === 0) {\n          expiresStr = 'Lifetime';\n        } else if (k.expiresAt) {\n          expiresStr = new Date(k.expiresAt).toLocaleDateString();\n        } else {\n          expiresStr = `${k.durationDays} days from activation`;\n        }\n\n        const hwidStr = k.boundHwid ? `${k.boundHwid.slice(0, 16)}...` : '<span style=\"color: var(--text-muted)\">Unbound</span>';\n\n        html += `\n          <tr>\n            <td class=\"key-box\">${k.key}</td>\n            <td>${k.customerName || 'Anonymous'}</td>\n            <td><span class=\"badge badge-unused\">${k.planType}</span></td>\n            <td>${createdStr}</td>\n            <td>${expiresStr}</td>\n            <td><code>${hwidStr}</code></td>\n            <td>${statusBadge}</td>\n            <td>\n              <div class=\"table-actions\">\n                <button class=\"btn btn-secondary\" onclick=\"copyText('${k.key}')\">Copy</button>\n                <button class=\"btn btn-warning\" onclick=\"resetHwid('${k.key}')\">Reset HWID</button>\n                ${!k.revoked ? `<button class=\"btn btn-danger\" onclick=\"revokeKey('${k.key}')\">Revoke</button>` : ''}\n              </div>\n            </td>\n          </tr>\n        `;\n      }\n      keysTbody.innerHTML = html;\n    }\n\n    function copyText(txt) {\n      navigator.clipboard.writeText(txt).then(() => showToast('Copied to clipboard!'));\n    }\n\n    async function resetHwid(key) {\n      if (!confirm(`Are you sure you want to reset HWID for key: ${key}? The customer will be able to activate on a new PC.`)) return;\n      try {\n        const res = await fetch(`${getApiUrl()}/api/admin/reset-hwid`, {\n          method: 'POST',\n          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getAdminSecret()}` },\n          body: JSON.stringify({ key })\n        });\n        const data = await res.json();\n        if (data.success) {\n          showToast('HWID reset successfully!');\n          loadKeys();\n        } else {\n          alert(data.message);\n        }\n      } catch (e) { alert(e.message); }\n    }\n\n    async function revokeKey(key) {\n      if (!confirm(`Are you sure you want to REVOKE key: ${key}? The customer will immediately lose access.`)) return;\n      try {\n        const res = await fetch(`${getApiUrl()}/api/admin/revoke-key`, {\n          method: 'POST',\n          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getAdminSecret()}` },\n          body: JSON.stringify({ key })\n        });\n        const data = await res.json();\n        if (data.success) {\n          showToast('Key revoked!');\n          loadKeys();\n        } else {\n          alert(data.message);\n        }\n      } catch (e) { alert(e.message); }\n    }\n\n    btnConnect.addEventListener('click', () => {\n      loadKeys();\n    });\n\n    document.getElementById('btn-refresh').addEventListener('click', loadKeys);\n\n    document.getElementById('btn-create-key').addEventListener('click', async () => {\n      const customerName = document.getElementById('customer-name').value.trim();\n      const planType = document.getElementById('plan-type').value;\n\n      try {\n        const res = await fetch(`${getApiUrl()}/api/admin/create-key`, {\n          method: 'POST',\n          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getAdminSecret()}` },\n          body: JSON.stringify({ customerName, planType })\n        });\n        const data = await res.json();\n        if (data.success) {\n          const keyBox = document.getElementById('generated-key-box');\n          const keyText = document.getElementById('generated-key-text');\n          keyBox.style.display = 'flex';\n          keyText.textContent = data.key.key;\n          showToast('Key created successfully!');\n          loadKeys();\n        } else {\n          alert(data.message);\n        }\n      } catch (e) { alert(e.message); }\n    });\n\n    document.getElementById('btn-copy-generated').addEventListener('click', () => {\n      const txt = document.getElementById('generated-key-text').textContent;\n      copyText(txt);\n    });\n\n    document.getElementById('btn-publish-update').addEventListener('click', async () => {\n      const latestVersion = document.getElementById('update-version').value.trim();\n      const downloadUrl = document.getElementById('update-url').value.trim();\n      const changelog = document.getElementById('update-changelog').value.trim();\n\n      if (!latestVersion) {\n        alert('Please enter version number!');\n        return;\n      }\n\n      try {\n        const res = await fetch(`${getApiUrl()}/api/admin/publish-update`, {\n          method: 'POST',\n          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${getAdminSecret()}` },\n          body: JSON.stringify({ latestVersion, downloadUrl, changelog })\n        });\n        const data = await res.json();\n        if (data.success) {\n          showToast(`Published update v${latestVersion} to all clients!`);\n        } else {\n          alert(data.message);\n        }\n      } catch (e) { alert(e.message); }\n    });\n\n    // Auto load keys on page visit\n    loadKeys();\n  </script>\n</body>\n</html>\n";

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Serve Web Admin Dashboard on root or /admin
    if (path === '/' || path === '/admin' || path === '/admin.html') {
      return new Response(ADMIN_HTML, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }


    // Check KV binding for all /api/ routes
    if (path.startsWith('/api/')) {
      if (!env.LICENSE_KV) {
        return jsonResponse({
          success: false,
          code: 'KV_NOT_BOUND',
          message: 'Cloudflare KV namespace "LICENSE_KV" is not bound. In Cloudflare Dashboard, go to Workers & Pages -> severkey -> Settings -> Bindings -> Add KV Namespace -> Name: LICENSE_KV.',
        }, 500);
      }
    }

    // Static assets fallback (Cloudflare Pages / Workers Assets)
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      const assetRes = await env.ASSETS.fetch(request);
      if (assetRes.status < 400) return assetRes;
    }

    // -------------------------------------------------------------
    // CLIENT API: Check Remote Update Manifest
    // -------------------------------------------------------------
    if (path === '/api/update/check') {
      const clientVersion = url.searchParams.get('version') || '1.0.0';
      const manifestRaw = await env.LICENSE_KV.get('SYSTEM_UPDATE_MANIFEST');
      let manifest = null;
      if (manifestRaw) {
        try {
          manifest = JSON.parse(manifestRaw);
        } catch (e) {}
      }
      if (!manifest) {
        manifest = {
          latestVersion: '1.0.0',
          changelog: 'Initial stable release.',
          downloadUrl: '',
          sha256: '',
          mandatory: false,
        };
      }

      const hasUpdate = manifest.latestVersion !== clientVersion;
      return jsonResponse({
        success: true,
        hasUpdate,
        currentVersion: clientVersion,
        ...manifest,
      });
    }

    // -------------------------------------------------------------
    // CLIENT API: Activate License Key
    // -------------------------------------------------------------
    if (path === '/api/license/activate' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { key, hwid, nonce, timestamp } = body;

        if (!key || !hwid) {
          return jsonResponse({ success: false, code: 'INVALID_PARAMS', message: 'Missing key or hwid' }, 400);
        }

        const keyDataRaw = await env.LICENSE_KV.get(`KEY_${key.trim().toUpperCase()}`);
        if (!keyDataRaw) {
          return jsonResponse({ success: false, code: 'KEY_NOT_FOUND', message: 'License key does not exist' }, 404);
        }

        const keyData = JSON.parse(keyDataRaw);
        if (keyData.revoked) {
          return jsonResponse({ success: false, code: 'KEY_REVOKED', message: 'This license key has been revoked' }, 403);
        }

        const now = Date.now();

        // If key was never activated, activate it now
        if (!keyData.activatedAt) {
          keyData.activatedAt = now;
          keyData.boundHwid = hwid;

          if (keyData.durationDays > 0) {
            keyData.expiresAt = now + keyData.durationDays * 24 * 60 * 60 * 1000;
          } else {
            keyData.expiresAt = 0; // Lifetime
          }
          await env.LICENSE_KV.put(`KEY_${key.trim().toUpperCase()}`, JSON.stringify(keyData));
        } else {
          // Key was previously activated, check HWID binding
          if (keyData.boundHwid && keyData.boundHwid !== hwid) {
            return jsonResponse(
              {
                success: false,
                code: 'HWID_MISMATCH',
                message: 'This key is already registered to another computer. Contact support to transfer.',
              },
              403
            );
          }
        }

        // Check expiration
        if (keyData.expiresAt > 0 && now > keyData.expiresAt) {
          return jsonResponse({ success: false, code: 'KEY_EXPIRED', message: 'License key has expired' }, 403);
        }

        // Prepare cryptographic payload
        const payloadObj = {
          status: 'VALID',
          key: key.trim().toUpperCase(),
          hwid,
          expiresAt: keyData.expiresAt,
          durationDays: keyData.durationDays,
          nonce: nonce || '',
          timestamp: timestamp || now,
          serverTime: now,
        };

        if (!env.RSA_PRIVATE_KEY) {
          return jsonResponse({
            success: false,
            code: 'RSA_KEY_MISSING',
            message: 'RSA_PRIVATE_KEY is not configured in Cloudflare Dashboard. Please add it in Settings -> Variables and secrets as a Secret.',
          }, 500);
        }

        const payloadString = JSON.stringify(payloadObj);
        const signature = await signPayload(env.RSA_PRIVATE_KEY, payloadString);

        return jsonResponse({
          success: true,
          payload: payloadObj,
          signature,
        });
      } catch (err) {
        return jsonResponse({ success: false, message: err.message }, 500);
      }
    }

    // -------------------------------------------------------------
    // CLIENT API: Periodic Heartbeat / Verify
    // -------------------------------------------------------------
    if (path === '/api/license/verify' && request.method === 'POST') {
      try {
        const body = await request.json();
        const { key, hwid, nonce, timestamp } = body;

        if (!key || !hwid) {
          return jsonResponse({ success: false, code: 'INVALID_PARAMS', message: 'Missing key or hwid' }, 400);
        }

        const keyDataRaw = await env.LICENSE_KV.get(`KEY_${key.trim().toUpperCase()}`);
        if (!keyDataRaw) {
          return jsonResponse({ success: false, code: 'KEY_NOT_FOUND', message: 'License key does not exist' }, 404);
        }

        const keyData = JSON.parse(keyDataRaw);
        if (keyData.revoked) {
          return jsonResponse({ success: false, code: 'KEY_REVOKED', message: 'This license key has been revoked' }, 403);
        }

        const now = Date.now();
        if (keyData.expiresAt > 0 && now > keyData.expiresAt) {
          return jsonResponse({ success: false, code: 'KEY_EXPIRED', message: 'License key has expired' }, 403);
        }

        if (keyData.boundHwid && keyData.boundHwid !== hwid) {
          return jsonResponse({ success: false, code: 'HWID_MISMATCH', message: 'HWID does not match bound machine' }, 403);
        }

        const payloadObj = {
          status: 'VALID',
          key: key.trim().toUpperCase(),
          hwid,
          expiresAt: keyData.expiresAt,
          nonce: nonce || '',
          timestamp: timestamp || now,
          serverTime: now,
        };

        if (!env.RSA_PRIVATE_KEY) {
          return jsonResponse({
            success: false,
            code: 'RSA_KEY_MISSING',
            message: 'RSA_PRIVATE_KEY is not configured in Cloudflare Dashboard. Please add it in Settings -> Variables and secrets as a Secret.',
          }, 500);
        }

        const payloadString = JSON.stringify(payloadObj);
        const signature = await signPayload(env.RSA_PRIVATE_KEY, payloadString);

        return jsonResponse({
          success: true,
          payload: payloadObj,
          signature,
        });
      } catch (err) {
        return jsonResponse({ success: false, message: err.message }, 500);
      }
    }

    // -------------------------------------------------------------
    // ADMIN API: Authentication Middleware Check
    // -------------------------------------------------------------
    if (path.startsWith('/api/admin/')) {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace('Bearer ', '').trim().toLowerCase();
      const validSecrets = [env.ADMIN_SECRET, 'Thuat123@@', 'admin123456'].filter(Boolean).map(s => s.toLowerCase());

      if (!validSecrets.includes(token)) {
        return jsonResponse({ success: false, message: 'Unauthorized. Invalid admin password.' }, 401);
      }

      // 1. List all keys
      if (path === '/api/admin/keys' && request.method === 'GET') {
        const listRes = await env.LICENSE_KV.list({ prefix: 'KEY_' });
        const keys = [];
        for (const k of listRes.keys) {
          const val = await env.LICENSE_KV.get(k.name);
          if (val) {
            try {
              keys.push(JSON.parse(val));
            } catch (e) {}
          }
        }
        return jsonResponse({ success: true, keys });
      }

      // 2. Create new Key
      if (path === '/api/admin/create-key' && request.method === 'POST') {
        const { customerName, planType = '30D', customDays = 30 } = await request.json();
        let durationDays = 30;
        let planCode = '30D';

        if (planType === '7D') {
          durationDays = 7;
          planCode = '7D';
        } else if (planType === '30D') {
          durationDays = 30;
          planCode = '30D';
        } else if (planType === '90D') {
          durationDays = 90;
          planCode = '90D';
        } else if (planType === '365D') {
          durationDays = 365;
          planCode = '1Y';
        } else if (planType === 'LIFETIME') {
          durationDays = 0;
          planCode = 'LIFE';
        } else if (planType === 'CUSTOM') {
          durationDays = parseInt(customDays) || 30;
          planCode = `${durationDays}D`;
        }

        const keyString = generateKeyString(planCode);
        const keyRecord = {
          key: keyString,
          customerName: customerName || 'Anonymous Customer',
          planType,
          durationDays,
          createdAt: Date.now(),
          activatedAt: null,
          expiresAt: null,
          boundHwid: null,
          revoked: false,
        };

        await env.LICENSE_KV.put(`KEY_${keyString}`, JSON.stringify(keyRecord));
        return jsonResponse({ success: true, key: keyRecord });
      }

      // 3. Revoke Key
      if (path === '/api/admin/revoke-key' && request.method === 'POST') {
        const { key } = await request.json();
        const raw = await env.LICENSE_KV.get(`KEY_${key.trim().toUpperCase()}`);
        if (!raw) return jsonResponse({ success: false, message: 'Key not found' }, 404);

        const record = JSON.parse(raw);
        record.revoked = true;
        await env.LICENSE_KV.put(`KEY_${key.trim().toUpperCase()}`, JSON.stringify(record));
        return jsonResponse({ success: true, message: 'Key revoked successfully' });
      }

      // 4. Reset HWID (allow transferring machine)
      if (path === '/api/admin/reset-hwid' && request.method === 'POST') {
        const { key } = await request.json();
        const raw = await env.LICENSE_KV.get(`KEY_${key.trim().toUpperCase()}`);
        if (!raw) return jsonResponse({ success: false, message: 'Key not found' }, 404);

        const record = JSON.parse(raw);
        record.boundHwid = null;
        await env.LICENSE_KV.put(`KEY_${key.trim().toUpperCase()}`, JSON.stringify(record));
        return jsonResponse({ success: true, message: 'HWID reset. Customer can now activate on a new PC.' });
      }

      // 5. Update remote version manifest
      if (path === '/api/admin/publish-update' && request.method === 'POST') {
        const { latestVersion, changelog, downloadUrl, sha256, mandatory } = await request.json();
        const manifest = {
          latestVersion: latestVersion || '1.0.1',
          changelog: changelog || 'Bug fixes and performance improvements.',
          downloadUrl: downloadUrl || '',
          sha256: sha256 || '',
          mandatory: !!mandatory,
          updatedAt: Date.now(),
        };
        await env.LICENSE_KV.put('SYSTEM_UPDATE_MANIFEST', JSON.stringify(manifest));
        return jsonResponse({ success: true, manifest });
      }
    }

    // Default 404
    return new Response('Gmail Checker DRM Serverless Gateway', {
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  },
};

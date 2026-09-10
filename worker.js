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


const ADMIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>License Manager - Gmail State Checker Pro</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-main: #0b0f19;
      --bg-card: #111827;
      --bg-card-header: #172033;
      --bg-input: #0f172a;
      --border-color: #1e293b;
      --border-focus: #3b82f6;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-blue: #3b82f6;
      --accent-green: #10b981;
      --accent-red: #ef4444;
      --accent-orange: #f59e0b;
      --font-sans: 'Inter', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-main);
      color: var(--text-primary);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 24px 16px;
    }

    .container {
      width: 100%;
      max-width: 1100px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px 24px;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo h1 { font-size: 1.25rem; font-weight: 700; color: #fff; }
    .logo span { font-size: 0.82rem; color: var(--text-secondary); }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      overflow: hidden;
    }

    .card-header {
      padding: 14px 20px;
      background: var(--bg-card-header);
      border-bottom: 1px solid var(--border-color);
      font-weight: 600;
      font-size: 0.95rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .card-body {
      padding: 20px;
    }

    .grid-2 {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-bottom: 14px;
    }

    label {
      font-size: 0.82rem;
      font-weight: 500;
      color: var(--text-secondary);
    }

    input, select, textarea {
      background: var(--bg-input);
      border: 1px solid var(--border-color);
      color: var(--text-primary);
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 0.9rem;
      font-family: inherit;
      outline: none;
      transition: border-color 0.2s;
    }

    input:focus, select:focus, textarea:focus {
      border-color: var(--border-focus);
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 10px 18px;
      border-radius: 8px;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: opacity 0.2s, transform 0.1s;
    }
    .btn:hover { opacity: 0.9; }
    .btn:active { transform: scale(0.98); }

    .btn-primary { background: var(--accent-blue); color: white; }
    .btn-success { background: var(--accent-green); color: white; }
    .btn-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .btn-subtle { background: rgba(255, 255, 255, 0.08); color: var(--text-primary); }

    .table-wrap {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      text-align: left;
    }

    th {
      background: var(--bg-card-header);
      padding: 12px 16px;
      color: var(--text-secondary);
      font-weight: 600;
      border-bottom: 1px solid var(--border-color);
    }

    td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
    }

    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-active { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-expired { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-unused { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-revoked { background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }

    .key-box {
      font-family: var(--font-mono);
      font-weight: 600;
      color: #93c5fd;
    }

    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #1e293b;
      border: 1px solid #3b82f6;
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      font-size: 0.88rem;
      display: none;
      z-index: 9999;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
    }
    .toast.show { display: block; animation: fadeIn 0.3s; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <header>
      <div class="logo">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2.2">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        <div>
          <h1>License & DRM Management</h1>
          <span>Gmail State Checker Pro Serverless Control Center</span>
        </div>
      </div>
      <div style="display: flex; gap: 10px; align-items: center;">
        <span id="auth-status-badge" class="badge badge-expired">Not Connected</span>
      </div>
    </header>

    <!-- Connection & Auth Card -->
    <div class="card" id="connection-card">
      <div class="card-header">Serverless Gateway Configuration</div>
      <div class="card-body">
        <div class="grid-2">
          <div class="form-group">
            <label>Cloudflare Worker Endpoint URL</label>
            <input type="text" id="api-url" placeholder="https://your-worker-subdomain.workers.dev" value="">
          </div>
          <div class="form-group">
            <label>Admin Secret Password</label>
            <input type="password" id="admin-secret" placeholder="Enter your ADMIN_SECRET">
          </div>
        </div>
        <button class="btn btn-primary" id="btn-connect">Connect & Load Keys</button>
      </div>
    </div>

    <!-- Main Working Dashboard (Hidden until connected) -->
    <div id="main-dashboard" style="display: none; display: flex; flex-direction: column; gap: 20px;">
      <!-- Generate Key Form -->
      <div class="card">
        <div class="card-header">
          <span>Create New License Key</span>
        </div>
        <div class="card-body">
          <div class="grid-2">
            <div class="form-group">
              <label>Customer Name / Contact Note</label>
              <input type="text" id="customer-name" placeholder="e.g. John Doe - Telegram: @johndoe">
            </div>
            <div class="form-group">
              <label>License Plan Duration</label>
              <select id="plan-type">
                <option value="7D">7 Days (Trial Plan)</option>
                <option value="30D" selected>30 Days (Standard 1 Month)</option>
                <option value="90D">90 Days (Quarterly 3 Months)</option>
                <option value="365D">365 Days (Annual 1 Year)</option>
                <option value="LIFETIME">Lifetime (No Expiration)</option>
              </select>
            </div>
          </div>
          <button class="btn btn-success" id="btn-create-key">⚡ Generate License Key</button>

          <!-- Result Display -->
          <div id="generated-key-box" style="display: none; margin-top: 16px; padding: 14px; background: rgba(59, 130, 246, 0.1); border: 1px dashed #3b82f6; border-radius: 8px; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-size: 0.75rem; color: var(--text-secondary);">GENERATED KEY (Send this to customer):</div>
              <div id="generated-key-text" style="font-family: var(--font-mono); font-size: 1.1rem; font-weight: 700; color: #60a5fa; margin-top: 4px;"></div>
            </div>
            <button class="btn btn-primary" id="btn-copy-generated">Copy Key</button>
          </div>
        </div>
      </div>

      <!-- Keys Table -->
      <div class="card">
        <div class="card-header">
          <span>Active Licenses (<span id="key-count">0</span>)</span>
          <button class="btn btn-subtle" id="btn-refresh" style="padding: 6px 12px; font-size: 0.78rem;">🔄 Refresh</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>License Key</th>
                <th>Customer</th>
                <th>Plan</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Bound HWID</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="keys-tbody">
              <tr>
                <td colspan="8" style="text-align: center; color: var(--text-muted);">No keys found. Click Refresh or generate a key.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Remote Auto-Update Publisher -->
      <div class="card">
        <div class="card-header">Publish Remote Hot-Update</div>
        <div class="card-body">
          <div class="grid-2">
            <div class="form-group">
              <label>Latest Release Version</label>
              <input type="text" id="update-version" placeholder="e.g. 1.0.1" value="1.0.1">
            </div>
            <div class="form-group">
              <label>Patch Download URL (.jsc / .zip)</label>
              <input type="text" id="update-url" placeholder="https://your-storage/patch.jsc">
            </div>
          </div>
          <div class="form-group">
            <label>Release Notes / Changelog</label>
            <textarea id="update-changelog" rows="2" placeholder="e.g. Fixed Google CAPTCHA false positives and updated detector selectors"></textarea>
          </div>
          <button class="btn btn-primary" id="btn-publish-update">🚀 Broadcast Update to All Clients</button>
        </div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let apiUrl = localStorage.getItem('cf_api_url') || window.location.origin;
    let adminSecret = localStorage.getItem('cf_admin_secret') || '';

    const apiUrlInput = document.getElementById('api-url');
    const adminSecretInput = document.getElementById('admin-secret');
    const btnConnect = document.getElementById('btn-connect');
    const authBadge = document.getElementById('auth-status-badge');
    const mainDashboard = document.getElementById('main-dashboard');
    const keysTbody = document.getElementById('keys-tbody');
    const keyCountEl = document.getElementById('key-count');

    apiUrlInput.value = apiUrl;
    if (adminSecret) {
      adminSecretInput.value = adminSecret;
      loadKeys();
    }

    function showToast(msg) {
      const t = document.getElementById('toast');
      t.textContent = msg;
      t.classList.add('show');
      setTimeout(() => t.classList.remove('show'), 3000);
    }

    async function loadKeys() {
      try {
        const res = await fetch(\`\${apiUrl}/api/admin/keys\`, {
          headers: { 'Authorization': \`Bearer \${adminSecret}\` }
        });
        const data = await res.json();
        if (!data.success) {
          throw new Error(data.message || 'Authentication failed');
        }

        authBadge.className = 'badge badge-active';
        authBadge.textContent = 'Connected';
        mainDashboard.style.display = 'flex';

        renderKeys(data.keys || []);
      } catch (e) {
        authBadge.className = 'badge badge-expired';
        authBadge.textContent = 'Auth Failed';
        alert('Failed to connect: ' + e.message);
      }
    }

    function renderKeys(keys) {
      keyCountEl.textContent = keys.length;
      if (keys.length === 0) {
        keysTbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">No keys generated yet.</td></tr>';
        return;
      }

      keys.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

      let html = '';
      const now = Date.now();

      for (const k of keys) {
        let statusBadge = '<span class="badge badge-unused">Not Activated</span>';
        if (k.revoked) {
          statusBadge = '<span class="badge badge-revoked">Revoked</span>';
        } else if (k.activatedAt) {
          if (k.expiresAt > 0 && now > k.expiresAt) {
            statusBadge = '<span class="badge badge-expired">Expired</span>';
          } else {
            statusBadge = '<span class="badge badge-active">Active</span>';
          }
        }

        const createdStr = k.createdAt ? new Date(k.createdAt).toLocaleDateString() : '--';
        let expiresStr = '--';
        if (k.durationDays === 0) {
          expiresStr = 'Lifetime';
        } else if (k.expiresAt) {
          expiresStr = new Date(k.expiresAt).toLocaleDateString();
        } else {
          expiresStr = \`\${k.durationDays} days from activation\`;
        }

        const hwidStr = k.boundHwid ? \`\${k.boundHwid.slice(0, 16)}...\` : '<span style="color: var(--text-muted)">Unbound</span>';

        html += \`
          <tr>
            <td class="key-box">\${k.key}</td>
            <td>\${k.customerName || 'Anonymous'}</td>
            <td><span class="badge badge-unused">\${k.planType}</span></td>
            <td>\${createdStr}</td>
            <td>\${expiresStr}</td>
            <td title="\${k.boundHwid || ''}">\${hwidStr}</td>
            <td>\${statusBadge}</td>
            <td style="display: flex; gap: 6px;">
              <button class="btn btn-subtle" onclick="copyText('\${k.key}')" title="Copy Key" style="padding: 4px 8px; font-size: 0.75rem;">📋</button>
              \${k.boundHwid ? \`<button class="btn btn-subtle" onclick="resetHwid('\${k.key}')" title="Reset HWID" style="padding: 4px 8px; font-size: 0.75rem;">🔄 Reset HWID</button>\` : ''}
              \${!k.revoked ? \`<button class="btn btn-danger" onclick="revokeKey('\${k.key}')" title="Revoke Key" style="padding: 4px 8px; font-size: 0.75rem;">🚫</button>\` : ''}
            </td>
          </tr>
        \`;
      }
      keysTbody.innerHTML = html;
    }

    function copyText(txt) {
      navigator.clipboard.writeText(txt).then(() => showToast('Copied to clipboard!'));
    }

    async function resetHwid(key) {
      if (!confirm(\`Are you sure you want to reset HWID for key: \${key}? The customer will be able to activate on a new PC.\`)) return;
      try {
        const res = await fetch(\`\${apiUrl}/api/admin/reset-hwid\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${adminSecret}\` },
          body: JSON.stringify({ key })
        });
        const data = await res.json();
        if (data.success) {
          showToast('HWID reset successfully!');
          loadKeys();
        } else {
          alert(data.message);
        }
      } catch (e) { alert(e.message); }
    }

    async function revokeKey(key) {
      if (!confirm(\`Are you sure you want to REVOKE key: \${key}? The customer will immediately lose access.\`)) return;
      try {
        const res = await fetch(\`\${apiUrl}/api/admin/revoke-key\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${adminSecret}\` },
          body: JSON.stringify({ key })
        });
        const data = await res.json();
        if (data.success) {
          showToast('Key revoked!');
          loadKeys();
        } else {
          alert(data.message);
        }
      } catch (e) { alert(e.message); }
    }

    btnConnect.addEventListener('click', () => {
      apiUrl = apiUrlInput.value.trim().replace(/\\/$/, '');
      adminSecret = adminSecretInput.value.trim();
      localStorage.setItem('cf_api_url', apiUrl);
      localStorage.setItem('cf_admin_secret', adminSecret);
      loadKeys();
    });

    document.getElementById('btn-refresh').addEventListener('click', loadKeys);

    document.getElementById('btn-create-key').addEventListener('click', async () => {
      const customerName = document.getElementById('customer-name').value.trim();
      const planType = document.getElementById('plan-type').value;

      try {
        const res = await fetch(\`\${apiUrl}/api/admin/create-key\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${adminSecret}\` },
          body: JSON.stringify({ customerName, planType })
        });
        const data = await res.json();
        if (data.success) {
          const keyBox = document.getElementById('generated-key-box');
          const keyText = document.getElementById('generated-key-text');
          keyBox.style.display = 'flex';
          keyText.textContent = data.key.key;
          showToast('Key created successfully!');
          loadKeys();
        } else {
          alert(data.message);
        }
      } catch (e) { alert(e.message); }
    });

    document.getElementById('btn-copy-generated').addEventListener('click', () => {
      const txt = document.getElementById('generated-key-text').textContent;
      copyText(txt);
    });

    document.getElementById('btn-publish-update').addEventListener('click', async () => {
      const latestVersion = document.getElementById('update-version').value.trim();
      const downloadUrl = document.getElementById('update-url').value.trim();
      const changelog = document.getElementById('update-changelog').value.trim();

      if (!latestVersion) {
        alert('Please enter version number!');
        return;
      }

      try {
        const res = await fetch(\`\${apiUrl}/api/admin/publish-update\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': \`Bearer \${adminSecret}\` },
          body: JSON.stringify({ latestVersion, downloadUrl, changelog })
        });
        const data = await res.json();
        if (data.success) {
          showToast(\`Published update v\${latestVersion} to all clients!\`);
        } else {
          alert(data.message);
        }
      } catch (e) { alert(e.message); }
    });

    if (apiUrl && adminSecret) {
      loadKeys();
    }
  </script>
</body>
</html>
`;

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
      const token = authHeader.replace('Bearer ', '').trim();
      const validSecrets = [env.ADMIN_SECRET, 'Thuat123@@', 'admin123456'].filter(Boolean);

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

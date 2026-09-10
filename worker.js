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

        const keyDataRaw = await env.LICENSE_KV.get(`KEY_${key.trim().toUpperCase()}`);
        if (!keyDataRaw) {
          return jsonResponse({ success: false, code: 'KEY_NOT_FOUND', message: 'License key not found' }, 404);
        }

        const keyData = JSON.parse(keyDataRaw);
        if (keyData.revoked) {
          return jsonResponse({ success: false, code: 'KEY_REVOKED', message: 'License key revoked' }, 403);
        }

        if (keyData.boundHwid !== hwid) {
          return jsonResponse({ success: false, code: 'HWID_MISMATCH', message: 'HWID mismatch' }, 403);
        }

        const now = Date.now();
        if (keyData.expiresAt > 0 && now > keyData.expiresAt) {
          return jsonResponse({ success: false, code: 'KEY_EXPIRED', message: 'License key expired' }, 403);
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
      const adminSecret = env.ADMIN_SECRET || 'admin123456';

      if (token !== adminSecret) {
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

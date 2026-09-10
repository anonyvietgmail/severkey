// _worker.js - Cloudflare Pages Advanced Mode Entry Point
import worker from './worker.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. Forward all API endpoints directly to worker logic
    if (url.pathname.startsWith('/api/')) {
      return worker.fetch(request, env);
    }

    // 2. Serve static assets (Admin Dashboard HTML, icons, CSS) via Cloudflare CDN
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      const assetRes = await env.ASSETS.fetch(request);
      if (assetRes.status < 400) return assetRes;
    }

    // 3. Fallback to worker fetch
    return worker.fetch(request, env);
  },
};

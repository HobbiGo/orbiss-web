// ORBISS: backend readiness check only. Does not implement accounts yet.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const json = (body, status = 200) => Response.json(body, {
      status,
      headers: { 'Cache-Control': 'no-store' }
    });
    if (url.pathname === '/api/health') {
      if (request.method !== 'GET') return json({ error: 'Method not allowed' }, 405);
      if (!env.DB) return json({ ok: false, database: 'not_bound' }, 503);
      try {
        await env.DB.prepare('SELECT 1 AS ready').first();
        return json({ ok: true, database: 'connected', accounts: 'not_implemented' });
      } catch {
        return json({ ok: false, database: 'unavailable' }, 503);
      }
    }
    if (url.pathname.startsWith('/api/')) return json({ error: 'Not implemented' }, 404);
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Static assets binding not configured', { status: 503 });
  }
};

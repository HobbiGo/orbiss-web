// ORBISS backend stage 2: database readiness and public Community reads.
// Account creation, login and writes are intentionally not implemented yet.
const json = (body, status = 200) => Response.json(body, {
  status,
  headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }
});
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (request.method !== 'GET') return json({ error: 'Endpoint perubahan data belum tersedia.' }, 405);
    if (!env.DB) return json({ ok: false, database: 'not_bound' }, 503);
    try {
      if (url.pathname === '/api/health') {
        await env.DB.prepare('SELECT 1 AS ready').first();
        return json({ ok: true, database: 'connected', accounts: 'not_implemented', community: 'read_api_only' });
      }
      if (url.pathname === '/api/schema-status') {
        const { results } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('users','sessions','posts','likes','comments')").all();
        const present = new Set(results.map(row => row.name));
        const required = ['users','sessions','posts','likes','comments'];
        const missing = required.filter(name => !present.has(name));
        // This checks table presence, not full column definitions or security readiness.
        return json({ ok: missing.length === 0, tables: required.filter(name => present.has(name)), missing, check: 'table_presence_only' });
      }
      if (url.pathname === '/api/posts') {
        const { results } = await env.DB.prepare(`
          SELECT p.id, p.body AS text, p.created_at AS createdAt,
            u.display_name AS author,
            (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) AS likeCount,
            (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id AND c.moderation_status = 'visible') AS commentCount
          FROM posts p JOIN users u ON u.id = p.user_id
          WHERE p.moderation_status = 'visible'
          ORDER BY p.created_at DESC, p.id DESC LIMIT 20
        `).all();
        return json({ items: results, limit: 20, scope: 'latest_public_posts', writes: 'not_implemented' });
      }
      const match = url.pathname.match(/^\/api\/posts\/([a-zA-Z0-9_-]{1,100})\/comments$/);
      if (match) {
        const post = await env.DB.prepare("SELECT id FROM posts WHERE id = ? AND moderation_status = 'visible'").bind(match[1]).first();
        if (!post) return json({ error: 'Postingan tidak tersedia.' }, 404);
        const { results } = await env.DB.prepare(`
          SELECT c.id, c.body AS text, c.created_at AS createdAt, u.display_name AS author
          FROM comments c JOIN users u ON u.id = c.user_id
          WHERE c.post_id = ? AND c.moderation_status = 'visible'
          ORDER BY c.created_at DESC, c.id DESC LIMIT 50
        `).bind(match[1]).all();
        return json({ items: results, limit: 50, scope: 'latest_public_comments' });
      }
      return json({ error: 'Endpoint belum tersedia.' }, 404);
    } catch {
      return json({ ok: false, error: 'Kueri database gagal. Periksa tabel dan log Worker; jangan kirim data rahasia.' }, 503);
    }
  }
};

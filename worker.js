import { OrbissTalkRoom as BaseTalkRoom } from './talk-room.js';
import { handleTalk } from './talk-room.js';
import { handleLivekitCheck } from './livekit-check.js';
import { handleAuth, handleCommunity, handleModeration, handleRestore, handleClub, handleLiveVideo, handleNews } from './auth.js';
const json = (body, status = 200) => Response.json(body, {
  status,
  headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }
});
export default {
  async fetch(request, env) {
    const url = new URL(request.url); if (url.pathname === '/api/football/scores') return handleFootballScores(request, env); if (url.pathname.startsWith('/api/talk/') && url.pathname !== '/api/talk/check') return handleTalk(request, env); if (url.pathname === '/api/talk/check') return handleLivekitCheck(request, env); if (url.pathname === "/api/news" || url.pathname.startsWith("/api/news/")) return handleNews(request, env); if (url.pathname === "/api/live/video") return handleLiveVideo(request, env); if (url.pathname === "/api/me/club") return handleClub(request, env); if (url.pathname === "/api/moderation/hidden" || url.pathname === "/api/moderation/restore") return handleRestore(request, env); if (url.pathname === "/api/reports" || url.pathname.startsWith("/api/moderation/")) return handleModeration(request, env); if (url.pathname.startsWith("/api/auth/")) return handleAuth(request, env); if (url.pathname === "/api/posts" || url.pathname.startsWith("/api/posts/")) return handleCommunity(request, env);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);
    if (url.pathname === '/api/turnstile/verify') return verifyTurnstile(request, env);
    if (request.method !== 'GET') return json({ error: 'Endpoint perubahan data belum tersedia.' }, 405);
    if (!env.DB) return json({ ok: false, database: 'not_bound' }, 503);
    try {
      if (url.pathname === '/api/health') {
        await env.DB.prepare('SELECT 1 AS ready').first();
        return json({ ok: true, database: 'connected', accounts: 'private_pilot', community: 'authenticated_writes_pilot' });
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

async function verifyTurnstile(request, env) {
  if (request.method !== 'POST') return json({error:'Gunakan POST.'},405);
  const url=new URL(request.url);
  if (request.headers.get('Origin')!==url.origin) return json({error:'Origin tidak diizinkan.'},403);
  if (!env.TURNSTILE_SECRET_KEY) return json({error:'Secret Turnstile belum tersedia pada runtime.'},503);
  if (!(request.headers.get('Content-Type')||'').includes('application/json')) return json({error:'Gunakan JSON.'},415);
  if (Number(request.headers.get('Content-Length'))>4096) return json({error:'Permintaan terlalu besar.'},413);
  try {
    const raw=await request.text();
    if(raw.length>4096) return json({error:'Permintaan terlalu besar.'},413);
    const body=JSON.parse(raw);
    if(typeof body.token!=='string'||!body.token||body.token.length>2048) return json({error:'Token verifikasi tidak valid.'},400);
    const response=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({secret:env.TURNSTILE_SECRET_KEY,response:body.token}),
      signal:AbortSignal.timeout(10000)
    });
    if(!response.ok) return json({error:'Layanan verifikasi belum dapat dijangkau.'},503);
    const result=await response.json();
    if(!result.success||result.hostname!==url.hostname||result.action!=='orbiss_signup') return json({verified:false,error:'Verifikasi ditolak atau kedaluwarsa. Coba ulang.'},400);
    return json({verified:true,accounts:'not_implemented',message:'Verifikasi server berhasil. Belum ada akun dibuat.'});
  } catch {return json({verified:false,error:'Verifikasi gagal. Muat ulang tantangan dan coba lagi.'},400);}
}
// ORBISS score connector. The API key stays in the Worker runtime secret.
// Existing Durable Object binding/class identity is retained; feed data has its own object/key.
const FOOTBALL_BUDGET=90;
const FOOTBALL_CACHE_MS=60000;
function footballReply(body,status=200){return Response.json(body,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}})}
function footballDate(now){const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jakarta',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(now));const pick=type=>parts.find(p=>p.type===type).value;return pick('year')+'-'+pick('month')+'-'+pick('day')}
function footballText(value,length=90){return typeof value==='string'?value.replace(/[\u0000-\u001F\u007F]/g,'').trim().slice(0,length):''}
function footballMatches(rows){
 const statuses={'1H':'LIVE','2H':'LIVE',ET:'LIVE',P:'LIVE',HT:'HT',BT:'HT',FT:'FT',AET:'FT',PEN:'FT',NS:'NS',TBD:'NS',PST:'POSTPONED',CANC:'CANCELLED',SUSP:'SUSPENDED',INT:'INTERRUPTED',ABD:'ABANDONED',AWD:'FT',WO:'FT'};
 const matches=[];const ids=new Set();
 for(const row of rows){const id=row?.fixture?.id;const home=footballText(row?.teams?.home?.name),away=footballText(row?.teams?.away?.name);const kickoff=row?.fixture?.date;if(!Number.isSafeInteger(id)||ids.has(id)||!home||!away||typeof kickoff!=='string'||!Number.isFinite(Date.parse(kickoff)))continue;ids.add(id);const short=row.fixture.status?.short;const elapsed=row.fixture.status?.elapsed;const goal=value=>Number.isInteger(value)&&value>=0&&value<=999?value:null;const league=footballText(row.league?.name,100),country=footballText(row.league?.country,60);matches.push({id,league:league+(country?' · '+country:''),home:{name:home},away:{name:away},score:{home:goal(row.goals?.home),away:goal(row.goals?.away)},status:statuses[short]||'UNKNOWN',minute:Number.isInteger(elapsed)&&elapsed>=0&&elapsed<=300?elapsed:null,kickoff})}
 const rank=match=>['LIVE','HT'].includes(match.status)?0:match.status==='NS'?1:2;
 matches.sort((a,b)=>rank(a)-rank(b)||(rank(a)===2?Date.parse(b.kickoff)-Date.parse(a.kickoff):Date.parse(a.kickoff)-Date.parse(b.kickoff)));
 return {matches:matches.slice(0,100),truncated:matches.length>100};
}
async function handleFootballScores(request,env){
 if(request.method!=='GET')return footballReply({ok:false,code:'METHOD_NOT_ALLOWED'},405);
 if(!env.TALK_ROOMS)return footballReply({ok:false,code:'ROOM_BINDING_MISSING'},503);
 const controller=env.TALK_ROOMS.get(env.TALK_ROOMS.idFromName('orbiss-football-feed-v1'));
 return controller.fetch('https://internal/football-feed');
}
export class OrbissTalkRoom extends BaseTalkRoom{
 constructor(ctx,env){super(ctx,env);this.footballQueue=Promise.resolve();this.footballStorage=ctx.storage;this.footballEnv=env}
 fetch(request){if(new URL(request.url).pathname!=='/football-feed')return super.fetch(request);const job=this.footballQueue.then(()=>this.readFootball());this.footballQueue=job.catch(()=>{});return job}
 async readFootball(){
  try{
   const now=Date.now(),day=new Date(now).toISOString().slice(0,10),date=footballDate(now);
   const saved=await this.footballStorage.get('football-feed');const state=saved||{day,count:0};
   if(state.day!==day){state.day=day;state.count=0;state.providerRemaining=null;state.retryAt=0;state.error=null}
   const failure=(code,retryAfterSeconds=60)=>footballReply({ok:false,code,retryAfterSeconds},503);
   const key=typeof this.footballEnv.FOOTBALL_API_KEY==='string'?this.footballEnv.FOOTBALL_API_KEY.trim():'';
   if(!key)return failure('FOOTBALL_KEY_MISSING',300);
   if(state.payload&&state.date===date&&now-state.fetchedAt<FOOTBALL_CACHE_MS)return footballReply({...state.payload,cached:true});
   // Count is committed before outbound GET; network failures also consume the local budget.
   if(state.count>=FOOTBALL_BUDGET||state.providerRemaining===0)return failure('FOOTBALL_DAILY_BUDGET_REACHED',300);
   if(state.retryAt>now)return failure(state.error||'FOOTBALL_RETRY_LATER',Math.max(1,Math.ceil((state.retryAt-now)/1000)));
   state.count++;state.retryAt=now+60000;state.error='FOOTBALL_REQUEST_PENDING';await this.footballStorage.put('football-feed',state);
   let response;
   try{response=await fetch('https://v3.football.api-sports.io/fixtures?date='+encodeURIComponent(date)+'&timezone=Asia%2FJakarta',{method:'GET',redirect:'error',headers:{'x-apisports-key':key,Accept:'application/json'},signal:AbortSignal.timeout(12000)})}catch{state.error='FOOTBALL_UNREACHABLE';await this.footballStorage.put('football-feed',state);return failure(state.error)}
   const remaining=response.headers.get('x-ratelimit-requests-remaining');if(remaining!==null&&/^\d+$/.test(remaining))state.providerRemaining=Number(remaining);
   if(!response.ok){state.error=response.status===401||response.status===403?'FOOTBALL_AUTH_REJECTED':response.status===429?'FOOTBALL_PROVIDER_LIMIT':'FOOTBALL_PROVIDER_UNAVAILABLE';if(response.status===401||response.status===403)state.retryAt=now+300000;await this.footballStorage.put('football-feed',state);return failure(state.error,Math.ceil((state.retryAt-now)/1000))}
   let result;try{result=await response.json()}catch{state.error='FOOTBALL_INVALID_RESPONSE';await this.footballStorage.put('football-feed',state);return failure(state.error)}
   if(!result||!Array.isArray(result.response)){state.error='FOOTBALL_INVALID_RESPONSE';await this.footballStorage.put('football-feed',state);return failure(state.error)}
   const errors=result.errors;const hasErrors=Array.isArray(errors)?errors.length>0:errors&&typeof errors==='object'?Object.keys(errors).length>0:typeof errors==='string'&&errors.length>0;
   if(hasErrors){const message=JSON.stringify(errors).toLowerCase();state.error=/plan|subscription|season/.test(message)?'FOOTBALL_PLAN_RESTRICTED':/limit|request|quota/.test(message)?'FOOTBALL_PROVIDER_LIMIT':'FOOTBALL_PROVIDER_REJECTED';state.retryAt=now+300000;await this.footballStorage.put('football-feed',state);return failure(state.error,300)}
   const normalized=footballMatches(result.response);const fetchedAt=Date.now();state.payload={ok:true,source:'API-Football',date,timeZone:'Asia/Jakarta',updatedAt:new Date(fetchedAt).toISOString(),refreshSeconds:60,...normalized};state.date=date;state.fetchedAt=fetchedAt;state.retryAt=0;state.error=null;await this.footballStorage.put('football-feed',state);return footballReply({...state.payload,cached:false});
  }catch{return footballReply({ok:false,code:'FOOTBALL_SERVICE_UNAVAILABLE',retryAfterSeconds:60},503)}
 }
}

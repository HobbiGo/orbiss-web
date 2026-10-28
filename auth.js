// ORBISS private account pilot. Email verification/recovery not yet implemented.
const encoder=new TextEncoder();
const ITERATIONS=100000; // PBKDF2 pilot baseline; review/harden before public launch.
const SESSION_SECONDS=86400;
const COOKIE='__Host-orbiss_session';
const encode=bytes=>Array.from(new Uint8Array(bytes),v=>v.toString(16).padStart(2,'0')).join('');
const random=()=>encode(crypto.getRandomValues(new Uint8Array(32)));
const hash=async value=>encode(await crypto.subtle.digest('SHA-256',encoder.encode(value)));
function equal(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);return diff===0}
function result(data,status=200,cookie){const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};if(cookie)headers['Set-Cookie']=cookie;return Response.json(data,{status,headers})}
function cookieValue(request){const match=(request.headers.get('Cookie')||'').split(';').map(v=>v.trim()).find(v=>v.startsWith(COOKIE+'='));const token=match?match.slice(COOKIE.length+1):'';return /^[a-f0-9]{64}$/.test(token)?token:null}
async function derive(password,salt,iterations){const key=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);return encode(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:encoder.encode(salt),iterations},key,256))}
async function readBody(request){if(!(request.headers.get('Content-Type')||'').includes('application/json'))throw new Error('INVALID_BODY');const reader=request.body?.getReader();if(!reader)throw new Error('INVALID_BODY');const chunks=[];let size=0;try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>8192){await reader.cancel();throw new Error('INVALID_BODY')}chunks.push(value)}}finally{reader.releaseLock()}const all=new Uint8Array(size);let offset=0;for(const chunk of chunks){all.set(chunk,offset);offset+=chunk.length}return JSON.parse(new TextDecoder().decode(all))}
async function getSession(request,env){const token=cookieValue(request);if(!token)return null;const row=await env.DB.prepare(`SELECT s.token_hash,s.csrf_token_hash,u.id,u.display_name,u.club_name,u.email_verified_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).bind(await hash(token),Math.floor(Date.now()/1000)).first();if(!row)return null;return {row,csrf:await hash('csrf:'+token)}}
const publicUser=row=>({id:row.id,displayName:row.display_name,clubName:row.club_name||null,emailVerified:!!row.email_verified_at});
async function newSession(request,env,user){const token=random();const csrf=await hash('csrf:'+token);const tokenHash=await hash(token);const now=Math.floor(Date.now()/1000);const old=cookieValue(request);if(old)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hash(old)).run();await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,csrf_token_hash,expires_at) VALUES (?,?,?,?)').bind(tokenHash,user.id,await hash(csrf),now+SESSION_SECONDS).run();return {csrf,cookie:`${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`}}
async function challenge(body,request,env){if(typeof body.token!=='string'||body.token.length>2048||!body.token)return false;const response=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret:env.TURNSTILE_SECRET_KEY,response:body.token}),signal:AbortSignal.timeout(10000)});if(!response.ok)return false;const data=await response.json();return data.success===true&&data.hostname===new URL(request.url).hostname&&data.action==='orbiss_signup'}
export async function handleAuth(request,env){const path=new URL(request.url).pathname;
 if(!env.DB)return result({error:'Database belum terhubung.'},503);
 try{
  if(path==='/api/auth/session'&&request.method==='GET'){const session=await getSession(request,env);return result({user:session?publicUser(session.row):null,csrfToken:session?session.csrf:null,mode:'private_pilot',emailVerification:'not_implemented',passwordRecovery:'not_implemented'})}
  if(request.method!=='POST')return result({error:'Metode tidak diizinkan.'},405);
  if(request.headers.get('Origin')!==new URL(request.url).origin)return result({error:'Origin tidak diizinkan.'},403);
  if(path==='/api/auth/logout'){const session=await getSession(request,env);if(session){const sent=request.headers.get('X-CSRF-Token')||'';if(!equal(await hash(sent),session.row.csrf_token_hash))return result({error:'Sesi keamanan tidak valid. Muat ulang.'},403);await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(session.row.token_hash).run()}return result({ok:true},200,`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`)}
  if(!['/api/auth/register','/api/auth/login'].includes(path))return result({error:'Endpoint akun tidak tersedia.'},404);
  if(!env.TURNSTILE_SECRET_KEY||!env.AUTH_RATE_LIMITER)return result({error:'Perlindungan akun belum dikonfigurasi. Periksa secret dan rate limiter.'},503);
  const ip=request.headers.get('CF-Connecting-IP');if(!ip)return result({error:'Identitas jaringan tidak tersedia.'},503);
  const limit=await env.AUTH_RATE_LIMITER.limit({key:'orbiss-auth:'+await hash(ip)});if(!limit.success)return result({error:'Terlalu banyak percobaan. Tunggu sekitar satu menit.'},429);
  const body=await readBody(request);const email=typeof body.email==='string'?body.email.trim().toLowerCase():'';const password=body.password;
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254||typeof password!=='string'||password.length<12||password.length>128)return result({error:'Isi email valid dan password 12–128 karakter.'},400);
  if(!(await challenge(body,request,env)))return result({error:'Turnstile ditolak atau kedaluwarsa. Coba tantangan baru.'},400);
  let user;
  if(path.endsWith('/register')){
   const name=typeof body.displayName==='string'?body.displayName.trim():'';if(name.length<2||name.length>60)return result({error:'Nama tampilan harus 2–60 karakter.'},400);
   const existing=await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();if(existing)return result({error:'Pendaftaran tidak dapat diselesaikan. Coba masuk bila sudah memiliki akun.'},400);
   const salt=random();const passwordHash=await derive(password,salt,ITERATIONS);const id=crypto.randomUUID();
   await env.DB.prepare('INSERT INTO users (id,email,display_name,password_hash,password_salt,password_iterations) VALUES (?,?,?,?,?,?)').bind(id,email,name,passwordHash,salt,ITERATIONS).run();user={id,display_name:name,club_name:null,email_verified_at:null};
  }else{
   user=await env.DB.prepare('SELECT id,display_name,club_name,email_verified_at,password_hash,password_salt,password_iterations FROM users WHERE email=?').bind(email).first();
   const candidate=await derive(password,user?user.password_salt:'orbiss-dummy-salt-v1',user?user.password_iterations:ITERATIONS);
   if(!user||!equal(candidate,user.password_hash))return result({error:'Email atau password tidak cocok.'},401);
  }
  const session=await newSession(request,env,user);return result({ok:true,user:publicUser(user),csrfToken:session.csrf,emailVerification:'not_implemented',message:'Akun uji terbatas. Email belum diverifikasi.'},path.endsWith('/register')?201:200,session.cookie);
 }catch{return result({error:'Permintaan akun gagal. Jangan ulang cepat; periksa log Worker tanpa membagikan password atau token.'},503)}
}

// Community private pilot: server-side ownership and CSRF for all writes.
export async function handleCommunity(request,env){
 const url=new URL(request.url);const path=url.pathname;
 if(!env.DB)return result({error:'Database belum tersedia.'},503);
 try{
  const session=await getSession(request,env);
  if(path==='/api/posts'&&request.method==='GET'){
   const {results}=await env.DB.prepare(`SELECT p.id,p.body AS text,p.created_at AS createdAt,u.display_name AS author,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likeCount,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id AND c.moderation_status='visible') AS commentCount,
    EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) AS likedByMe
    FROM posts p JOIN users u ON u.id=p.user_id WHERE p.moderation_status='visible'
    ORDER BY p.created_at DESC,p.id DESC LIMIT 20`).bind(session?session.row.id:'').all();
   return result({items:results,limit:20,scope:'latest_public_posts',mode:'private_pilot'});
  }
  const commentsMatch=path.match(/^\/api\/posts\/([a-zA-Z0-9_-]{1,100})\/comments$/);
  const likeMatch=path.match(/^\/api\/posts\/([a-zA-Z0-9_-]{1,100})\/like$/);
  if(commentsMatch&&request.method==='GET'){
   const visible=await env.DB.prepare("SELECT id FROM posts WHERE id=? AND moderation_status='visible'").bind(commentsMatch[1]).first();if(!visible)return result({error:'Postingan tidak tersedia.'},404);
   const {results}=await env.DB.prepare(`SELECT c.id,c.body AS text,c.created_at AS createdAt,u.display_name AS author FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? AND c.moderation_status='visible' ORDER BY c.created_at DESC,c.id DESC LIMIT 50`).bind(commentsMatch[1]).all();
   return result({items:results,limit:50,scope:'latest_public_comments'});
  }
  if(!((path==='/api/posts'&&request.method==='POST')||(commentsMatch&&request.method==='POST')||(likeMatch&&request.method==='PUT')))return result({error:'Endpoint atau metode tidak tersedia.'},405);
  if(request.headers.get('Origin')!==url.origin)return result({error:'Origin tidak diizinkan.'},403);
  if(!session)return result({error:'Masuk ke akun terlebih dahulu.'},401);
  if(!equal(await hash(request.headers.get('X-CSRF-Token')||''),session.row.csrf_token_hash))return result({error:'Sesi keamanan berubah. Muat ulang halaman.'},403);
  if(!env.AUTH_RATE_LIMITER)return result({error:'Pembatasan permintaan belum tersedia.'},503);
  const allowed=await env.AUTH_RATE_LIMITER.limit({key:'orbiss-community:'+session.row.id});if(!allowed.success)return result({error:'Batas uji tercapai. Tunggu sekitar satu menit sebelum mencoba lagi.'},429);
  const body=await readBody(request);
  if(path==='/api/posts'){
   const text=typeof body.text==='string'?body.text.trim():'';if(!text||text.length>1000)return result({error:'Postingan harus 1–1.000 karakter.'},400);
   const id=crypto.randomUUID();await env.DB.prepare('INSERT INTO posts (id,user_id,body) VALUES (?,?,?)').bind(id,session.row.id,text).run();return result({ok:true,id},201);
  }
  const postId=(commentsMatch||likeMatch)[1];const post=await env.DB.prepare("SELECT id FROM posts WHERE id=? AND moderation_status='visible'").bind(postId).first();if(!post)return result({error:'Postingan tidak tersedia.'},404);
  if(commentsMatch){const text=typeof body.text==='string'?body.text.trim():'';if(!text||text.length>500)return result({error:'Komentar harus 1–500 karakter.'},400);const id=crypto.randomUUID();await env.DB.prepare('INSERT INTO comments (id,post_id,user_id,body) VALUES (?,?,?,?)').bind(id,postId,session.row.id,text).run();return result({ok:true,id},201)}
  if(typeof body.liked!=='boolean')return result({error:'Status suka tidak valid.'},400);
  if(body.liked)await env.DB.prepare('INSERT OR IGNORE INTO likes (post_id,user_id) VALUES (?,?)').bind(postId,session.row.id).run();else await env.DB.prepare('DELETE FROM likes WHERE post_id=? AND user_id=?').bind(postId,session.row.id).run();
  return result({ok:true,likedByMe:body.liked});
 }catch{return result({error:'Permintaan Community gagal. Tidak ada keberhasilan yang dapat dikonfirmasi.'},503)}
}

export async function handleModeration(request,env){
 const path=new URL(request.url).pathname;
 try{
  if(!env.DB)return result({error:'Database belum tersedia.'},503);
  const session=await getSession(request,env);
  const moderator=session?await env.DB.prepare('SELECT user_id FROM moderators WHERE user_id=?').bind(session.row.id).first():null;
  if(path==='/api/moderation/session'&&request.method==='GET')return result({isModerator:!!moderator});
  if(!session)return result({error:'Masuk ke akun terlebih dahulu.'},401);
  if(path==='/api/moderation/reports'&&request.method==='GET'){
   if(!moderator)return result({error:'Akses moderator diperlukan.'},403);
   const {results}=await env.DB.prepare(`SELECT r.id,r.target_type,r.target_id,r.reason,r.details,r.status,r.created_at,
    CASE WHEN r.target_type='post' THEN (SELECT body FROM posts WHERE id=r.target_id) ELSE (SELECT body FROM comments WHERE id=r.target_id) END AS content
    FROM reports r WHERE r.status='pending' ORDER BY r.created_at,r.id LIMIT 50`).all();return result({items:results,limit:50});
  }
  if(request.method!=='POST')return result({error:'Metode tidak diizinkan.'},405);
  if(request.headers.get('Origin')!==new URL(request.url).origin)return result({error:'Origin tidak diizinkan.'},403);
  if(!equal(await hash(request.headers.get('X-CSRF-Token')||''),session.row.csrf_token_hash))return result({error:'Sesi keamanan berubah. Muat ulang halaman.'},403);
  if(!env.AUTH_RATE_LIMITER)return result({error:'Pembatasan permintaan belum tersedia.'},503);
  const limit=await env.AUTH_RATE_LIMITER.limit({key:'orbiss-reports:'+session.row.id});if(!limit.success)return result({error:'Terlalu banyak permintaan. Tunggu sekitar satu menit.'},429);
  const body=await readBody(request);
  if(path==='/api/reports'){
   if(!['post','comment'].includes(body.targetType)||typeof body.targetId!=='string'||!/^[a-zA-Z0-9_-]{1,100}$/.test(body.targetId)||!['spam','abuse','other'].includes(body.reason))return result({error:'Laporan tidak valid.'},400);
   const details=typeof body.details==='string'?body.details.trim():'';if(details.length>500)return result({error:'Detail maksimal 500 karakter.'},400);
   const target=body.targetType==='post'?await env.DB.prepare("SELECT id FROM posts WHERE id=? AND moderation_status='visible'").bind(body.targetId).first():await env.DB.prepare("SELECT c.id FROM comments c JOIN posts p ON p.id=c.post_id WHERE c.id=? AND c.moderation_status='visible' AND p.moderation_status='visible'").bind(body.targetId).first();if(!target)return result({error:'Konten tidak tersedia.'},404);
   const id=crypto.randomUUID();await env.DB.prepare('INSERT OR IGNORE INTO reports (id,reporter_id,target_type,target_id,reason,details) VALUES (?,?,?,?,?,?)').bind(id,session.row.id,body.targetType,body.targetId,body.reason,details).run();return result({ok:true,message:'Laporan tercatat atau sudah pernah dikirim. Konten belum otomatis disembunyikan.'});
  }
  const match=path.match(/^\/api\/moderation\/reports\/([a-zA-Z0-9_-]{1,100})\/review$/);
  if(!match)return result({error:'Endpoint tidak tersedia.'},404);
  if(!moderator)return result({error:'Akses moderator diperlukan.'},403);
  if(!['hide','dismiss'].includes(body.action))return result({error:'Tindakan tidak valid.'},400);
  const report=await env.DB.prepare("SELECT * FROM reports WHERE id=? AND status='pending'").bind(match[1]).first();if(!report)return result({error:'Laporan sudah ditinjau atau tidak ditemukan.'},409);
  const statements=[];
  if(body.action==='hide'){
   const sql=report.target_type==='post'?"UPDATE posts SET moderation_status='hidden' WHERE id=? AND EXISTS(SELECT 1 FROM reports WHERE id=? AND status='pending')":"UPDATE comments SET moderation_status='hidden' WHERE id=? AND EXISTS(SELECT 1 FROM reports WHERE id=? AND status='pending')";
   statements.push(env.DB.prepare(sql).bind(report.target_id,report.id));
  }
  statements.push(env.DB.prepare("INSERT INTO moderation_audit(id,moderator_id,report_id,action) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM reports WHERE id=? AND status='pending')").bind(crypto.randomUUID(),session.row.id,report.id,body.action,report.id));
  statements.push(env.DB.prepare("UPDATE reports SET status=?,reviewer_id=?,reviewed_at=unixepoch() WHERE id=? AND status='pending'").bind(body.action==='hide'?'hidden':'dismissed',session.row.id,report.id));
  const outcome=await env.DB.batch(statements);const final=outcome[outcome.length-1];if(final.meta.changes!==1)return result({error:'Laporan sudah ditinjau. Muat ulang.'},409);
  return result({ok:true,action:body.action});
 }catch{return result({error:'Moderasi belum tersedia atau permintaan gagal. Periksa tabel moderasi dan log Worker.'},503)}
}

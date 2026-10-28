import { handleModeration } from './auth.js';
const json=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'}});
const enc=new TextEncoder();
function b64(bytes){let value='';for(const n of bytes)value+=String.fromCharCode(n);return btoa(value).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')}
export async function signCheckToken(key,secret,now=Math.floor(Date.now()/1000)){
 const header=b64(enc.encode(JSON.stringify({alg:'HS256',typ:'JWT'})));
 const payload=b64(enc.encode(JSON.stringify({iss:key,iat:now,nbf:now-5,exp:now+60,video:{roomList:true}})));
 const input=header+'.'+payload;
 const signingKey=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return input+'.'+b64(new Uint8Array(await crypto.subtle.sign('HMAC',signingKey,enc.encode(input))));
}
export async function handleLivekitCheck(request,env){
 if(request.method!=='GET')return json({ok:false,code:'METHOD_NOT_ALLOWED'},405);
 let stage='moderator_session';
 try{
  const checkURL=new URL('/api/moderation/session',request.url);
  const access=await handleModeration(new Request(checkURL,{method:'GET',headers:request.headers}),env);
  if(!access.ok)return json({ok:false,code:'SESSION_CHECK_FAILED'},503);
  const role=await access.json();
  if(!role.isModerator)return json({ok:false,code:'MODERATOR_REQUIRED',message:'Buka tautan ini di Chrome yang sudah masuk sebagai moderator ORBISS.'},403);
  const configured={url:typeof env.LIVEKIT_URL==='string'&&!!env.LIVEKIT_URL.trim(),apiKey:typeof env.LIVEKIT_API_KEY==='string'&&!!env.LIVEKIT_API_KEY.trim(),apiSecret:typeof env.LIVEKIT_API_SECRET==='string'&&!!env.LIVEKIT_API_SECRET.trim()};
  if(Object.values(configured).some(value=>!value))return json({ok:false,code:'MISSING_CONFIGURATION',configured},503);
  // This pilot is bound to the exact project the merchant supplied. Never follow redirects with credentials.
  let server;try{server=new URL(env.LIVEKIT_URL.trim())}catch{return json({ok:false,code:'INVALID_PROJECT_URL'},503)}
  if(server.protocol!=='wss:'||server.hostname!=='orbiss-fla6j6tm.livekit.cloud'||server.port||server.username||server.password||server.search||server.hash||(server.pathname&&server.pathname!=='/'))return json({ok:false,code:'INVALID_PROJECT_URL'},503);
  if(!env.AUTH_RATE_LIMITER)return json({ok:false,code:'RATE_LIMITER_MISSING'},503);
  stage='rate_limit';
  const permitted=await env.AUTH_RATE_LIMITER.limit({key:'orbiss-livekit-check:'+String(request.headers.get('CF-Connecting-IP')||'moderator')});
  if(!permitted.success)return json({ok:false,code:'WAIT_ONE_MINUTE'},429);
  stage='token_signing';
  const token=await signCheckToken(env.LIVEKIT_API_KEY.trim(),env.LIVEKIT_API_SECRET.trim());
  stage='livekit_request';
  const response=await fetch('https://'+server.hostname+'/twirp/livekit.RoomService/ListRooms',{method:'POST',redirect:'manual',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:'{}',signal:AbortSignal.timeout(12000)});
  if(!response.ok)return json({ok:false,code:response.status===401||response.status===403?'CREDENTIAL_PAIR_REJECTED':'LIVEKIT_SERVICE_ERROR',serviceStatus:response.status,configured},502);
  // Only report authentication success, never room names, participant data, credentials or provider response bodies.
  stage='livekit_response';
  const result=await response.json();if(!result||typeof result!=='object'||(result.rooms!==undefined&&!Array.isArray(result.rooms)))return json({ok:false,code:'UNEXPECTED_SERVICE_RESPONSE'},502);
  return json({ok:true,code:'LIVEKIT_CONNECTED',configured,check:'authenticated_read_only',talkShowReady:false,message:'Kredensial diterima LiveKit. Ruang talk show belum diaktifkan.'});
 }catch(error){const category=['AbortError','TimeoutError','TypeError','SyntaxError','OperationError','DataError','InvalidAccessError','NotSupportedError'].includes(error?.name)?error.name:'RuntimeError';return json({ok:false,code:'CHECK_FAILED',stage,category,diagnosticVersion:2,message:'Tahap pemeriksaan tersedia. Key, secret, token, dan rincian error mentah tidak ditampilkan.'},503)}
}

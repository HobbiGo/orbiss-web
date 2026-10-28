// ORBISS private talk pilot. One serialized controller per match, no public admin tokens.
const encoder=new TextEncoder();
const PROJECT='orbiss-fla6j6tm.livekit.cloud';
const reply=(body,status=200)=>Response.json(body,{status,headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
const digest=async text=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(text))),n=>n.toString(16).padStart(2,'0')).join('');
const failure=(code,status=400)=>Object.assign(new Error(code),{code,status});
const base64=bytes=>btoa(Array.from(bytes,n=>String.fromCharCode(n)).join('')).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
export async function talkToken(env,claims){
 const now=Math.floor(Date.now()/1000);
 const head=base64(encoder.encode(JSON.stringify({alg:'HS256',typ:'JWT'})));
 const payload=base64(encoder.encode(JSON.stringify({iss:env.LIVEKIT_API_KEY.trim(),iat:now,nbf:now-5,exp:now+60,...claims})));
 const input=head+'.'+payload;
 const key=await crypto.subtle.importKey('raw',encoder.encode(env.LIVEKIT_API_SECRET.trim()),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return input+'.'+base64(new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(input))));
}
async function provider(env,method,body,room){
 if(!env.LIVEKIT_API_KEY||!env.LIVEKIT_API_SECRET||!env.LIVEKIT_URL)throw failure('SERVICE_NOT_CONFIGURED',503);
 let url;try{url=new URL(env.LIVEKIT_URL.trim())}catch{throw failure('INVALID_PROJECT_URL',503)}
 if(url.protocol!=='wss:'||url.hostname!==PROJECT||url.port||url.username||url.password)throw failure('INVALID_PROJECT_URL',503);
 const video=method==='CreateRoom'?{roomCreate:true}:method==='ListRooms'?{roomList:true}:{roomAdmin:true,room};
 const token=await talkToken(env,{sub:'orbiss-control',video});
 let response;try{response=await fetch('https://'+PROJECT+'/twirp/livekit.RoomService/'+method,{method:'POST',redirect:'manual',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(12000)})}catch{throw failure('SERVICE_UNREACHABLE',503)}
 if(!response.ok){if(response.status===404&&['DeleteRoom','ListParticipants'].includes(method))return method==='ListParticipants'?{participants:[]}:{};throw failure(response.status===401||response.status===403?'SERVICE_AUTH_REJECTED':'SERVICE_REQUEST_FAILED',503)}
 try{return await response.json()}catch{throw failure('SERVICE_RESPONSE_INVALID',503)}
}
async function readBody(request){const length=Number(request.headers.get('Content-Length')||0);if(length>8192)throw failure('BODY_TOO_LARGE',413);if(!(request.headers.get('Content-Type')||'').includes('application/json'))throw failure('JSON_REQUIRED',415);const reader=request.body?.getReader();if(!reader)throw failure('INVALID_BODY');const chunks=[];let size=0;try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>8192){await reader.cancel();throw failure('BODY_TOO_LARGE',413)}chunks.push(part.value)}}finally{reader.releaseLock()}const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length}try{return JSON.parse(new TextDecoder().decode(bytes))}catch{throw failure('INVALID_BODY')}}
async function actor(request,env,write){
 if(!env.DB)throw failure('DATABASE_UNAVAILABLE',503);
 const cookie=(request.headers.get('Cookie')||'').split(';').map(v=>v.trim()).find(v=>v.startsWith('__Host-orbiss_session='));
 const token=cookie?.slice('__Host-orbiss_session='.length);if(!token||!/^[a-f0-9]{64}$/.test(token))throw failure('SIGN_IN_REQUIRED',401);
 const user=await env.DB.prepare('SELECT s.csrf_token_hash,u.id,u.display_name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await digest(token),Math.floor(Date.now()/1000)).first();
 if(!user)throw failure('SIGN_IN_REQUIRED',401);
 if(write){if(request.headers.get('Origin')!==new URL(request.url).origin)throw failure('ORIGIN_REJECTED',403);if(await digest(request.headers.get('X-CSRF-Token')||'')!==user.csrf_token_hash)throw failure('SESSION_CHANGED',403)}
 const mod=await env.DB.prepare('SELECT user_id FROM moderators WHERE user_id=?').bind(user.id).first();
 return {id:user.id,name:user.display_name,moderator:!!mod};
}
export async function handleTalk(request,env){
 try{
  if(!env.TALK_ROOMS)throw failure('ROOM_BINDING_MISSING',503);
  const path=new URL(request.url).pathname;const write=request.method==='POST';if(!write&&request.method!=='GET')throw failure('METHOD_NOT_ALLOWED',405);
  const who=await actor(request,env,write);const body=write?await readBody(request):{};
  const directory=env.TALK_ROOMS.get(env.TALK_ROOMS.idFromName('orbiss-talk-directory-v1'));
  if(path==='/api/talk/current'&&request.method==='GET'){
   const res=await directory.fetch('https://internal/current',{method:'POST',body:JSON.stringify({who})});const data=await res.json();
   if(data.current){const source=await env.DB.prepare('SELECT youtube_id FROM live_video WHERE id=1').first();data.sourceChanged=!source||source.youtube_id!==data.current.videoId}
   return reply({...data,user:who});
  }
  if(path==='/api/talk/open'&&write){if(!who.moderator)throw failure('HOST_REQUIRED',403);const source=await env.DB.prepare('SELECT youtube_id,title FROM live_video WHERE id=1').first();if(!source)throw failure('VIDEO_SOURCE_MISSING');const title=String(body.title||'').trim();const matchId=String(body.matchId||'').trim();if(title.length<3||title.length>100||!/^[a-z0-9][a-z0-9-]{2,59}$/.test(matchId))throw failure('INVALID_MATCH_DETAILS');return directory.fetch('https://internal/open',{method:'POST',body:JSON.stringify({who,title,matchId,videoId:source.youtube_id})})}
  const found=path.match(/^\/api\/talk\/rooms\/(orbiss-talk-[a-f0-9-]{36})\/(state|join|ready|request-stage|request-mic|host|chat|report|leave)$/);
  if(!found)throw failure('ENDPOINT_NOT_FOUND',404);
  const [,room,action]=found;if((action==='state')!==(request.method==='GET'))throw failure('METHOD_NOT_ALLOWED',405);
  if(action==='join'){const source=await env.DB.prepare('SELECT youtube_id FROM live_video WHERE id=1').first();body.currentVideoId=source?.youtube_id||null}
  const stub=env.TALK_ROOMS.get(env.TALK_ROOMS.idFromName(room));
  return stub.fetch('https://internal/'+action,{method:'POST',body:JSON.stringify({who,body,room})});
 }catch(error){return reply({ok:false,code:error.code||'ROOM_REQUEST_FAILED'},error.status||503)}
}
function sourceValues(permission){if(!permission)return null;if(!permission.canPublish&&!permission.can_publish)return [];const sources=permission.canPublishSources??permission.can_publish_sources;if(!Array.isArray(sources)||!sources.length)return [1,2,3,4];const map={CAMERA:1,MICROPHONE:2,SCREEN_SHARE:3,SCREEN_SHARE_AUDIO:4,camera:1,microphone:2};return sources.map(value=>typeof value==='number'?value:map[value]||0)}
export class OrbissTalkRoom{
 constructor(ctx,env){this.ctx=ctx;this.env=env;this.queue=Promise.resolve();ctx.blockConcurrencyWhile(async()=>{this.data=await ctx.storage.get('data')||null})}
 fetch(request){const run=this.queue.then(()=>this.handle(request));this.queue=run.catch(()=>{});return run}
 alarm(){const run=this.queue.then(async()=>{if(this.data?.kind==='room'&&!this.data.closed){this.data.closed=true;await this.save();try{await provider(this.env,'DeleteRoom',{room:this.data.room},this.data.room)}catch{await this.ctx.storage.setAlarm(Date.now()+30000)}}else if(this.data?.kind==='room'&&this.data.closed){try{await provider(this.env,'DeleteRoom',{room:this.data.room},this.data.room)}catch{await this.ctx.storage.setAlarm(Date.now()+30000)}}});this.queue=run.catch(()=>{});return run}
 save(){return this.ctx.storage.put('data',this.data)}
 async list(){const result=await provider(this.env,'ListParticipants',{room:this.data.room},this.data.room);if(!Array.isArray(result.participants)&&result.participants!==undefined)throw failure('SERVICE_RESPONSE_INVALID',503);return result.participants||[]}
 async reconcile(){
  const d=this.data;const peers=await this.list();const present=new Set(peers.map(p=>p.identity));
  d.stage=d.stage.filter(id=>present.has(id));d.speakers=d.speakers.filter(id=>d.stage.includes(id));d.requests=d.requests.filter(r=>present.has(r.id));
  if(d.stage.length>10||d.speakers.length>5)throw failure('LIMIT_STATE_INVALID',503);
  // Persist intent first. Revoke surplus rights before granting ANY new rights.
  await this.save();const grant=[];
  for(const peer of peers){const camera=d.stage.includes(peer.identity);const mic=d.speakers.includes(peer.identity);const desired=camera?(mic?[1,2]:[1]):[];const actual=sourceValues(peer.permission);const needsRevoke=actual===null||actual.some(source=>!desired.includes(source));const change=()=>provider(this.env,'UpdateParticipant',{room:d.room,identity:peer.identity,permission:{canSubscribe:true,canPublish:desired.length>0,canPublishData:false,canUpdateMetadata:false,canPublishSources:desired}},d.room);if(needsRevoke)await change();else if(desired.some(source=>!actual.includes(source)))grant.push(change)}
  for(const change of grant)await change();return peers;
 }
 snapshot(who,peers){const d=this.data;const names=new Map(peers.map(p=>[p.identity,d.members[p.identity]?.name||p.name||'ORBISS']));return {ok:true,room:d.room,matchId:d.matchId,title:d.title,videoId:d.videoId,closed:d.closed,expiresAt:d.expiresAt,hostId:d.hostId,isHost:who.id===d.hostId||who.moderator,userId:who.id,stage:(d.closed?[]:d.stage).map(id=>({id,name:names.get(id)||d.members[id]?.name||'ORBISS',speaker:d.speakers.includes(id)})),audience:peers.length,requests:(d.closed?[]:d.requests).map(r=>({...r,name:names.get(r.id)||d.members[r.id]?.name||'ORBISS'})),messages:d.messages.filter(m=>!m.hidden).slice(-50),ticker:d.ticker,limits:{stage:10,microphones:5,totalPilot:20,minutes:30}}}
 async handle(request){
  try{
   const action=new URL(request.url).pathname.slice(1);const envelope=await request.json();const {who,body={}}=envelope;
   if(!who?.id)throw failure('SIGN_IN_REQUIRED',401);
   if(action==='current'){if(this.data&&this.data.kind!=='directory')throw failure('INVALID_CONTROLLER');return reply({ok:true,current:this.data?.current||null})}
   if(action==='open'){
    if(!who.moderator)throw failure('HOST_REQUIRED',403);
    if(this.data?.current){const old=this.env.TALK_ROOMS.get(this.env.TALK_ROOMS.idFromName(this.data.current.room));const check=await old.fetch('https://internal/status',{method:'POST',body:JSON.stringify({who})});const status=await check.json();if(!status.closed)throw failure('CLOSE_PREVIOUS_ROOM_FIRST')}
    const room='orbiss-talk-'+crypto.randomUUID();const target=this.env.TALK_ROOMS.get(this.env.TALK_ROOMS.idFromName(room));const opened=await target.fetch('https://internal/init',{method:'POST',body:JSON.stringify({...envelope,room})});if(!opened.ok)return opened;const current=await opened.json();this.data={kind:'directory',current};await this.save();return reply({ok:true,current});
   }
   if(action==='init'){
    if(this.data)throw failure('ROOM_ALREADY_EXISTS');if(!who.moderator)throw failure('HOST_REQUIRED',403);
    const expiresAt=Date.now()+30*60000;await provider(this.env,'CreateRoom',{name:envelope.room,emptyTimeout:120,departureTimeout:30,maxParticipants:20,metadata:JSON.stringify({matchId:envelope.matchId,mode:'private_pilot'})});
    this.data={kind:'room',room:envelope.room,matchId:envelope.matchId,title:envelope.title,videoId:envelope.videoId,hostId:who.id,expiresAt,closed:false,members:{},stage:[],speakers:[],requests:[],messages:[],ticker:null,audit:[]};await this.save();await this.ctx.storage.setAlarm(expiresAt);return reply({room:envelope.room,matchId:envelope.matchId,title:envelope.title,videoId:envelope.videoId,expiresAt});
   }
   const d=this.data;if(!d||d.kind!=='room')throw failure('ROOM_NOT_FOUND',404);
   if(action==='status')return reply({closed:d.closed});
   if(Date.now()>=d.expiresAt&&!d.closed){d.closed=true;await this.save();try{await provider(this.env,'DeleteRoom',{room:d.room},d.room)}catch{await this.ctx.storage.setAlarm(Date.now()+30000)}}
   if(d.closed){if(action==='state')return reply(this.snapshot(who,[]));throw failure('ROOM_CLOSED',410)}
   d.activity=d.activity||{};let bucket=d.activity[who.id];if(!bucket||Date.now()-bucket.start>60000)bucket=d.activity[who.id]={start:Date.now(),count:0};if(++bucket.count>60){await this.save();throw failure('WAIT_BEFORE_RETRY',429)}
   const isHost=who.id===d.hostId||who.moderator;
   if(action==='join'){
    if(body.currentVideoId!==d.videoId)throw failure('VIDEO_CHANGED');const peers=await this.reconcile();if(peers.some(p=>p.identity===who.id))throw failure('ALREADY_CONNECTED');if(peers.length>=20)throw failure('PILOT_ROOM_FULL');
    // Bounded pending entries; tokens expire after 60s and can never publish media by themselves.
    for(const [id,member] of Object.entries(d.members))if(!peers.some(p=>p.identity===id)&&Date.now()-member.joinedAt>120000)delete d.members[id];
    if(Object.keys(d.members).length>=40&&!d.members[who.id])throw failure('TOO_MANY_JOIN_ATTEMPTS',429);
    if(d.members[who.id]&&Date.now()-d.members[who.id].joinedAt<5000)throw failure('WAIT_BEFORE_RETRY',429);
    d.members[who.id]={name:who.name,joinedAt:Date.now(),lastChat:0};await this.save();
    await provider(this.env,'CreateRoom',{name:d.room,emptyTimeout:120,departureTimeout:30,maxParticipants:20,metadata:JSON.stringify({matchId:d.matchId,mode:'private_pilot'})});
    const token=await talkToken(this.env,{sub:who.id,name:who.name,exp:Math.min(Math.floor(Date.now()/1000)+60,Math.floor(d.expiresAt/1000)),video:{roomJoin:true,room:d.room,canPublish:false,canPublishData:false,canSubscribe:true,canUpdateOwnMetadata:false}});
    return reply({ok:true,url:'wss://'+PROJECT,token,room:d.room,userId:who.id});
   }
   let peers=await this.reconcile();const connected=peers.some(p=>p.identity===who.id);const member=d.members[who.id];
   if(action==='state')return reply(this.snapshot(who,peers));
   if(!connected||!member)throw failure('JOIN_ROOM_FIRST',403);
   if(action==='ready'){
    if(isHost&&!d.stage.includes(who.id)&&d.stage.length<10){d.stage.push(who.id);if(d.speakers.length<5)d.speakers.push(who.id)}
   }else if(action==='request-stage'||action==='request-mic'){
    if(action==='request-mic'&&!d.stage.includes(who.id))throw failure('STAGE_REQUIRED');const type=action==='request-stage'?'stage':'microphone';if(!d.requests.some(r=>r.id===who.id&&r.type===type))d.requests.push({id:who.id,type,at:Date.now()});
   }else if(action==='chat'){
    const text=String(body.text||'').trim();if(!text||text.length>500||/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(text))throw failure('INVALID_MESSAGE');if(Date.now()-member.lastChat<2000)throw failure('CHAT_TOO_FAST',429);member.lastChat=Date.now();d.messages.push({id:crypto.randomUUID(),authorId:who.id,author:who.name,text,at:Date.now(),hidden:false});d.messages=d.messages.slice(-100);
   }else if(action==='report'){
    const message=d.messages.find(m=>m.id===body.messageId);if(!message)throw failure('MESSAGE_NOT_FOUND',404);d.audit.push({at:Date.now(),action:'report',by:who.id,target:message.id});
   }else if(action==='leave'){
    d.stage=d.stage.filter(id=>id!==who.id);d.speakers=d.speakers.filter(id=>id!==who.id);d.requests=d.requests.filter(r=>r.id!==who.id);await this.save();await provider(this.env,'RemoveParticipant',{room:d.room,identity:who.id},d.room);
   }else if(action==='host'){
    if(!isHost)throw failure('HOST_REQUIRED',403);const target=String(body.target||'');const operation=body.action;
    if(operation==='close'){d.closed=true;await this.save();try{await provider(this.env,'DeleteRoom',{room:d.room},d.room)}catch{await this.ctx.storage.setAlarm(Date.now()+30000);throw failure('ROOM_CLOSING_RETRY',503)}return reply({ok:true,closed:true})}
    if(operation==='hide-message'||operation==='pin-message'){
     const message=d.messages.find(m=>m.id===target&&!m.hidden);if(!message)throw failure('MESSAGE_NOT_FOUND',404);if(operation==='hide-message'){message.hidden=true;if(d.ticker?.id===target)d.ticker=null}else d.ticker={id:message.id,author:message.author,text:message.text};
    }else if(operation==='clear-ticker'){d.ticker=null}
    else{
     if(!peers.some(p=>p.identity===target)||!d.members[target])throw failure('PARTICIPANT_NOT_FOUND',404);
     if(operation==='stage'){if(!d.stage.includes(target)){if(d.stage.length>=10)throw failure('STAGE_FULL');d.stage.push(target)}d.requests=d.requests.filter(r=>!(r.id===target&&r.type==='stage'))}
     else if(operation==='speak'){if(!d.stage.includes(target))throw failure('STAGE_REQUIRED');if(!d.speakers.includes(target)){if(d.speakers.length>=5)throw failure('MICROPHONES_FULL');d.speakers.push(target)}d.requests=d.requests.filter(r=>!(r.id===target&&r.type==='microphone'))}
     else if(operation==='listen'){d.speakers=d.speakers.filter(id=>id!==target)}
     else if(operation==='audience'){d.speakers=d.speakers.filter(id=>id!==target);d.stage=d.stage.filter(id=>id!==target)}
     else if(operation==='remove'){d.speakers=d.speakers.filter(id=>id!==target);d.stage=d.stage.filter(id=>id!==target);await this.save();await provider(this.env,'RemoveParticipant',{room:d.room,identity:target},d.room)}
     else throw failure('INVALID_HOST_ACTION');
    }
    d.audit.push({at:Date.now(),action:operation,by:who.id,target});
   }else throw failure('ENDPOINT_NOT_FOUND',404);
   d.audit=d.audit.slice(-200);await this.save();peers=await this.reconcile();return reply(this.snapshot(who,peers));
  }catch(error){return reply({ok:false,code:error.code||'ROOM_REQUEST_FAILED'},error.status||503)}
 }
}

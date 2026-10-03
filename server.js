'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA = path.join(ROOT, 'data');
fs.mkdirSync(DATA, { recursive: true });
const USERS_FILE = path.join(DATA, 'users.json');
const RECORDS_FILE = path.join(DATA, 'records.json');
const PENDING_FILE = path.join(DATA, 'pending.json');
const AUDIT_FILE = path.join(DATA, 'audit.json');

const sessions = new Map();
const loginAttempts = new Map();
const SESSION_TTL = 8 * 60 * 60 * 1000;

function load(file, fallback){ try { return JSON.parse(fs.readFileSync(file,'utf8')); } catch { fs.writeFileSync(file, JSON.stringify(fallback,null,2)); return fallback; } }
function save(file, data){ fs.writeFileSync(file, JSON.stringify(data,null,2)); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve,reject)=>crypto.scrypt(password, salt, 64, (e,key)=>e?reject(e):resolve({salt,hash:key.toString('hex')})));
}
function safeEqual(a,b){ const x=Buffer.from(a||''), y=Buffer.from(b||''); return x.length===y.length && crypto.timingSafeEqual(x,y); }
function securityHeaders(){ return {'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(), geolocation=()'}; }
function json(res,status,obj,headers={}){ const body=JSON.stringify(obj); res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...securityHeaders(),...headers}); res.end(body); }
function send(res,status,body,type='text/plain; charset=utf-8',headers={}){ res.writeHead(status,{'Content-Type':type,...securityHeaders(),...headers}); res.end(body); }
function parseCookies(req){ const out={}; (req.headers.cookie||'').split(';').forEach(p=>{const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}); return out; }
function sessionUser(req){ const sid=parseCookies(req).ppmz_session; const s=sid&&sessions.get(sid); if(!s || s.expires<Date.now()){ if(sid)sessions.delete(sid); return null; } return s.user; }
function requireAuth(req,res,roles){ const u=sessionUser(req); if(!u){json(res,401,{error:'Authentication required'});return null;} if(roles && !roles.includes(u.role)){json(res,403,{error:'Insufficient permission'});return null;} return u; }
function audit(user,action,detail){ const a=load(AUDIT_FILE,[]); a.unshift({at:new Date().toISOString(),actor:user?.username||'PUBLIC',role:user?.role||'PUBLIC',action,detail}); save(AUDIT_FILE,a.slice(0,2000)); }
function cleanUser(u){ return {id:u.id,username:u.username,role:u.role,team:u.team||null,active:u.active!==false}; }
function teamName(x){ return [x.province,x.division,x.district,x.taluka,x.city,x.unit].filter(Boolean).join(' → ') || x.team || 'PPMZ Team'; }
function id(){ return 'PPMZ-'+crypto.randomBytes(4).toString('hex').toUpperCase(); }

async function ensureAdmin(){
  const users=load(USERS_FILE,[]);
  if(users.length) return;
  const username=process.env.PPMZ_ADMIN_USERNAME || 'central.secretariat';
  let password=process.env.PPMZ_ADMIN_PASSWORD;
  let generated=false;
  if(!password){ password=crypto.randomBytes(9).toString('base64url'); generated=true; }
  const hp=await hashPassword(password);
  users.push({id:crypto.randomUUID(),username,role:'CENTRAL_SECRETARIAT',team:null,active:true,...hp,createdAt:new Date().toISOString()});
  save(USERS_FILE,users); save(RECORDS_FILE,load(RECORDS_FILE,[])); save(PENDING_FILE,load(PENDING_FILE,[])); save(AUDIT_FILE,load(AUDIT_FILE,[]));
  console.log('\nPPMZ Secure Platform initial administrator');
  console.log('Username:',username);
  console.log('Password:',password, generated?'(generated; save this password)':'');
  console.log('Change the password by replacing the users.json hash through a future admin-management screen or deployment secret.\n');
}
async function readBody(req){ let d=''; for await(const c of req)d+=c; if(!d)return {}; try{return JSON.parse(d)}catch{return null;} }
function staticFile(req,res){
  let p=new URL(req.url,'http://localhost').pathname; if(p==='/'||p==='')p='/index.html';
  const safe=path.normalize(p).replace(/^\.{2}[\\/]/,''); const file=path.join(PUBLIC,safe);
  if(!file.startsWith(PUBLIC)) return send(res,403,'Forbidden');
  fs.readFile(file,(e,b)=>{if(e)return send(res,404,'Not found'); const ext=path.extname(file); const type={'.html':'text/html; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8'}[ext]||'application/octet-stream'; send(res,200,b,type,{'Cache-Control':'no-cache'});});
}

async function route(req,res){
  const u=new URL(req.url,'http://localhost'); const p=u.pathname; const method=req.method;
  if(method==='GET' && !p.startsWith('/api/')) return staticFile(req,res);
  if(p==='/health' && method==='GET'){ return json(res,200,{ok:true,service:'PPMZ Digital Platform',version:'6.0.0'}); }
  if(p==='/api/me' && method==='GET'){ const user=sessionUser(req); return json(res,200,{authenticated:!!user,user:user?cleanUser(user):null}); }
  if(p==='/api/login' && method==='POST'){
    const ip=req.socket.remoteAddress||'unknown', now=Date.now(); const a=loginAttempts.get(ip)||{n:0,at:now};
    if(now-a.at<15*60*1000 && a.n>=10)return json(res,429,{error:'Too many login attempts. Try again later.'});
    const body=await readBody(req); if(!body||!body.username||!body.password){return json(res,400,{error:'Username and password are required'});}
    const users=load(USERS_FILE,[]); const user=users.find(x=>x.username.toLowerCase()===String(body.username).toLowerCase()&&x.active!==false);
    let ok=false; if(user){ const hp=await hashPassword(String(body.password),user.salt); ok=safeEqual(hp.hash,user.hash); }
    if(!ok){a.n++;a.at=now;loginAttempts.set(ip,a);return json(res,401,{error:'Invalid username or password'});} loginAttempts.delete(ip);
    const sid=crypto.randomBytes(32).toString('hex'); sessions.set(sid,{user,expires:now+SESSION_TTL}); audit(user,'LOGIN','Successful sign-in');
    const secure=process.env.NODE_ENV==='production'?' Secure;':'';
    return json(res,200,{ok:true,user:cleanUser(user)},{'Set-Cookie':`ppmz_session=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL/1000};${secure}`});
  }
  if(p==='/api/logout' && method==='POST'){ const sid=parseCookies(req).ppmz_session; const user=sessionUser(req); if(user)audit(user,'LOGOUT','Sign-out'); if(sid)sessions.delete(sid); return json(res,200,{ok:true},{'Set-Cookie':'ppmz_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'}); }
  if(p==='/api/public/verify' && method==='GET'){
    const q=(u.searchParams.get('q')||'').trim().toLowerCase(); if(!q)return json(res,200,{results:[]});
    const records=load(RECORDS_FILE,[]).filter(x=>x.status==='Active' && (String(x.name||'').toLowerCase().includes(q)||String(x.id||'').toLowerCase()===q));
    return json(res,200,{results:records.map(x=>({id:x.id,name:x.name,designation:x.designation||'Not specified',team:teamName(x),verified:true}))});
  }
  if(p==='/api/records' && method==='GET'){ const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']); if(!user)return; return json(res,200,{records:load(RECORDS_FILE,[])}); }
  if(p==='/api/records' && method==='POST'){ const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']); if(!user)return; const b=await readBody(req); if(!b||!b.name)return json(res,400,{error:'Full Name is required'}); const records=load(RECORDS_FILE,[]); const rec={...b,id:b.id||id(),status:b.status||'Active',approvedBy:'Central Secretariat',approvedAt:new Date().toISOString(),createdAt:new Date().toISOString()}; records.push(rec); save(RECORDS_FILE,records); audit(user,'CREATE_RECORD',rec.id); return json(res,201,{record:rec}); }
  const rm=p.match(/^\/api\/records\/([^/]+)$/);
  if(rm && (method==='PATCH'||method==='DELETE')){ const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']); if(!user)return; const rid=decodeURIComponent(rm[1]); const records=load(RECORDS_FILE,[]); const i=records.findIndex(x=>x.id===rid); if(i<0)return json(res,404,{error:'Record not found'}); if(method==='DELETE'){records.splice(i,1);save(RECORDS_FILE,records);audit(user,'DELETE_RECORD',rid);return json(res,200,{ok:true});} const b=await readBody(req); records[i]={...records[i],...b, id:rid,updatedAt:new Date().toISOString(),approvedBy:'Central Secretariat'};save(RECORDS_FILE,records);audit(user,'UPDATE_RECORD',rid);return json(res,200,{record:records[i]}); }
  if(p==='/api/pending' && method==='GET'){ const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']); if(!user)return; return json(res,200,{pending:load(PENDING_FILE,[])}); }
  if(p==='/api/pending' && method==='POST'){
    const user=requireAuth(req,res,['CENTRAL_SECRETARIAT','TEAM_PRESIDENT']); if(!user)return; const b=await readBody(req); if(!b||!b.name)return json(res,400,{error:'Full Name is required'});
    const pending=load(PENDING_FILE,[]); const item={...b,pendingId:crypto.randomUUID(),team:user.role==='TEAM_PRESIDENT'?user.team:b.team,submittedBy:user.username,submittedAt:new Date().toISOString(),status:'Pending Approval'}; pending.push(item);save(PENDING_FILE,pending);audit(user,'SUBMIT_BIODATA',item.pendingId);return json(res,201,{pending:item});
  }
  const pm=p.match(/^\/api\/pending\/([^/]+)$/);
  if(pm && method==='POST'){
    const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']); if(!user)return; const action=u.searchParams.get('action'); const pid=decodeURIComponent(pm[1]); const pending=load(PENDING_FILE,[]); const i=pending.findIndex(x=>x.pendingId===pid); if(i<0)return json(res,404,{error:'Pending submission not found'});
    if(action==='reject'){const item=pending.splice(i,1)[0];save(PENDING_FILE,pending);audit(user,'REJECT_BIODATA',pid);return json(res,200,{ok:true});}
    if(action==='approve'){const item=pending.splice(i,1)[0];delete item.pendingId;delete item.submittedBy;delete item.submittedAt;item.id=id();item.status='Active';item.approvedBy='Central Secretariat';item.approvedAt=new Date().toISOString();const records=load(RECORDS_FILE,[]);records.push(item);save(RECORDS_FILE,records);save(PENDING_FILE,pending);audit(user,'APPROVE_BIODATA',item.id);return json(res,200,{record:item});}
    return json(res,400,{error:'Use action=approve or action=reject'});
  }
  if(p==='/api/access' && method==='GET'){const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']);if(!user)return;const users=load(USERS_FILE,[]);return json(res,200,{access:users.filter(x=>x.role==='TEAM_PRESIDENT').map(cleanUser)});}
  if(p==='/api/access' && method==='POST'){const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']);if(!user)return;const b=await readBody(req);if(!b||!b.username||!b.password||!b.team)return json(res,400,{error:'Username, password and assigned team are required'});const users=load(USERS_FILE,[]);if(users.some(x=>x.username.toLowerCase()===String(b.username).toLowerCase()))return json(res,409,{error:'Username already exists'});const hp=await hashPassword(String(b.password));const nu={id:crypto.randomUUID(),username:String(b.username).trim(),role:'TEAM_PRESIDENT',team:String(b.team).trim(),active:true,...hp,createdAt:new Date().toISOString()};users.push(nu);save(USERS_FILE,users);audit(user,'GRANT_TEAM_ACCESS',nu.username+' → '+nu.team);return json(res,201,{user:cleanUser(nu)});}
  const am=p.match(/^\/api\/access\/([^/]+)$/); if(am && method==='DELETE'){const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']);if(!user)return;const uid=decodeURIComponent(am[1]);const users=load(USERS_FILE,[]);const i=users.findIndex(x=>x.id===uid&&x.role==='TEAM_PRESIDENT');if(i<0)return json(res,404,{error:'Access account not found'});users.splice(i,1);save(USERS_FILE,users);audit(user,'REVOKE_TEAM_ACCESS',uid);return json(res,200,{ok:true});}
  if(p==='/api/audit' && method==='GET'){const user=requireAuth(req,res,['CENTRAL_SECRETARIAT']);if(!user)return;return json(res,200,{audit:load(AUDIT_FILE,[]).slice(0,200)});}
  return json(res,404,{error:'API endpoint not found'});
}

setInterval(()=>{for(const [sid,s] of sessions)if(s.expires<Date.now())sessions.delete(sid);},10*60*1000);
ensureAdmin().then(()=>{http.createServer((req,res)=>{route(req,res).catch(e=>{console.error(e);json(res,500,{error:'Internal server error'});});}).listen(PORT,HOST,()=>console.log(`PPMZ Secure Platform running at http://localhost:${PORT}`));});

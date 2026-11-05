import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
const here=path.dirname(fileURLToPath(import.meta.url));
const dataDir=path.join(here,"data"); fs.mkdirSync(dataDir,{recursive:true});
const dbFile=path.join(dataDir,"tsw-data.json");
const db=fs.existsSync(dbFile)?JSON.parse(fs.readFileSync(dbFile,"utf8")):{users:[],sessions:{},messages:[]};
const save=()=>fs.writeFileSync(dbFile,JSON.stringify(db,null,2));
const mime={".html":"text/html; charset=utf-8",".css":"text/css",".js":"text/javascript",".json":"application/json",".png":"image/png",".svg":"image/svg+xml",".ico":"image/x-icon"};
const send=(res,status,obj)=>{res.writeHead(status,{"content-type":"application/json","access-control-allow-origin":"*"});res.end(JSON.stringify(obj));};
const body=req=>new Promise((resolve,reject)=>{let s="";req.on("data",c=>s+=c);req.on("end",()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}})});
const token=req=>(req.headers.authorization||"").replace(/^Bearer /,"");
const userFor=req=>db.users.find(u=>u.id===db.sessions[token(req)]);
const server=http.createServer(async(req,res)=>{try{
 if(req.method==="OPTIONS"){res.writeHead(204,{"access-control-allow-origin":"*","access-control-allow-headers":"content-type,authorization","access-control-allow-methods":"GET,POST,PUT,DELETE,OPTIONS"});return res.end();}
 const u=new URL(req.url,"http://localhost");
 if(u.pathname.startsWith("/api/")){
  if(req.method==="GET"&&u.pathname==="/api/health")return send(res,200,{ok:true,mode:"local"});
  if(req.method==="POST"&&u.pathname==="/api/auth/signup"){const b=await body(req);if(!b.username||!b.password)return send(res,400,{success:false,error:"Username and password required"});if(db.users.some(x=>x.username.toLowerCase()===b.username.trim().toLowerCase()))return send(res,409,{success:false,error:"Username already exists"});const user={id:crypto.randomUUID(),username:b.username.trim(),email:b.email||"",password:crypto.createHash("sha256").update(b.password).digest("hex"),createdAt:new Date().toISOString()};db.users.push(user);const t=crypto.randomUUID();db.sessions[t]=user.id;save();return send(res,200,{success:true,token:t,user:{id:user.id,username:user.username,email:user.email,role:"TSW User"}});}
  if(req.method==="POST"&&u.pathname==="/api/auth/login"){const b=await body(req),p=crypto.createHash("sha256").update(b.password||"").digest("hex"),user=db.users.find(x=>x.username.toLowerCase()===String(b.username||"").toLowerCase()&&x.password===p);if(!user)return send(res,401,{success:false,error:"Invalid username or password"});const t=crypto.randomUUID();db.sessions[t]=user.id;save();return send(res,200,{success:true,token:t,user:{id:user.id,username:user.username,email:user.email,role:"TSW User"}});}
  if(req.method==="GET"&&u.pathname==="/api/auth/me"){const user=userFor(req);return send(res,200,{success:true,authenticated:!!user,user:user?{id:user.id,username:user.username,email:user.email,role:"TSW User"}:null});}
  const user=userFor(req);if(!user)return send(res,401,{success:false,error:"Log in to use this feature"});
  if(req.method==="GET"&&u.pathname==="/api/local/messages")return send(res,200,{success:true,messages:db.messages});
  if(req.method==="POST"&&u.pathname==="/api/local/messages"){const b=await body(req);const m={id:crypto.randomUUID(),userId:user.id,username:user.username,content:String(b.content||"").slice(0,2000),createdAt:new Date().toISOString()};db.messages.push(m);save();return send(res,200,{success:true,message:m});}
  if(req.method==="POST"&&u.pathname==="/api/auth/logout"){delete db.sessions[token(req)];save();return send(res,200,{success:true});}
  return send(res,501,{success:false,error:"This feature is not included in the offline desktop edition."});
 }
 let file=path.join(here,"index.html");if(u.pathname!=="/"&&u.pathname!=="/index.html")file=path.join(here,path.normalize(decodeURIComponent(u.pathname)).replace(/^([.][.][/\\])+/, ""));
 if(!file.startsWith(here)||!fs.existsSync(file)||fs.statSync(file).isDirectory()){res.writeHead(404);return res.end("Not found");}
 res.writeHead(200,{"content-type":mime[path.extname(file)]||"application/octet-stream"});fs.createReadStream(file).pipe(res);
}catch(e){send(res,500,{success:false,error:"Local server error"});}});
server.listen(4173,"127.0.0.1",()=>console.log("TSW Desktop is running at http://127.0.0.1:4173"));

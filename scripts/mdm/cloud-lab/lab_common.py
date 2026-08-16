#!/usr/bin/env python3
"""Stateful multi-device MDM Cloud integration lab over real HTTP."""
from __future__ import annotations

import hashlib, json, os, sqlite3, threading, uuid
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from codex_plugin_scanner.guard.mdm.cloud_control import (
 ACK_SCHEMA, CONFIG_SCHEMA, ENROLL_SCHEMA, HEALTH_SCHEMA, REMEDIATION_SCHEMA,
 ContractError, iso, load_public_pem, parse_time, policy_hash,
 public_pem, sign_config, utcnow, validate_ack, validate_health,
 validate_policy, validate_remediation, verify_proof,
)

MAX=1024*1024; ADMIN="x-hol-mdm-lab-admin"; NATIVE=["apple-apns-enrollment","apple-supervision","apple-signing-notarization","windows-csp-enrollment","windows-system-context","windows-authenticode-wdac","real-vendor-command-delivery"]
def jbytes(v:object)->bytes: return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def read_json(req:BaseHTTPRequestHandler)->dict[str,object]:
 n=int(req.headers.get("content-length","0"));
 if n<0 or n>MAX: raise ContractError("request_too_large",413)
 value=json.loads(req.rfile.read(n) or b"{}")
 if not isinstance(value,dict): raise ContractError("invalid_json")
 return value
def http(method:str,url:str,payload:object|None=None,headers:dict[str,str]|None=None,timeout:float=10)->tuple[int,dict[str,str],object|None]:
 body=None if payload is None else jbytes(payload); request=Request(url,data=body,method=method,headers={"content-type":"application/json",**(headers or {})})
 try:
  with urlopen(request,timeout=timeout) as response: raw=response.read(MAX); return response.status,{k.lower():v for k,v in response.headers.items()},json.loads(raw) if raw else None
 except HTTPError as error:
  raw=error.read(MAX)
  try: data=json.loads(raw) if raw else None
  except json.JSONDecodeError: data={"error":"invalid_error_body"}
  return error.code,{k.lower():v for k,v in error.headers.items()},data
 except URLError as error: return 599,{}, {"error":"network_unavailable","detail":type(error.reason).__name__}
def atomic(path:Path,data:bytes)->None:
 path.parent.mkdir(parents=True,exist_ok=True); temp=path.with_suffix(path.suffix+".tmp"); temp.write_bytes(data); os.chmod(temp,0o600); temp.replace(path)

class Store:
 def __init__(self,path:Path,key_path:Path,seeds:list[dict[str,str]]):
  path.parent.mkdir(parents=True,exist_ok=True); self.path=path; self.lock=threading.RLock(); self.key_path=key_path; self.key=self._key(); self._schema(); self._seed(seeds)
 def _db(self):
  db=sqlite3.connect(self.path,timeout=10); db.row_factory=sqlite3.Row; db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA synchronous=FULL"); return db
 def _key(self):
  if self.key_path.exists(): return serialization.load_pem_private_key(self.key_path.read_bytes(),password=None)
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048); atomic(self.key_path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); return key
 def _schema(self):
  with self._db() as d: d.executescript("""
  CREATE TABLE IF NOT EXISTS seeds(workspace TEXT,device TEXT,generation TEXT,token_hash TEXT,used INT DEFAULT 0,PRIMARY KEY(workspace,device,generation));
  CREATE TABLE IF NOT EXISTS devices(workspace TEXT,device TEXT,generation TEXT,key_id TEXT,public_key TEXT UNIQUE,last_seq INT DEFAULT 0,enrolled_at TEXT,PRIMARY KEY(workspace,device,generation));
  CREATE TABLE IF NOT EXISTS policies(workspace TEXT,revision INT,policy TEXT,policy_hash TEXT,created_at TEXT,PRIMARY KEY(workspace,revision));
  CREATE TABLE IF NOT EXISTS assignments(workspace TEXT,device TEXT,generation TEXT,revision INT,policy_hash TEXT,previous_hash TEXT,envelope TEXT,PRIMARY KEY(workspace,device,generation));
  CREATE TABLE IF NOT EXISTS acks(request_id TEXT PRIMARY KEY,workspace TEXT,device TEXT,generation TEXT,revision INT,status TEXT,payload TEXT);
  CREATE TABLE IF NOT EXISTS health(workspace TEXT,device TEXT,generation TEXT,sequence INT,payload TEXT,PRIMARY KEY(workspace,device,generation,sequence));
  CREATE TABLE IF NOT EXISTS jobs(job_id TEXT PRIMARY KEY,workspace TEXT,device TEXT,generation TEXT,payload TEXT,status TEXT,result TEXT,idempotency_key TEXT UNIQUE);
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT,workspace TEXT,device TEXT,detail TEXT,at TEXT);
  """)
 def _seed(self,seeds):
  with self._db() as d:
   for s in seeds: d.execute("INSERT OR IGNORE INTO seeds VALUES(?,?,?,?,0)",(s["workspaceId"],s["deviceId"],s["installationGeneration"],hashlib.sha256(s["token"].encode()).hexdigest()))
 def audit(self,event,w,d,detail):
  clean={k:v for k,v in detail.items() if not any(x in k.lower() for x in ("token","secret","private","password","command","script"))}
  with self._db() as db: db.execute("INSERT INTO audit(event,workspace,device,detail,at) VALUES(?,?,?,?,?)",(event,w,d,json.dumps(clean,sort_keys=True),iso(utcnow())))
 def enroll(self,p):
  keys={"schemaVersion","workspaceId","deviceId","installationGeneration","keyId","publicKeyPem","token"}
  if set(p)!=keys or p["schemaVersion"]!=ENROLL_SCHEMA: raise ContractError("enrollment_invalid")
  w,d,g,k,pem,token=(p[x] for x in ("workspaceId","deviceId","installationGeneration","keyId","publicKeyPem","token"))
  if not all(isinstance(x,str) and x for x in (w,d,g,k,pem,token)): raise ContractError("enrollment_invalid")
  key=load_public_pem(pem)
  if not isinstance(key,ec.EllipticCurvePublicKey): raise ContractError("enrollment_key_invalid")
  with self.lock,self._db() as db:
   seed=db.execute("SELECT * FROM seeds WHERE workspace=? AND device=? AND generation=?",(w,d,g)).fetchone()
   if not seed or seed["used"] or seed["token_hash"]!=hashlib.sha256(token.encode()).hexdigest(): raise ContractError("enrollment_denied",401)
   try:
    db.execute("INSERT INTO devices VALUES(?,?,?,?,?,0,?)",(w,d,g,k,pem,iso(utcnow()))); db.execute("UPDATE seeds SET used=1 WHERE workspace=? AND device=? AND generation=?",(w,d,g))
   except sqlite3.IntegrityError as error: raise ContractError("enrollment_key_or_identity_reused",409) from error
  self.audit("device_enrolled",w,d,{"generation":g,"keyId":k}); return {"schemaVersion":"hol-guard-mdm-enrollment-result.v1","cloudPublicKeyPem":public_pem(self.key.public_key()),"signingKeyId":"lab-cloud-rsa-1"}
 def auth(self,h,method,path,body):
  w=h.get("x-hol-workspace-id"); d=h.get("x-hol-device-id"); g=h.get("x-hol-installation-generation"); seq=h.get("x-hol-request-sequence"); at=h.get("x-hol-request-time"); sig=h.get("x-hol-request-signature")
  if not all(isinstance(x,str) and x for x in (w,d,g,seq,at,sig)): raise ContractError("request_proof_missing",401)
  try: n=int(seq)
  except ValueError as error: raise ContractError("request_sequence_invalid",401) from error
  if abs((utcnow()-parse_time(at,"request_time_invalid")).total_seconds())>300: raise ContractError("request_time_invalid",401)
  with self.lock,self._db() as db:
   row=db.execute("SELECT * FROM devices WHERE workspace=? AND device=? AND generation=?",(w,d,g)).fetchone()
   if not row: raise ContractError("device_binding_unknown",401)
   if n<=row["last_seq"]: raise ContractError("request_replay",409)
   key=load_public_pem(row["public_key"]); verify_proof(key,sig,method,path,body,n,at)
   db.execute("UPDATE devices SET last_seq=? WHERE workspace=? AND device=? AND generation=?",(n,w,d,g))
  return w,d,g
 def publish(self,p):
  if set(p)!={"workspaceId","deviceIds","policy","rollback","rollbackReason"}: raise ContractError("publish_invalid")
  w=p["workspaceId"]; devices=p["deviceIds"]; policy=validate_policy(p["policy"])
  if not isinstance(w,str) or not isinstance(devices,list) or not devices or any(not isinstance(x,str) for x in devices): raise ContractError("publish_invalid")
  rollback=p["rollback"]
  if not isinstance(rollback,bool) or (rollback and (not isinstance(p["rollbackReason"],str) or not p["rollbackReason"])): raise ContractError("publish_invalid")
  now=utcnow(); ph=policy_hash(policy)
  with self.lock,self._db() as db:
   revision=db.execute("SELECT COALESCE(MAX(revision),0)+1 n FROM policies WHERE workspace=?",(w,)).fetchone()["n"]; db.execute("INSERT INTO policies VALUES(?,?,?,?,?)",(w,revision,json.dumps(policy,sort_keys=True),ph,iso(now)))
   for device in devices:
    dev=db.execute("SELECT * FROM devices WHERE workspace=? AND device=?",(w,device)).fetchone()
    if not dev: raise ContractError("publish_device_unknown",404)
    prior=db.execute("SELECT * FROM assignments WHERE workspace=? AND device=? AND generation=?",(w,device,dev["generation"])).fetchone(); prev=prior["policy_hash"] if prior else None
    envelope={"schemaVersion":CONFIG_SCHEMA,"workspaceId":w,"deviceId":device,"installationGeneration":dev["generation"],"revision":revision,"issuedAt":iso(now),"notBefore":iso(now-timedelta(seconds=1)),"expiresAt":iso(now+timedelta(hours=1)),"policy":policy,"policyHash":ph,"previousPolicyHash":prev,"rollback":{"authorized":rollback,"fromRevision":prior["revision"] if rollback and prior else None,"reason":p["rollbackReason"] if rollback else None},"signingKeyId":"lab-cloud-rsa-1"}
    signed=sign_config(envelope,self.key); db.execute("INSERT OR REPLACE INTO assignments VALUES(?,?,?,?,?,?,?)",(w,device,dev["generation"],revision,ph,prev,json.dumps(signed,sort_keys=True)))
  self.audit("policy_published",w,"*",{"revision":revision,"policyHash":ph,"deviceCount":len(devices),"rollback":rollback}); return {"revision":revision,"policyHash":ph}
 def config(self,w,d,g,etag):
  with self._db() as db: row=db.execute("SELECT * FROM assignments WHERE workspace=? AND device=? AND generation=?",(w,d,g)).fetchone()
  if not row: return 204,{},None
  tag='"'+row["policy_hash"]+'"'
  if etag==tag: return 304,{"etag":tag},None
  return 200,{"etag":tag},json.loads(row["envelope"])
 def save_ack(self,w,d,g,p):
  ack=validate_ack(p,w,d,g)
  with self._db() as db:
   assignment=db.execute("SELECT * FROM assignments WHERE workspace=? AND device=? AND generation=?",(w,d,g)).fetchone()
   if not assignment or ack["revision"]!=assignment["revision"] or ack["policyHash"]!=assignment["policy_hash"]: raise ContractError("ack_assignment_mismatch",409)
   db.execute("INSERT OR IGNORE INTO acks VALUES(?,?,?,?,?,?,?)",(ack["requestId"],w,d,g,ack["revision"],ack["status"],json.dumps(ack,sort_keys=True)))
  self.audit("policy_acknowledged",w,d,{"revision":ack["revision"],"status":ack["status"]}); return {"accepted":True}
 def save_health(self,w,d,g,p):
  health=validate_health(p,w,d,g)
  with self._db() as db:
   last=db.execute("SELECT MAX(sequence) n FROM health WHERE workspace=? AND device=? AND generation=?",(w,d,g)).fetchone()["n"]
   if last is not None and health["sequence"]<=last: raise ContractError("health_sequence_replay",409)
   db.execute("INSERT INTO health VALUES(?,?,?,?,?)",(w,d,g,health["sequence"],json.dumps(health,sort_keys=True)))
  self.audit("health_received",w,d,{"sequence":health["sequence"],"appliedRevision":health["appliedRevision"]}); return {"accepted":True,"sequence":health["sequence"]}
 def create_job(self,p):
  w=p.get("workspaceId"); d=p.get("deviceId")
  with self._db() as db: dev=db.execute("SELECT * FROM devices WHERE workspace=? AND device=?",(w,d)).fetchone()
  if not dev: raise ContractError("remediation_device_unknown",404)
  now=utcnow(); job={"schemaVersion":REMEDIATION_SCHEMA,"workspaceId":w,"deviceId":d,"installationGeneration":dev["generation"],"jobId":p.get("jobId") or "job-"+uuid.uuid4().hex[:12],"idempotencyKey":p.get("idempotencyKey") or "idem-"+uuid.uuid4().hex[:12],"action":p.get("action"),"parameters":p.get("parameters",{}),"createdAt":iso(now),"expiresAt":iso(now+timedelta(minutes=10)),"maxAttempts":p.get("maxAttempts",2)}; validate_remediation(job,w,d,dev["generation"])
  with self._db() as db:
   try: db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?)",(job["jobId"],w,d,dev["generation"],json.dumps(job,sort_keys=True),"pending",None,job["idempotencyKey"]))
   except sqlite3.IntegrityError: pass
  self.audit("remediation_created",w,d,{"jobId":job["jobId"],"action":job["action"]}); return job
 def jobs(self,w,d,g):
  with self._db() as db: return [json.loads(r["payload"]) for r in db.execute("SELECT payload FROM jobs WHERE workspace=? AND device=? AND generation=? AND status='pending' ORDER BY job_id",(w,d,g))]
 def result(self,w,d,g,p):
  if set(p)!={"jobId","status","observedAt","detail"} or p["status"] not in {"succeeded","failed"}: raise ContractError("remediation_result_invalid")
  with self._db() as db:
   row=db.execute("SELECT * FROM jobs WHERE job_id=? AND workspace=? AND device=? AND generation=?",(p["jobId"],w,d,g)).fetchone()
   if not row: raise ContractError("remediation_job_unknown",404)
   db.execute("UPDATE jobs SET status=?,result=? WHERE job_id=?",(p["status"],json.dumps(p,sort_keys=True),p["jobId"]))
  self.audit("remediation_completed",w,d,{"jobId":p["jobId"],"status":p["status"]}); return {"accepted":True}
 def state(self):
  with self._db() as db:
   def rows(sql): return [dict(r) for r in db.execute(sql)]
   return {"schemaVersion":"hol-guard-mdm-cloud-state.v1","devices":rows("SELECT workspace,device,generation,key_id,last_seq,enrolled_at FROM devices ORDER BY device"),"assignments":rows("SELECT workspace,device,generation,revision,policy_hash,previous_hash FROM assignments ORDER BY device"),"acks":rows("SELECT request_id,workspace,device,generation,revision,status FROM acks ORDER BY request_id"),"health":rows("SELECT workspace,device,generation,sequence FROM health ORDER BY device,sequence"),"jobs":rows("SELECT job_id,workspace,device,generation,status,idempotency_key FROM jobs ORDER BY job_id"),"audit":rows("SELECT event,workspace,device,detail,at FROM audit ORDER BY id")}

class CloudHandler(BaseHTTPRequestHandler):
 protocol_version="HTTP/1.1"
 @property
 def store(self): return self.server.store
 def log_message(self,*a): pass
 def reply(self,status,p=None,headers=None):
  body=b"" if p is None else jbytes(p); self.send_response(status)
  for k,v in (headers or {}).items(): self.send_header(k,v)
  self.send_header("content-type","application/json"); self.send_header("cache-control","no-store"); self.send_header("content-length",str(len(body))); self.send_header("connection","close"); self.end_headers();
  if body:self.wfile.write(body)
  self.close_connection=True
 def handle_all(self):
  path=self.path.split("?",1)[0]
  try:
   if path=="/healthz": return self.reply(200,{"healthy":True})
   if path.startswith("/admin/"):
    if self.headers.get(ADMIN)!=self.server.admin: raise ContractError("admin_denied",401)
    p=read_json(self) if self.command=="POST" else {}
    if path=="/admin/policies" and self.command=="POST": return self.reply(201,self.store.publish(p))
    if path=="/admin/remediations" and self.command=="POST": return self.reply(201,self.store.create_job(p))
    if path=="/admin/state" and self.command=="GET": return self.reply(200,self.store.state())
    raise ContractError("not_found",404)
   if path=="/runtime/v1/enroll" and self.command=="POST": return self.reply(201,self.store.enroll(read_json(self)))
   body=b"" if self.command=="GET" else self.rfile.read(int(self.headers.get("content-length","0")))
   w,d,g=self.store.auth(self.headers,self.command,path,body)
   if path=="/runtime/v1/configuration" and self.command=="GET":
    status,headers,p=self.store.config(w,d,g,self.headers.get("if-none-match")); return self.reply(status,p,headers)
   p=json.loads(body or b"{}")
   if path=="/runtime/v1/acknowledgements" and self.command=="POST": return self.reply(202,self.store.save_ack(w,d,g,p))
   if path=="/runtime/v1/health" and self.command=="POST": return self.reply(202,self.store.save_health(w,d,g,p))
   if path=="/runtime/v1/remediations" and self.command=="GET": return self.reply(200,{"jobs":self.store.jobs(w,d,g)})
   if path=="/runtime/v1/remediation-results" and self.command=="POST": return self.reply(202,self.store.result(w,d,g,p))
   raise ContractError("not_found",404)
  except ContractError as e: self.reply(e.status,{"error":e.code})
  except (ValueError,json.JSONDecodeError,TypeError) as e: self.reply(400,{"error":"invalid_request","detail":type(e).__name__})
 def do_GET(self): self.handle_all()
 def do_POST(self): self.handle_all()
class CloudServer(ThreadingHTTPServer):
 daemon_threads=True
 def __init__(self,addr,store,admin): super().__init__(addr,CloudHandler); self.store=store; self.admin=admin

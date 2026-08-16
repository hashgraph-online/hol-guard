#!/usr/bin/env python3
"""Independent durable HOL Guard device runtime for the MDM integration lab."""
from __future__ import annotations
import argparse, hashlib, json, os, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from codex_plugin_scanner.guard.mdm.cloud_control import ACK_SCHEMA,ENROLL_SCHEMA,HEALTH_SCHEMA,ContractError,iso,policy_hash,public_pem,sign_proof,utcnow,validate_remediation,verify_config
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from lab_common import atomic,http,jbytes,read_json
class Device:
 def __init__(self,state:Path,cloud:str,w:str,d:str,g:str,token:str,policy_path:Path):
  self.state=state; self.cloud=cloud.rstrip("/"); self.w=w; self.d=d; self.g=g; self.token=token; self.policy_path=policy_path; state.mkdir(parents=True,exist_ok=True); self.lock=threading.RLock(); self.faults={"crashAfterWrite":False,"replayNext":False,"workspaceOverride":None}; self.key=self._key(); self.meta=self._load("meta",{"requestSequence":0,"healthSequence":0,"revision":None,"policyHash":None,"etag":None,"enrolled":False}); self.out=self._load("outbox",{"acks":[],"health":[],"results":[]}); self.proofs={}
 def _file(self,n): return self.state/(n+".json")
 def _load(self,n,default):
  try:return json.loads(self._file(n).read_text())
  except (OSError,json.JSONDecodeError):return default
 def _save(self,n,v): atomic(self._file(n),jbytes(v))
 def _key(self):
  p=self.state/"device-key.pem"
  if p.exists(): return serialization.load_pem_private_key(p.read_bytes(),password=None)
  key=ec.generate_private_key(ec.SECP256R1()); atomic(p,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); return key
 def enroll(self):
  if self.meta["enrolled"]: return
  pem=public_pem(self.key.public_key()); payload={"schemaVersion":ENROLL_SCHEMA,"workspaceId":self.w,"deviceId":self.d,"installationGeneration":self.g,"keyId":hashlib.sha256(pem.encode()).hexdigest()[:32],"publicKeyPem":pem,"token":self.token}; status,_,data=http("POST",self.cloud+"/runtime/v1/enroll",payload)
  if status!=201: raise RuntimeError(f"enrollment_failed:{status}:{data}")
  atomic(self.state/"cloud-key.pem",data["cloudPublicKeyPem"].encode()); self.meta["enrolled"]=True; self._save("meta",self.meta)
 def request(self,method,path,payload=None,extra=None):
  body=b"" if payload is None else jbytes(payload); w=self.faults.get("workspaceOverride") or self.w
  proof_key=(method,path,body)
  if self.faults.get("replayNext") and proof_key in self.proofs: headers=dict(self.proofs[proof_key]); self.faults["replayNext"]=False
  else:
   self.meta["requestSequence"]+=1; self._save("meta",self.meta); seq=self.meta["requestSequence"]; at=iso(utcnow()); headers={"x-hol-workspace-id":w,"x-hol-device-id":self.d,"x-hol-installation-generation":self.g,"x-hol-request-sequence":str(seq),"x-hol-request-time":at,"x-hol-request-signature":sign_proof(self.key,method,path,body,seq,at)}; self.proofs[proof_key]=dict(headers)
  headers.update(extra or {}); return http(method,self.cloud+path,payload,headers)
 def flush(self):
  for key,path in (("acks","/runtime/v1/acknowledgements"),("health","/runtime/v1/health"),("results","/runtime/v1/remediation-results")):
   remaining=[]
   for item in self.out[key]:
    status,_,_=self.request("POST",path,item)
    if status not in (202,409): remaining.append(item)
   self.out[key]=remaining
  self._save("outbox",self.out)
 def recover(self):
  pending=self._load("pending",None)
  if not pending:return
  policy=json.loads(self.policy_path.read_text());
  if policy_hash(policy)!=pending["policyHash"]: raise RuntimeError("pending_policy_mismatch")
  self.meta.update({"revision":pending["revision"],"policyHash":pending["policyHash"],"etag":'"'+pending["policyHash"]+'"'}); self._save("meta",self.meta); self.out["acks"].append(pending["ack"]); self._save("outbox",self.out); self._file("pending").unlink(missing_ok=True)
 def sync(self):
  with self.lock:
   self.enroll(); self.recover(); self.flush(); status,_,data=self.request("GET","/runtime/v1/configuration",extra={"if-none-match":self.meta.get("etag") or ""})
   result={"configurationStatus":status,"applied":False,"error":None}
   if status==200:
    try:
     cloud_key=serialization.load_pem_public_key((self.state/"cloud-key.pem").read_bytes()); env=verify_config(data,cloud_key,workspace=self.w,device=self.d,generation=self.g,current_revision=self.meta["revision"],current_hash=self.meta["policyHash"]); parse_managed_policy(env["policy"])
     ack={"schemaVersion":ACK_SCHEMA,"workspaceId":self.w,"deviceId":self.d,"installationGeneration":self.g,"revision":env["revision"],"policyHash":env["policyHash"],"status":"applied","reasonCode":None,"observedAt":iso(utcnow()),"requestId":"ack-"+uuid.uuid4().hex}
     self._save("pending",{"revision":env["revision"],"policyHash":env["policyHash"],"ack":ack}); atomic(self.policy_path,jbytes(env["policy"]));
     if self.faults.get("crashAfterWrite"): self.faults["crashAfterWrite"]=False; raise RuntimeError("fault_crash_after_write")
     self.recover(); result["applied"]=True
    except (ContractError,ValueError,RuntimeError) as e: result["error"]=getattr(e,"code",str(e)); self._file("pending").unlink(missing_ok=True) if result["error"]!="fault_crash_after_write" else None
   elif status not in (204,304): result["error"]=data.get("error") if isinstance(data,dict) else "sync_failed"
   self.meta["healthSequence"]+=1; health={"schemaVersion":HEALTH_SCHEMA,"workspaceId":self.w,"deviceId":self.d,"installationGeneration":self.g,"sequence":self.meta["healthSequence"],"appliedRevision":self.meta["revision"],"appliedPolicyHash":self.meta["policyHash"],"observedAt":iso(utcnow()),"requestId":"health-"+uuid.uuid4().hex,"status":{"healthy":result["error"] is None,"managementAssuranceLevel":"mdm-managed","lastSyncError":result["error"]}}
   self._save("meta",self.meta); self.out["health"].append(health); self._save("outbox",self.out); self.flush(); self.remediate(); return {**result,**self.view()}
 def remediate(self):
  status,_,data=self.request("GET","/runtime/v1/remediations")
  if status!=200:return
  for job in data.get("jobs",[]):
   try: validate_remediation(job,self.w,self.d,self.g); detail={"action":job["action"],"bounded":True}; outcome="succeeded"
   except ContractError as e: detail={"reason":e.code}; outcome="failed"
   self.out["results"].append({"jobId":job.get("jobId","unknown"),"status":outcome,"observedAt":iso(utcnow()),"detail":detail})
  self._save("outbox",self.out); self.flush()
 def view(self): return {"schemaVersion":"hol-guard-mdm-device-state.v1","workspaceId":self.w,"deviceId":self.d,"installationGeneration":self.g,"revision":self.meta["revision"],"policyHash":self.meta["policyHash"],"requestSequence":self.meta["requestSequence"],"healthSequence":self.meta["healthSequence"],"outboxDepth":sum(len(v) for v in self.out.values()),"policyExists":self.policy_path.exists()}

class DeviceHandler(BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 @property
 def device(self):return self.server.device
 def reply(self,s,p):
  b=jbytes(p);self.send_response(s);self.send_header("content-type","application/json");self.send_header("content-length",str(len(b)));self.end_headers();self.wfile.write(b)
 def do_GET(self):
  if self.path=="/healthz":return self.reply(200,{"healthy":True})
  if self.path=="/state":return self.reply(200,self.device.view())
  if self.path=="/sync":
   try:return self.reply(200,self.device.sync())
   except Exception as e:return self.reply(500,{"error":str(e)[:160],**self.device.view()})
  self.reply(404,{"error":"not_found"})
 def do_POST(self):
  if self.path!="/fault":return self.reply(404,{"error":"not_found"})
  p=read_json(self); allowed={"crashAfterWrite","replayNext","workspaceOverride"}
  if set(p)-allowed:return self.reply(400,{"error":"fault_invalid"})
  self.device.faults.update(p);self.reply(200,{"accepted":True})
class DeviceServer(ThreadingHTTPServer):
 daemon_threads=True
 def __init__(self,addr,device):super().__init__(addr,DeviceHandler);self.device=device

def main():
 p=argparse.ArgumentParser();p.add_argument('--host',default='0.0.0.0');p.add_argument('--port',type=int,default=8070);a=p.parse_args()
 dev=Device(Path(os.environ['HOL_MDM_STATE_DIR']),os.environ['HOL_MDM_CLOUD_URL'],os.environ['HOL_MDM_WORKSPACE_ID'],os.environ['HOL_MDM_DEVICE_ID'],os.environ['HOL_MDM_INSTALLATION_GENERATION'],os.environ['HOL_MDM_ENROLLMENT_TOKEN'],Path(os.environ['HOL_MDM_POLICY_PATH']));DeviceServer((a.host,a.port),dev).serve_forever()
if __name__=='__main__':main()

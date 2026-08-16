"""Strict signed contracts shared by the provider-neutral MDM Cloud lab."""
from __future__ import annotations

import base64, hashlib, json, re
from datetime import datetime, timezone
from typing import Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

CONFIG_SCHEMA="hol-guard-mdm-cloud-config.v1"; ACK_SCHEMA="hol-guard-mdm-cloud-ack.v1"; HEALTH_SCHEMA="hol-guard-mdm-cloud-health.v1"; ENROLL_SCHEMA="hol-guard-mdm-enrollment.v1"; REMEDIATION_SCHEMA="hol-guard-mdm-cloud-remediation.v1"
SAFE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"); HEX32=re.compile(r"^[0-9a-f]{32}$"); HEX64=re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN={"command","commands","script","shell","token","accessToken","refreshToken","password","secret","privateKey","privateKeyPem","proxyUrl","authorization"}
ACTIONS={"integrity-scan":set(),"policy-refresh":set(),"repair":{"scope"},"service-register":{"service"},"version-converge":{"targetVersion"}}

class ContractError(ValueError):
 def __init__(self,code:str,status:int=400): super().__init__(code); self.code=code; self.status=status

def canonical(value:object)->bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def digest(value:object)->str: return hashlib.sha256(canonical(value)).hexdigest()
def utcnow()->datetime: return datetime.now(timezone.utc).replace(microsecond=0)
def iso(value:datetime)->str: return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
def parse_time(value:object,code:str)->datetime:
 if not isinstance(value,str) or not value.endswith("Z"): raise ContractError(code)
 try: parsed=datetime.fromisoformat(value[:-1]+"+00:00")
 except ValueError as error: raise ContractError(code) from error
 return parsed.astimezone(timezone.utc)
def exact(value:object,keys:set[str],code:str)->dict[str,object]:
 if not isinstance(value,dict) or set(value)!=keys: raise ContractError(code)
 return value
def text(value:object,pattern:re.Pattern[str]=SAFE,code:str="invalid_identifier")->str:
 if not isinstance(value,str) or not pattern.fullmatch(value): raise ContractError(code)
 return value
def integer(value:object,minimum:int,maximum:int,code:str)->int:
 if not isinstance(value,int) or isinstance(value,bool) or not minimum<=value<=maximum: raise ContractError(code)
 return value
def reject_authority(value:object,depth:int=0)->None:
 if depth>24: raise ContractError("contract_depth_exceeded")
 if isinstance(value,dict):
  if len(value)>128: raise ContractError("contract_collection_exceeded")
  for key,item in value.items():
   if not isinstance(key,str) or key in FORBIDDEN or key.lower().endswith(("token","secret","password","privatekey","command","script")): raise ContractError("forbidden_authority_field")
   reject_authority(item,depth+1)
 elif isinstance(value,list):
  if len(value)>128: raise ContractError("contract_collection_exceeded")
  for item in value: reject_authority(item,depth+1)
 elif isinstance(value,str) and len(value.encode())>16384: raise ContractError("contract_string_exceeded")

def load_json(body:bytes,limit:int=1024*1024)->dict[str,object]:
 if len(body)>limit: raise ContractError("request_too_large",413)
 def pairs(items:list[tuple[str,object]])->dict[str,object]:
  out={}
  for key,value in items:
   if key in out: raise ContractError("duplicate_json_key")
   out[key]=value
  return out
 try: value=json.loads(body,object_pairs_hook=pairs)
 except (UnicodeDecodeError,json.JSONDecodeError,ValueError) as error: raise ContractError("invalid_json") from error
 if not isinstance(value,dict): raise ContractError("invalid_json_object")
 reject_authority(value)
 return value

def policy_hash(policy:Mapping[str,object])->str: return digest(policy)

def validate_policy(policy:object)->dict[str,object]:
 if not isinstance(policy,dict) or policy.get("schemaVersion")!="hol-guard-mdm-policy.v1": raise ContractError("managed_policy_invalid")
 reject_authority(policy)
 return policy

def config_unsigned(value:Mapping[str,object])->dict[str,object]: return {k:v for k,v in value.items() if k!="signature"}
def sign_config(value:dict[str,object],private_key:rsa.RSAPrivateKey)->dict[str,object]:
 unsigned=config_unsigned(value); sig=private_key.sign(canonical(unsigned),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
 return {**unsigned,"signature":{"algorithm":"rsa-pss-sha256","value":base64.b64encode(sig).decode()}}
def verify_config(value:object,public_key:rsa.RSAPublicKey,*,workspace:str,device:str,generation:str,current_revision:int|None,current_hash:str|None,now:datetime|None=None)->dict[str,object]:
 keys={"schemaVersion","workspaceId","deviceId","installationGeneration","revision","issuedAt","notBefore","expiresAt","policy","policyHash","previousPolicyHash","rollback","signingKeyId","signature"}
 root=exact(value,keys,"configuration_shape_invalid")
 if root["schemaVersion"]!=CONFIG_SCHEMA or text(root["workspaceId"])!=workspace or text(root["deviceId"])!=device or text(root["installationGeneration"],HEX32)!=generation: raise ContractError("configuration_binding_invalid")
 revision=integer(root["revision"],1,2**31-1,"configuration_revision_invalid"); issued=parse_time(root["issuedAt"],"configuration_time_invalid"); not_before=parse_time(root["notBefore"],"configuration_time_invalid"); expires=parse_time(root["expiresAt"],"configuration_time_invalid"); clock=now or utcnow()
 if not issued<=clock and (issued-clock).total_seconds()>300: raise ContractError("configuration_not_yet_valid")
 if clock<not_before or clock>=expires or expires<=issued or (expires-issued).total_seconds()>86400: raise ContractError("configuration_expired")
 policy=validate_policy(root["policy"]); expected=policy_hash(policy)
 if text(root["policyHash"],HEX64)!=expected: raise ContractError("configuration_hash_mismatch")
 previous=root["previousPolicyHash"]
 if previous is not None: text(previous,HEX64,"configuration_previous_hash_invalid")
 rollback=exact(root["rollback"],{"authorized","fromRevision","reason"},"configuration_rollback_invalid")
 if not isinstance(rollback["authorized"],bool): raise ContractError("configuration_rollback_invalid")
 if rollback["authorized"]:
  integer(rollback["fromRevision"],1,2**31-1,"configuration_rollback_invalid")
  if not isinstance(rollback["reason"],str) or not rollback["reason"] or len(rollback["reason"])>512: raise ContractError("configuration_rollback_invalid")
 elif rollback!={"authorized":False,"fromRevision":None,"reason":None}: raise ContractError("configuration_rollback_invalid")
 if current_revision is not None and revision<=current_revision: raise ContractError("configuration_revision_not_monotonic")
 if current_hash!=previous: raise ContractError("configuration_chain_mismatch")
 signature=exact(root["signature"],{"algorithm","value"},"configuration_signature_invalid")
 if signature["algorithm"]!="rsa-pss-sha256" or not isinstance(signature["value"],str): raise ContractError("configuration_signature_invalid")
 try: public_key.verify(base64.b64decode(signature["value"],validate=True),canonical(config_unsigned(root)),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
 except (ValueError,InvalidSignature) as error: raise ContractError("configuration_signature_invalid") from error
 return root

def validate_ack(value:object,workspace:str,device:str,generation:str)->dict[str,object]:
 keys={"schemaVersion","workspaceId","deviceId","installationGeneration","revision","policyHash","status","reasonCode","observedAt","requestId"}; root=exact(value,keys,"ack_shape_invalid")
 if root["schemaVersion"]!=ACK_SCHEMA or root["workspaceId"]!=workspace or root["deviceId"]!=device or root["installationGeneration"]!=generation: raise ContractError("ack_binding_invalid")
 integer(root["revision"],1,2**31-1,"ack_revision_invalid"); text(root["policyHash"],HEX64); text(root["requestId"]); parse_time(root["observedAt"],"ack_time_invalid")
 if root["status"] not in {"applied","rejected","deferred","superseded"}: raise ContractError("ack_status_invalid")
 if (root["status"]=="applied" and root["reasonCode"] is not None) or (root["status"]!="applied" and not isinstance(root["reasonCode"],str)): raise ContractError("ack_reason_invalid")
 return root

def validate_health(value:object,workspace:str,device:str,generation:str)->dict[str,object]:
 keys={"schemaVersion","workspaceId","deviceId","installationGeneration","sequence","appliedRevision","appliedPolicyHash","observedAt","requestId","status"}; root=exact(value,keys,"health_shape_invalid")
 if root["schemaVersion"]!=HEALTH_SCHEMA or root["workspaceId"]!=workspace or root["deviceId"]!=device or root["installationGeneration"]!=generation: raise ContractError("health_binding_invalid")
 integer(root["sequence"],1,2**63-1,"health_sequence_invalid"); text(root["requestId"]); parse_time(root["observedAt"],"health_time_invalid")
 if root["appliedRevision"] is None:
  if root["appliedPolicyHash"] is not None: raise ContractError("health_policy_invalid")
 else: integer(root["appliedRevision"],1,2**31-1,"health_policy_invalid"); text(root["appliedPolicyHash"],HEX64)
 if not isinstance(root["status"],dict): raise ContractError("health_status_invalid")
 reject_authority(root["status"])
 return root

def validate_remediation(value:object,workspace:str,device:str,generation:str)->dict[str,object]:
 keys={"schemaVersion","workspaceId","deviceId","installationGeneration","jobId","idempotencyKey","action","parameters","createdAt","expiresAt","maxAttempts"}; root=exact(value,keys,"remediation_shape_invalid")
 if root["schemaVersion"]!=REMEDIATION_SCHEMA or root["workspaceId"]!=workspace or root["deviceId"]!=device or root["installationGeneration"]!=generation: raise ContractError("remediation_binding_invalid")
 text(root["jobId"]); text(root["idempotencyKey"]); created=parse_time(root["createdAt"],"remediation_time_invalid"); expires=parse_time(root["expiresAt"],"remediation_time_invalid")
 if expires<=created or (expires-created).total_seconds()>3600: raise ContractError("remediation_time_invalid")
 action=root["action"]
 if action not in ACTIONS or not isinstance(root["parameters"],dict) or set(root["parameters"])!=ACTIONS[action]: raise ContractError("remediation_action_invalid")
 params=root["parameters"]
 if action=="repair" and params.get("scope") not in {"machine","users"}: raise ContractError("remediation_action_invalid")
 if action=="service-register" and params.get("service") not in {"machine-health","supervisor"}: raise ContractError("remediation_action_invalid")
 if action=="version-converge": text(params.get("targetVersion"))
 integer(root["maxAttempts"],1,5,"remediation_attempts_invalid"); return root

def proof_message(method:str,path:str,body:bytes,sequence:int,observed_at:str)->bytes: return canonical({"bodyHash":hashlib.sha256(body).hexdigest(),"method":method.upper(),"observedAt":observed_at,"path":path,"sequence":sequence})
def sign_proof(private_key:ec.EllipticCurvePrivateKey,method:str,path:str,body:bytes,sequence:int,observed_at:str)->str: return base64.b64encode(private_key.sign(proof_message(method,path,body,sequence,observed_at),ec.ECDSA(hashes.SHA256()))).decode()
def verify_proof(public_key:ec.EllipticCurvePublicKey,signature:str,method:str,path:str,body:bytes,sequence:int,observed_at:str)->None:
 try: public_key.verify(base64.b64decode(signature,validate=True),proof_message(method,path,body,sequence,observed_at),ec.ECDSA(hashes.SHA256()))
 except (ValueError,InvalidSignature) as error: raise ContractError("request_proof_invalid",401) from error

def public_pem(key:object)->str: return key.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()  # type: ignore[attr-defined]
def load_public_pem(value:str)->object:
 try: return serialization.load_pem_public_key(value.encode())
 except ValueError as error: raise ContractError("public_key_invalid") from error

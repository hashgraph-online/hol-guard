from __future__ import annotations
import copy
from datetime import timedelta
import pytest
from cryptography.hazmat.primitives.asymmetric import ec,rsa
from codex_plugin_scanner.guard.mdm.cloud_control import ContractError,ACK_SCHEMA,HEALTH_SCHEMA,REMEDIATION_SCHEMA,iso,policy_hash,sign_config,sign_proof,utcnow,validate_ack,validate_health,validate_remediation,verify_config,verify_proof
W='workspace-mdm-cloud-lab';D='device-a';G='a'*32

def policy(mode='enforce'):
 return {'schemaVersion':'hol-guard-mdm-policy.v1','settings':{'mode':mode},'lockedSettings':['mode'],'requiredHarnesses':[]}
def envelope(private,revision=1,previous=None):
 now=utcnow();p=policy();return sign_config({'schemaVersion':'hol-guard-mdm-cloud-config.v1','workspaceId':W,'deviceId':D,'installationGeneration':G,'revision':revision,'issuedAt':iso(now),'notBefore':iso(now-timedelta(seconds=1)),'expiresAt':iso(now+timedelta(minutes=10)),'policy':p,'policyHash':policy_hash(p),'previousPolicyHash':previous,'rollback':{'authorized':False,'fromRevision':None,'reason':None},'signingKeyId':'cloud-key'},private)
def test_signed_configuration_is_bound_and_monotonic():
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048);one=envelope(key);assert verify_config(one,key.public_key(),workspace=W,device=D,generation=G,current_revision=None,current_hash=None)['revision']==1
 two=envelope(key,2,one['policyHash']);assert verify_config(two,key.public_key(),workspace=W,device=D,generation=G,current_revision=1,current_hash=one['policyHash'])['revision']==2
 with pytest.raises(ContractError,match='configuration_revision_not_monotonic'):verify_config(one,key.public_key(),workspace=W,device=D,generation=G,current_revision=1,current_hash=one['policyHash'])
def test_configuration_rejects_tamper_wrong_binding_and_chain():
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048);value=envelope(key)
 for field,replacement,code in [('policyHash','0'*64,'configuration_hash_mismatch'),('workspaceId','other','configuration_binding_invalid')]:
  bad=copy.deepcopy(value);bad[field]=replacement
  with pytest.raises(ContractError,match=code):verify_config(bad,key.public_key(),workspace=W,device=D,generation=G,current_revision=None,current_hash=None)
 with pytest.raises(ContractError,match='configuration_chain_mismatch'):verify_config(envelope(key,2,'1'*64),key.public_key(),workspace=W,device=D,generation=G,current_revision=1,current_hash=value['policyHash'])
def test_request_proof_is_body_path_and_sequence_bound():
 key=ec.generate_private_key(ec.SECP256R1());at=iso(utcnow());body=b'{}';sig=sign_proof(key,'POST','/runtime/v1/health',body,4,at);verify_proof(key.public_key(),sig,'POST','/runtime/v1/health',body,4,at)
 for path,seq in [('/runtime/v1/acknowledgements',4),('/runtime/v1/health',5)]:
  with pytest.raises(ContractError,match='request_proof_invalid'):verify_proof(key.public_key(),sig,'POST',path,body,seq,at)
def test_ack_health_and_remediation_are_strict():
 now=utcnow();ack={'schemaVersion':ACK_SCHEMA,'workspaceId':W,'deviceId':D,'installationGeneration':G,'revision':1,'policyHash':'1'*64,'status':'applied','reasonCode':None,'observedAt':iso(now),'requestId':'ack-1'};assert validate_ack(ack,W,D,G)==ack
 health={'schemaVersion':HEALTH_SCHEMA,'workspaceId':W,'deviceId':D,'installationGeneration':G,'sequence':1,'appliedRevision':1,'appliedPolicyHash':'1'*64,'observedAt':iso(now),'requestId':'health-1','status':{'healthy':True}};assert validate_health(health,W,D,G)==health
 job={'schemaVersion':REMEDIATION_SCHEMA,'workspaceId':W,'deviceId':D,'installationGeneration':G,'jobId':'job-1','idempotencyKey':'idem-1','action':'repair','parameters':{'scope':'machine'},'createdAt':iso(now),'expiresAt':iso(now+timedelta(minutes=5)),'maxAttempts':2};assert validate_remediation(job,W,D,G)==job
 bad={**job,'action':'shell','parameters':{'command':'curl attacker'}}
 with pytest.raises(ContractError,match='remediation_action_invalid'):validate_remediation(bad,W,D,G)

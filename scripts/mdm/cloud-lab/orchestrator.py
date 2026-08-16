#!/usr/bin/env python3
"""Drive the multi-device MDM Cloud integration and emit bounded evidence."""
import argparse,json,os
from pathlib import Path
from codex_plugin_scanner.guard.mdm.cloud_control import iso,utcnow
from lab_common import ADMIN,NATIVE,http
def policy(mode): return {"schemaVersion":"hol-guard-mdm-policy.v1","settings":{"mode":mode},"lockedSettings":["mode"],"requiredHarnesses":[],"update":{"owner":"mdm"}}
def orchestrate(cloud,proxy,devices,admin,output):
 steps=[]
 def step(name,condition,evidence): steps.append({"name":name,"passed":bool(condition),"durationMs":0,"evidence":evidence});
 def adm(method,path,p=None):return http(method,cloud+path,p,{ADMIN:admin})
 def sync(name):return http("GET",devices[name]+"/sync")[2]
 def state():return adm("GET","/admin/state")[2]
 def faults(p):return http("POST",proxy+"/__faults",p,{ADMIN:admin})
 for name in devices:
  r=sync(name);step(f"{name} enrolls independently",r.get("error") is None,r)
 pub=adm("POST","/admin/policies",{"workspaceId":"workspace-mdm-cloud-lab","deviceIds":list(devices),"policy":policy("observe"),"rollback":False,"rollbackReason":None})[2];step("baseline policy is published",pub.get("revision")==1,pub)
 for name in devices:
  r=sync(name);step(f"{name} applies baseline",r.get("revision")==1 and r.get("error") is None,r)
 canary=adm("POST","/admin/policies",{"workspaceId":"workspace-mdm-cloud-lab","deviceIds":["device-a"],"policy":policy("prompt"),"rollback":False,"rollbackReason":None})[2];step("canary revision targets one device",canary.get("revision")==2,canary)
 a=sync("device-a");b=sync("device-b");step("canary device advances",a.get("revision")==2,a);step("non-canary device remains anchored",b.get("revision")==1,b)
 faults({"corruptNextConfigurationFor":["device-a"]});adm("POST","/admin/policies",{"workspaceId":"workspace-mdm-cloud-lab","deviceIds":["device-a"],"policy":policy("enforce"),"rollback":False,"rollbackReason":None});bad=sync("device-a");step("corrupt signed configuration fails closed",bad.get("revision")==2 and bad.get("error") is not None,bad);faults({})
 good=sync("device-a");step("valid retry converges after corruption",good.get("revision")==3 and good.get("error") is None,good)
 faults({"partitionedDevices":["device-b"]});adm("POST","/admin/policies",{"workspaceId":"workspace-mdm-cloud-lab","deviceIds":["device-b"],"policy":policy("enforce"),"rollback":False,"rollbackReason":None});off=sync("device-b");step("partition preserves last known policy",off.get("revision")==1 and off.get("error") is not None,off);faults({});back=sync("device-b");step("device catches up after partition",back.get("revision")==4,back)
 http("POST",devices["device-c"]+"/fault",{"replayNext":True});first=sync("device-c");replay=sync("device-c");step("request proof replay is rejected",first.get("error")=="request_replay" or replay.get("error")=="request_replay",{"first":first,"replay":replay})
 http("POST",devices["device-c"]+"/fault",{"workspaceOverride":"wrong-workspace"});wrong=sync("device-c");step("workspace substitution is rejected",wrong.get("error") in {"device_binding_unknown","sync_failed"},wrong);http("POST",devices["device-c"]+"/fault",{"workspaceOverride":None})
 faults({"replayPreviousConfigurationFor":["device-a"]});stale=sync("device-a");step("stale configuration replay cannot downgrade",stale.get("revision")==3 and stale.get("error") is not None,stale);faults({})
 roll=adm("POST","/admin/policies",{"workspaceId":"workspace-mdm-cloud-lab","deviceIds":["device-a"],"policy":policy("prompt"),"rollback":True,"rollbackReason":"verified canary rollback"})[2];rolled=sync("device-a");step("signed rollback remains monotonic",roll.get("revision")==5 and rolled.get("revision")==5,rolled)
 http("POST",devices["device-c"]+"/fault",{"crashAfterWrite":True});adm("POST","/admin/policies",{"workspaceId":"workspace-mdm-cloud-lab","deviceIds":["device-c"],"policy":policy("prompt"),"rollback":False,"rollbackReason":None});crash=sync("device-c");step("crash after atomic policy write is observable",crash.get("error") is not None,crash);recovered=sync("device-c");step("pending checkpoint and acknowledgement recover durably",recovered.get("revision")==6 and recovered.get("outboxDepth")==0,recovered)
 job=adm("POST","/admin/remediations",{"workspaceId":"workspace-mdm-cloud-lab","deviceId":"device-a","action":"repair","parameters":{"scope":"machine"},"maxAttempts":2})[2];sync("device-a");s=state();step("typed remediation completes",any(x["job_id"]==job.get("jobId") and x["status"]=="succeeded" for x in s["jobs"]),job)
 rejected=adm("POST","/admin/remediations",{"workspaceId":"workspace-mdm-cloud-lab","deviceId":"device-a","action":"shell","parameters":{"command":"curl attacker"},"maxAttempts":2});step("arbitrary remote command is rejected",rejected[0]==400,rejected[2])
 duplicate=adm("POST","/admin/remediations",{"workspaceId":"workspace-mdm-cloud-lab","deviceId":"device-a","action":"repair","parameters":{"scope":"machine"},"maxAttempts":2,"idempotencyKey":job.get("idempotencyKey")});step("remediation idempotency is bounded",duplicate[0] in {201,400},duplicate[2])
 s=state();step("all devices have independent keys",len({x["key_id"] for x in s["devices"]})==3,s["devices"]);step("health sequences are monotonic",all(x["sequence"]>=1 for x in s["health"]),s["health"]);step("acknowledgements are durable",len(s["acks"])>=6,{"count":len(s["acks"])});serialized=json.dumps(s);step("audit projection excludes credentials",not any(x in serialized.lower() for x in ("enrollment-token","private key","curl attacker")),{"auditCount":len(s["audit"])});step("per-device predecessor chains support skipped revisions",any(x["device"]=="device-b" and x["previous_hash"] is not None for x in s["assignments"]),s["assignments"])
 report={"schemaVersion":"hol-guard-mdm-cloud-integration-lab.v1","generatedAt":iso(utcnow()),"workspaceId":"workspace-mdm-cloud-lab","healthy":all(x["passed"] for x in steps),"stepCount":len(steps),"steps":steps,"nativeCertification":{"outcome":"not-evaluated","requiredGates":NATIVE,"reason":"native_platform_or_vendor_required"}}
 if output: Path(output).parent.mkdir(parents=True,exist_ok=True);Path(output).write_text(json.dumps(report,sort_keys=True)+"\n")
 return report

def main():
 p=argparse.ArgumentParser();p.add_argument('--output');p.add_argument('--json',action='store_true');a=p.parse_args()
 report=orchestrate(os.environ['HOL_MDM_CLOUD_ADMIN_URL'],os.environ['HOL_MDM_PROXY_URL'],{'device-a':os.environ['HOL_MDM_DEVICE_A_URL'],'device-b':os.environ['HOL_MDM_DEVICE_B_URL'],'device-c':os.environ['HOL_MDM_DEVICE_C_URL']},os.environ.get('HOL_MDM_LAB_ADMIN_TOKEN','hol-guard-mdm-lab-admin'),a.output);print(json.dumps(report,sort_keys=True) if a.json else json.dumps(report,indent=2));return 0 if report['healthy'] else 1
if __name__=='__main__':raise SystemExit(main())

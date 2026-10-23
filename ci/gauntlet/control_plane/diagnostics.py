"""Read bounded, fixed VM diagnostics; retain raw control details privately."""
import json
import subprocess

READ_STAGE = '''import fcntl,json,re,runpy,sys
from pathlib import Path
r=json.loads(sys.stdin.read(8193));sha=r['source_sha'];job=r['job_id']
if set(r)!={'source_sha','job_id'} or not re.fullmatch('[0-9a-f]{40}',sha) or not re.fullmatch('[0-9a-f]{16}',job):raise ValueError('fixed source and job identity required')
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
p=Path('/opt/hol-gauntlet/worker.lock');h['trusted'](p)
idle=False
with p.open('r+') as lease:
 try:
  fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB);idle=True
 except BlockingIOError:pass
 result={'source_sha':sha,'job_id':job,'worker_idle':idle,'controls':[]}
 stage=Path('/opt/hol-gauntlet/candidates')/sha/'stage-progress.json'
 if stage.exists():result['stage']=h['read_json'](stage)
 terminal=stage.parent/'stage-result.json'
 if terminal.exists():result['stage_result']=h['read_json'](terminal)
 root=Path('/home/hc-'+sha[:16])
 for role in ('boundary','cancel','input-binding','injection','success','timeout'):
  path=root/role/'control.json'
  if not path.exists():continue
  record=h['read_json'](path);row={'role':role}
  for key in ('error','traceback','cleanup_error','gate_cleanup_error','sdk_exit_code','sdk_stderr','control_completed','agent_remove_returncode','agent_cgroup_absent','agent_profile_removed','image_released','root_imported_product'):
   value=record.get(key)
   if isinstance(value,str):value=value[-4000:]
   row[key]=value
  runtime=record.get('developer_runtime',{}).get('record',{}).get('errors',[])
  row['runtime_errors']=[str(e)[:1000] for e in runtime[:8]] if isinstance(runtime,list) else [str(runtime)[:1000]]
  plane=record.get('plane',{})
  row['plane_cleanup_complete']=plane.get('cleanup_complete')
  row['plane_cleanup_errors']=plane.get('cleanup_errors')
  startup=[]
  for event in plane.get('observations',[]):
   if event.get('kind') not in ('native-workspace-readiness','daemon-readiness','daemon-channel','hook-denial-diagnostic','native-sandbox-preparation'):continue
   bounded={k:event[k] for k in ('kind','returncode','response','stdout','stderr','tool_input') if k in event}
   raw=json.dumps(bounded)
   if len(raw)<=8000:startup.append(bounded)
  row['startup_events']=startup[-8:]
  result['controls'].append(row)
 print(json.dumps(result))
'''


def collect(config, job, directory):
    c=config
    result=subprocess.run([c['limactl'],'shell',c['vm'],'--','sudo','-n',c['guest_python'],
        '-I','-B','-c',READ_STAGE],input=json.dumps({'source_sha':job['sha'],'job_id':job['id']}),
        capture_output=True,text=True,timeout=25)
    if result.returncode or len(result.stdout)>128*1024:
        raise RuntimeError('VM staging diagnostics unavailable: '+(result.stderr or result.stdout)[-1000:])
    value=json.loads(result.stdout)
    if value.get('source_sha')!=job['sha'] or value.get('job_id')!=job['id']:
        raise ValueError('VM staging diagnostic identity mismatch')
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'stage-diagnostic.json').write_text(json.dumps(value,indent=2)+'\n')
    return value


def summary(value):
    for row in value.get('controls',[]):
        readiness=next((e for e in reversed(row.get('startup_events',[]))
                        if e.get('kind')=='native-workspace-readiness'),None)
        if readiness and (readiness.get('returncode')!=0
                          or 'workspace readiness' in str(row.get('error',''))):
            response=readiness.get('response')
            return ('Conformance '+row['role']+' readiness: '+json.dumps(response,sort_keys=True))[:1000]
        for key in ('error','cleanup_error','gate_cleanup_error'):
            if row.get(key):
                if key=='error' and str(row[key]).strip()=='AssertionError:':
                    denial=next((e.get('response') for e in reversed(row.get('startup_events',[]))
                                 if e.get('kind')=='hook-denial-diagnostic'),None)
                    if isinstance(denial,dict):
                        return ('Conformance '+row['role']+': native hook denied: '
                                +str(denial.get('reason_code','unknown'))+'; '
                                +str(denial.get('reason','')))[:1000]
                return ('Conformance '+row['role']+': '+str(row[key]))[:1000]
    return 'No terminal control error captured; inspect the retained VM stage and diagnostic records'

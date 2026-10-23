"""Verify retained staging controls without replaying or changing a gate result."""
import fcntl
import json
import re
import subprocess

from .config import atomic_json


AUDIT = '''import fcntl,hashlib,json,re,runpy,sys
from pathlib import Path
r=json.loads(sys.stdin.read(8193));sha=r['source_sha'];job=r['job_id']
if set(r)!={'source_sha','job_id'} or not re.fullmatch('[0-9a-f]{40}',sha) or not re.fullmatch('[0-9a-f]{16}',job):raise ValueError('fixed source and job required')
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
lock=h['trusted'](Path('/opt/hol-gauntlet/worker.lock'))
with lock.open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 deployment,pin=h['deployment'](sha)
 if not deployment:raise ValueError('retained deployed candidate required')
 receipt=h['read_json'](Path('/var/lib/hol-gauntlet/outputs')/(job+'.json'))
 if receipt.get('source_sha')!=sha or receipt.get('job_id')!=job or receipt.get('deployment_digest')!=pin:raise ValueError('retained benchmark identity differs')
 sys.path.insert(0,deployment['controller'])
 from ci.gauntlet.benchmark.ci_runner_config import load_config,verify_assets,read_public
 from ci.gauntlet.benchmark.ci_runner_preflight import controller_environment
 from ci.gauntlet.benchmark.local_executor_conformance import verify_local_conformance
 from ci.gauntlet.benchmark.deterministic import ROLES,evaluate_control
 from ci.gauntlet.control_plane.stage_outcome import require_cleanup
 loaded=load_config(Path(deployment['config']),expected_digest=deployment['config_digest'],asset_root=Path(deployment['asset_root']))
 verify_assets(loaded)
 with controller_environment(loaded):verify_local_conformance(loaded['runtime'])
 expected=read_public(loaded['paths']['conformance'])['runtime']
 if expected['source_sha']!=sha:raise ValueError('conformance references another source')
 controls=Path('/home/hc-'+sha[:16]);cells=[]
 for role in ROLES:
  path=controls/role/'control.json';record=h['read_json'](path)
  require_cleanup(record)
  row=evaluate_control(role,record,expected)
  row['record_sha256']=hashlib.sha256(path.read_bytes()).hexdigest();cells.append(row)
 completion=loaded['paths']['guard_prefix']/'lib/python3.12/site-packages/codex_plugin_scanner/guard/runtime/contained_completion.py'
 missing=[] if completion.is_file() else ['contained-output-completion.v1']
 if any(name.startswith('codex_plugin_scanner') for name in sys.modules):raise ValueError('candidate imported into Root controller')
 result={'status':'diagnostic-passed','source_sha':sha,'job_id':job,'deployment_digest':pin,'controls':6,'suite_profile':'deterministic-six-control-diagnostic.v1','cells':cells,'missing_capabilities':missing,'benchmark_admitted':False,'cleanup_verified':True,'model_tokens':0,'strict_result_preserved':True}
 target=Path('/opt/hol-gauntlet/candidates')/sha/('diagnostic-audit-'+job+'.json')
 if target.exists():
  if h['read_json'](target)!=result:raise ValueError('retained audit differs')
 else:
  with target.open('x') as stream:json.dump(result,stream,sort_keys=True)
 print(json.dumps(result))
'''


def collect(config, job):
    if (not re.fullmatch('[0-9a-f]{16}', job.get('id', ''))
            or not re.fullmatch('[0-9a-f]{40}', job.get('sha', ''))
            or job.get('kind') != 'release' or job.get('state') not in {'passed', 'failed', 'invalid-evidence'}):
        raise ValueError('terminal local release benchmark required')
    result = subprocess.run([config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
        config['guest_python'], '-I', '-B', '-c', AUDIT],
        input=json.dumps({'source_sha':job['sha'], 'job_id':job['id']}),
        capture_output=True, text=True, timeout=90)
    if result.returncode or len(result.stdout) > 128*1024:
        raise RuntimeError('Retained staging audit refused: ' + (result.stderr or result.stdout)[-2000:])
    value=json.loads(result.stdout)
    if (value.get('source_sha')!=job['sha'] or value.get('job_id')!=job['id']
            or value.get('deployment_digest')!=job.get('deployment_digest')
            or value.get('status')!='diagnostic-passed' or value.get('controls')!=6
            or value.get('benchmark_admitted') is not False
            or value.get('strict_result_preserved') is not True
            or value.get('cleanup_verified') is not True
            or len(value.get('cells',[]))!=6
            or {c.get('episode_id') for c in value['cells']}!={'success','input-binding','injection','boundary','timeout','cancel'}
            or any(c.get('status')!='passed' for c in value['cells'])):
        raise ValueError('Retained staging audit identity or verdict differs')
    return value


def audit(state, config, identifier):
    from .agent import Agent
    from .lifecycle import assert_idle, stop_observer
    if not re.fullmatch('[0-9a-f]{16}', identifier):
        raise ValueError('fixed job identity required')
    assert_idle(state)
    stop_observer(state)
    with (state/'private/agent.lock').open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        agent=Agent(config,state)
        if any(j['state'] in {'running','preparing','unknown'} for j in agent.jobs):
            raise ValueError('active or unresolved job prevents staging audit')
        job=next((j for j in agent.jobs if j['id']==identifier),None)
        if job is None:
            raise ValueError('retained job required')
        result=collect(config,job)
        atomic_json(state/'private/local-builds'/identifier/'diagnostic-audit.json',result)
        job['diagnostic_result']=result
        agent.save(job)
        agent.publish()
        print('Verified six retained diagnostic controls; strict benchmark result remains '+job['state'])

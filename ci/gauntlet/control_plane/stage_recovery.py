"""Explicit retry of cleaned conformance failures; retain evidence and compiled bytes."""
import fcntl
import json
import re
import secrets
import subprocess
import time

from .config import atomic_json


PROBE_CLEAN_STARTUP = '''import fcntl,hashlib,json,re,runpy,subprocess,sys
from pathlib import Path
r=json.loads(sys.stdin.read(8193));j=r['job_id'];sha=r['source_sha']
if set(r)!={'job_id','source_sha'} or not re.fullmatch('[0-9a-f]{16}',j) or not re.fullmatch('[0-9a-f]{40}',sha):raise ValueError('exact stalled staging identity required')
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
base=Path('/opt/hol-gauntlet');lock=h['trusted'](base/'worker.lock')
with lock.open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 root=h['trusted'](base/'candidates'/sha,directory=True)
 if (root/'deployment.json').exists():raise ValueError('candidate is already deployed')
 progress=h['read_json'](root/'stage-progress.json')
 if (progress.get('source_sha')!=sha or progress.get('phase')!='conformance-control'
     or progress.get('current_control')!='boundary' or progress.get('completed_controls')!=[]):raise ValueError('not the first staging control')
 identity=h['process_identity'](progress.get('pid',0))
 if identity and identity.get('start_ticks')==progress.get('process_start_ticks'):raise ValueError('staging process remains live')
 controls=h['trusted'](Path('/home/hc-'+sha[:16]),directory=True)
 records=list(controls.glob('*/control.json'))
 if len(records)!=1 or records[0].parent.name!='boundary':raise ValueError('unexpected staging records')
 record=h['read_json'](records[0]);mcp=record.get('developer_runtime',{}).get('record',{}).get('native_mcp_audit',{}).get('record',{}).get('product_plane',{})
 name=mcp.get('container')
 if not isinstance(name,str) or not re.fullmatch('native-product-[0-9a-f]{32}',name):raise ValueError('owned product identity missing')
 present=subprocess.run(['/usr/bin/podman','container','exists',name],capture_output=True,timeout=10)
 if present.returncode!=1:raise ValueError('owned product container remains or is uncertain')
 profiles=Path('/sys/kernel/security/apparmor/profiles').read_text()
 if any(line.split(' ',1)[0]==name for line in profiles.splitlines()):raise ValueError('owned product profile remains')
 if (Path('/var/lib/hol-gauntlet/outputs')/(j+'.started.json')).exists():raise ValueError('benchmark execution began')
 print(json.dumps({'job_id':j,'source_sha':sha,'record_sha256':hashlib.sha256(records[0].read_bytes()).hexdigest(),'record':record}))
'''


def clean_startup_repair_allowed(config, job):
    """Permit a controller upgrade only after an uncertain pre-builtin cell is empty."""
    if (job.get('state') != 'unknown' or job.get('kind') != 'local-candidate'
            or job.get('local_build', {}).get('status') != 'built'):
        return False
    request = {'job_id': job.get('id'), 'source_sha': job.get('sha')}
    try:
        result = subprocess.run(
            [config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
             config['guest_python'], '-I', '-B', '-c', PROBE_CLEAN_STARTUP],
            input=json.dumps(request), capture_output=True, text=True, timeout=35)
        if result.returncode or len(result.stdout) > 1024**2:
            return False
        proof = json.loads(result.stdout)
        if (proof.get('job_id') != request['job_id'] or proof.get('source_sha') != request['source_sha']
                or not re.fullmatch('[0-9a-f]{64}', proof.get('record_sha256', ''))):
            return False
        from .stage_outcome import failed_roles
        record = proof['record']
        return (record.get('error') == 'TimeoutError: product capture exceeded deadline'
                and failed_roles({'boundary': record}) == ['boundary'])
    except (KeyError, OSError, ValueError, TypeError, subprocess.SubprocessError):
        return False


RETAIN = '''import fcntl,hashlib,json,re,runpy,sys
from pathlib import Path
r=json.loads(sys.stdin.read(8193));j=r['job_id'];sha=r['source_sha'];build=r['build_job_id']
if set(r) not in ({'job_id','source_sha','build_job_id'},{'job_id','source_sha','build_job_id','deployment_digest'}) or not re.fullmatch('[0-9a-f]{16}',j) or not re.fullmatch('[0-9a-f]{16}',build) or not re.fullmatch('[0-9a-f]{40}',sha):raise ValueError('fixed staging identity required')
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
base=Path('/opt/hol-gauntlet');p=base/'worker.lock';h['trusted'](p)
with p.open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 output=Path('/var/lib/hol-gauntlet/outputs')
 started_path=output/(j+'.started.json');receipt_path=output/(j+'.json')
 preflight_only=False;deployment=None
 if started_path.exists() or receipt_path.exists():
  if not started_path.exists() or not receipt_path.exists():raise ValueError('benchmark execution unresolved; reconcile instead')
  deployment,pin=h['deployment'](sha)
  if not deployment or pin!=r.get('deployment_digest'):raise ValueError('exact deployed benchmark pin required')
  started=h['read_json'](started_path);terminal=h['read_json'](receipt_path)
  for value in (started,terminal):
   if value.get('job_id')!=j or value.get('source_sha')!=sha or value.get('deployment_digest')!=pin:raise ValueError('benchmark receipt identity differs')
  identity=h['process_identity'](started.get('pid',0))
  if identity and identity.get('start_ticks')==started.get('process_start_ticks'):raise ValueError('benchmark process still live')
  report_path=output/j/'report/result.json';report=h['read_json'](report_path)
  if hashlib.sha256(report_path.read_bytes()).hexdigest()!=terminal.get('report_sha256'):raise ValueError('benchmark report digest differs')
  if (terminal.get('status')!='failed' or terminal.get('exit_code')!=1
      or report.get('schema')!='gauntlet-ci-check.v1' or report.get('profile')!='deterministic'
      or report.get('guard_source_sha')!=sha or report.get('expected_guard_source_sha')!=sha
      or report.get('runner_config_digest')!=deployment['config_digest']
      or report.get('model_tokens')!=0 or report.get('model_usage_known') is not True
      or report.get('errors')!=['ValueError: installed Guard lacks the declared completion module; new matching candidate required']
      or len(report.get('cells',[]))!=6
      or any(c.get('status')!='failed' or c.get('reasons')!=['control-failed-or-not-executed'] for c in report['cells'])):
   raise ValueError('only the proven completion-module preflight rejection permits this staging retry')
  preflight_only=True
 elif 'deployment_digest' in r:raise ValueError('terminal benchmark receipt missing')
 receipt=h['read_json'](Path('/var/lib/hol-gauntlet/builds')/build/'result.json')
 if receipt.get('source_sha')!=sha or receipt.get('job_id')!=build or receipt.get('status')!='built':raise ValueError('exact successful retained build required')
 root=base/'candidates'/sha;controls=Path('/home/hc-'+sha[:16])
 retained=base/'candidates'/(sha+'.failed-'+j);old_controls=Path(str(controls)+'.failed-'+j)
 original=root if root.exists() else retained
 original_controls=controls if controls.exists() else old_controls
 h['trusted'](original,directory=True)
 if (original/'deployment.json').exists() and not preflight_only:raise ValueError('candidate already deployed; refuse staging retry')
 progress=h['read_json'](original/'stage-progress.json')
 if progress.get('source_sha')!=sha:raise ValueError('stage identity differs')
 identity=h['process_identity'](progress.get('pid',0))
 if identity and identity.get('start_ticks')==progress.get('process_start_ticks'):raise ValueError('staging process still live')
 # A new dependency may be rejected before any control workspace exists. It is
 # safe to retain and retry only this pre-control phase, after the operator has
 # provisioned a separately pinned baseline. Never reinterpret a partial run.
 precontrol=(progress.get('phase')=='dependency-validation' and not original_controls.exists()
             and not (original/'provisional.json').exists() and (original/'candidate.zip').is_file())
 if not precontrol:h['trusted'](original_controls,directory=True)
 records=[] if precontrol else list(original_controls.glob('*/control.json'))
 roles={'boundary','cancel','input-binding','injection','success','timeout'}
 if not precontrol and (not 1<=len(records)<=6 or any(p.parent.name not in roles for p in records)):raise ValueError('fixed diagnostic controls required')
 settings=h['read_json'](base/'stage-settings.json')
 controller=deployment['controller'] if preflight_only else settings['controller']
 h['trusted'](Path(controller),directory=True);sys.path.insert(0,controller)
 from ci.gauntlet.control_plane.stage_outcome import failed_roles
 failed=failed_roles({p.parent.name:h['read_json'](p) for p in records})
 if not failed and not preflight_only and not precontrol:raise ValueError('no failed conformance role; refuse retry')
 if preflight_only:
  from ci.gauntlet.benchmark.ci_runner_config import load_config,verify_assets
  from ci.gauntlet.benchmark.ci_runner_preflight import controller_environment
  from ci.gauntlet.benchmark.local_executor_conformance import verify_local_conformance
  loaded=load_config(Path(deployment['config']),expected_digest=deployment['config_digest'],asset_root=Path(deployment['asset_root']))
  verify_assets(loaded)
  with controller_environment(loaded):verify_local_conformance(loaded['runtime'])
 if root.exists():
  if retained.exists():raise ValueError('retention destination already exists')
  root.rename(retained)
 if controls.exists():
  if old_controls.exists():raise ValueError('control retention destination already exists')
  controls.rename(old_controls)
 print(json.dumps({'job_id':j,'source_sha':sha,'build_job_id':build,'retained':str(retained),'controls':str(old_controls),'retry_safe':True,'preflight_only':preflight_only,'precontrol':precontrol}))
'''


def retain(config, job):
    build = job['local_build']['job_id']
    request={'job_id':job['id'], 'source_sha':job['sha'], 'build_job_id':build}
    if job.get('state')=='failed':
        pin=job.get('deployment_digest','')
        if not re.fullmatch('[0-9a-f]{64}',pin):
            raise ValueError('exact failed deployment pin required')
        request['deployment_digest']=pin
    result = subprocess.run([config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
        config['guest_python'], '-I', '-B', '-c', RETAIN],
        input=json.dumps(request),
        capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Staging retry refused: ' + (result.stderr or result.stdout)[-2500:])
    value = json.loads(result.stdout)
    if (value.get('job_id')!=job['id'] or value.get('source_sha')!=job['sha']
            or value.get('build_job_id')!=build or value.get('retry_safe') is not True
            or (job.get('state')=='failed' and value.get('preflight_only') is not True)):
        raise ValueError('staging retry receipt identity mismatch')
    return value


def retry(state, config, identifier):
    from .agent import Agent
    from .lifecycle import stop_observer
    from .releases import admitted
    stop_observer(state)
    with (state/'private/agent.lock').open('a+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        agent=Agent(config,state)
        previous=next((j for j in agent.jobs if j['id']==identifier),None)
        if (not previous or not admitted(config,previous) or previous['state'] not in {'unknown','conformance-failed','failed'}
                or previous.get('local_build',{}).get('status')!='built'):
            raise ValueError('exact unresolved local staging attempt required')
        if any(j['id']!=identifier and j['state'] in {'running','preparing','unknown'} for j in agent.jobs):
            raise ValueError('another job is active or unresolved')
        receipt=retain(config,previous)
        atomic_json(state/'private/local-builds'/identifier/'stage-retention.json',receipt)
        next_id=previous.get('retried_as') or secrets.token_hex(8)
        previous['retried_as']=next_id
        agent.save(previous)
        if not any(j['id']==next_id for j in agent.jobs):
            job={k:previous[k] for k in ('kind','tag','sha','title','url','local_build',
                'source_path','branch','version','operator_queued') if k in previous}
            job.update(id=next_id,retry_of=identifier,state='queued',created_at=time.time(),
                       reason='Retry staging with the retained exact-commit successful build')
            agent.jobs.append(job)
            agent.activity(job,'queued',job['reason'])
        previous.update(state='archived',archived_at=time.time(),finished_at=time.time(),
                        reason='Failed startup retained; retry queued as '+next_id)
        agent.save(previous)
        agent.publish()
        print('Retained failed staging; queued '+next_id+' using build '+previous['local_build']['job_id'])

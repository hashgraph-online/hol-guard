"""Run one model-backed twelve-cell campaign for an already passing local build."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import time

from .config import atomic_json
from .local_candidate import identity

PROJECT = Path(__file__).resolve().parents[4]
REPO = PROJECT/'workflow-benchmark-implementation'
UV = '/opt/homebrew/bin/uv'
VM_HELPER = '/opt/hol-gauntlet/live.py'


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def call_vm(config, request, *, timeout=90):
    command = [config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
               config['guest_python'], '-I', '-B', VM_HELPER]
    result = subprocess.run(command, input=json.dumps(request), capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode or len(result.stdout) > 1024**2:
        raise RuntimeError('VM live adapter refused request: '+result.stderr[-1000:])
    return json.loads(result.stdout)


def publish(state, value):
    value['updated_at'] = time.time()
    name = ('feature-ai.json' if value.get('profile') in {'feature-ai', 'feature-ai-protocol'}
            else 'live.json')
    atomic_json(state/'public'/name, value, mode=0o644)
    print(json.dumps({k:value.get(k) for k in
        ('job_id','status','completed_cases','total_cases','model_tokens','current_case')},
        sort_keys=True), flush=True)


def stop_owned_provider(root, pid):
    proof = json.loads((root/'startup/signed-result.json').read_bytes())['record']
    expected = proof['process_identity']
    observed = subprocess.run(['/bin/ps','-ww','-p',str(pid),'-o','pid=,lstart=,args='],
        capture_output=True,text=True,check=False).stdout.strip()
    if not observed:
        return True
    if observed != expected or str(root/'serve_model_v9.py') not in observed:
        return False
    os.kill(pid,signal.SIGTERM)
    for _ in range(20):
        time.sleep(0.5)
        row = subprocess.run(['/bin/ps','-p',str(pid),'-o','pid='],
            capture_output=True,text=True,check=False).stdout.strip()
        if not row:
            return True
    return False


def verified_terminal(terminal, transport_code):
    if (transport_code != 0
            or terminal.get('status') not in {'passed','failed','invalid-evidence','interrupted'}
            or type(terminal.get('exit_code')) is not int):
        raise RuntimeError('live worker exited without a verified terminal receipt')
    if terminal['status'] == 'passed' and terminal['exit_code'] != 0:
        return 'invalid-evidence'
    return terminal['status']


def passed_candidate_job(state, candidate):
    jobs = [json.loads(path.read_text()) for path in (state/'private/jobs').glob('*.json')]
    matches = [j for j in jobs if j.get('kind') == 'local-candidate'
               and j.get('sha') == candidate['sha'] and j.get('state') == 'passed'
               and not j.get('archived_at')]
    if len(matches) != 1:
        raise ValueError('exact current local candidate must pass strict controls before live E2E')
    if any(j.get('state') in {'running','preparing','unknown'} for j in jobs):
        raise ValueError('Gauntlet VM has active or unresolved work')
    return matches[0]


def refresh_candidate(config, state, checkout):
    """Restage one retained successful build under current execution sources."""
    candidate = identity(checkout)
    prior = passed_candidate_job(state,candidate)
    build = prior.get('local_build',{})
    if (build.get('status') != 'built' or build.get('source_sha') != candidate['sha']
            or re.fullmatch('[0-9a-f]{16}',build.get('job_id','')) is None
            or re.fullmatch('[0-9a-f]{64}',build.get('archive_sha256','')) is None):
        raise ValueError('retained exact-commit successful build required for live refresh')
    hold = state/'private/hold-admissions.json'
    if hold.exists():
        raise ValueError('admissions already held; resolve the existing reason first')
    stage_id = secrets.token_hex(8)
    owned_hold = {'requested_at':time.time(),'reason':'live conformance refresh',
                  'job_id':stage_id}
    private = state/'private/live-staging'/stage_id
    private.mkdir(parents=True,mode=0o700)
    atomic_json(hold,owned_hold)
    request = {'source_sha':candidate['sha'], 'archive_sha256':build['archive_sha256'],
               'build_job_id':build['job_id'], 'live_refresh_id':stage_id}
    command = [config['limactl'],'shell',config['vm'],'--','sudo','-n',
               config['guest_python'],'-I','-B','/opt/hol-gauntlet/stage.py']
    result = subprocess.run(command,input=json.dumps(request),capture_output=True,
                            text=True,timeout=1800)
    (private/'stage.stdout').write_text(result.stdout)
    (private/'stage.stderr').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError('live staging failed; admission hold and exact attempt retained')
    stage = json.loads(result.stdout.splitlines()[-1])
    if (stage.get('status') != 'staged' or stage.get('source_sha') != candidate['sha']
            or stage.get('controls') != 6):
        raise ValueError('live staging did not verify all six source-bound controls')
    record = {'schema':'hol-gauntlet-live-staging.v1','stage_id':stage_id,
              'source_sha':candidate['sha'],'build_job_id':build['job_id'],
              'archive_sha256':build['archive_sha256'],'status':'staged',
              'completed_at':time.time()}
    target = state/'private/live-staging'/(candidate['sha']+'.json')
    atomic_json(target,record)
    if json.loads(hold.read_text()) == owned_hold:
        hold.unlink()
    print(json.dumps(record,sort_keys=True),flush=True)
    return 0


def run(config, state, checkout, *, profile='beta-e2e'):
    if profile not in {'beta-e2e', 'feature-ai', 'feature-ai-protocol'}:
        raise ValueError('reviewed live profile required')
    candidate = identity(checkout)
    passed_candidate_job(state,candidate)
    stage_file = state/'private/live-staging'/(candidate['sha']+'.json')
    stage_id = None
    if stage_file.exists():
        staging = json.loads(stage_file.read_text())
        if (staging.get('schema') != 'hol-gauntlet-live-staging.v1'
                or staging.get('source_sha') != candidate['sha']
                or staging.get('status') != 'staged'
                or re.fullmatch('[0-9a-f]{16}',staging.get('stage_id','')) is None):
            raise ValueError('retained live staging record differs')
        stage_id = staging['stage_id']
    hold = state/'private/hold-admissions.json'
    if hold.exists():
        raise ValueError('admissions already held; resolve the existing reason first')
    job = secrets.token_hex(8)
    private = state/'private/live'/job
    private.mkdir(parents=True, mode=0o700)
    row = {'schema':'hol-gauntlet-live-operations.v1','job_id':job,
           'source_sha':candidate['sha'],'branch':candidate['branch'],
           'model_id':'mlx-community/Qwen3.6-35B-A3B-8bit',
           'profile':profile,'total_cases':2 if profile != 'beta-e2e' else 12,
           'completed_cases':0,
           'model_tokens':None,'status':'queued','started_at':time.time(),
           'required_gate':False,'qualification_eligible':False}
    provider_root = None
    remote_started = False
    terminal_verified = False
    owned_hold = {'requested_at':time.time(),'reason':'live model E2E', 'job_id':job}
    atomic_json(hold, owned_hold)
    publish(state,row)
    try:
        row['status']='provider-startup'
        publish(state,row)
        command = [UV,'run','--no-project','--with','cryptography==50.0.0',
            'python','-B','-m','ci.gauntlet.control_plane.live_provider',
            job,profile,candidate['sha']]
        result = subprocess.run(command,cwd=REPO,capture_output=True,text=True,timeout=900)
        (private/'provider-startup.stdout').write_text(result.stdout)
        (private/'provider-startup.stderr').write_text(result.stderr)
        if result.returncode:
            raise RuntimeError('owned model startup failed; inspect private provider-startup logs')
        provider = json.loads(result.stdout.splitlines()[-1])
        provider_root = Path(provider['root'])
        row.update(status='model-ready',model_provider_pid=provider['pid'],
                   model_tokens=0,provider_maximum_tokens=provider['maximum_accounted_tokens'],
                   provider_known_tokens_before=provider['known_tokens_before'])
        publish(state,row)
        for role in ('provider','model'):
            source = provider[role+'_manifest']
            if sha(source) != provider[role+'_sha256']:
                raise ValueError('model manifest changed before VM transfer')
            destination = config['vm']+':'+config['guest_inbox']+'/hol-live-'+job+'-'+role+'.json'
            subprocess.run([config['limactl'],'copy',source,destination],
                           check=True,capture_output=True,timeout=120)
        row['status']='vm-preflight'
        publish(state,row)
        request = {'action':'prepare','job_id':job,'source_sha':candidate['sha'],
            'provider_sha256':provider['provider_sha256'],
            'model_sha256':provider['model_sha256']}
        if profile != 'beta-e2e':
            request['profile'] = profile
        if stage_id is not None:
            request['stage_id'] = stage_id
        prepared = call_vm(config,request,timeout=1800)
        atomic_json(private/'preflight.json',prepared)
        if prepared['status'] != 'ready':
            row.update(status='preflight-failed',preflight_errors=prepared['preflight_errors'],
                       unsupported_cells=prepared['unsupported_cells'])
            publish(state,row)
            return 2
        row.update(status='running',config_digest=prepared['config_digest'])
        publish(state,row)
        command = [config['limactl'],'shell',config['vm'],'--','sudo','-n',
                   config['guest_python'],'-I','-B',VM_HELPER]
        with (private/'vm-run.stdout').open('x') as output, (private/'vm-run.stderr').open('x') as errors:
            process = subprocess.Popen(command,stdin=subprocess.PIPE,
                stdout=output,stderr=errors,text=True)
            remote_started = True
            process.stdin.write(json.dumps({'action':'run','job_id':job,
                'source_sha':candidate['sha']}))
            process.stdin.close()
            while process.poll() is None:
                try:
                    progress=call_vm(config,{'action':'status','job_id':job,
                        'source_sha':candidate['sha']},timeout=30)
                    row.update(status=progress['status'],
                        completed_cases=progress.get('completed_cases',row['completed_cases']),
                        current_case=progress.get('current_case'),
                        current_case_label=progress.get('current_case_label'),
                        model_tokens=progress.get('model_tokens'),
                        provider_pending_requests=progress.get('provider_pending_requests'),
                        vm_pid=progress.get('pid'),
                        vm_process_alive=progress.get('process_alive'))
                    publish(state,row)
                except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as error:
                    row['progress_error']=type(error).__name__+': '+str(error)[:300]
                    publish(state,row)
                time.sleep(15)
            code = process.wait()
        terminal=call_vm(config,{'action':'status','job_id':job,
            'source_sha':candidate['sha']},timeout=30)
        status = verified_terminal(terminal, code)
        terminal_verified = True
        atomic_json(private/'terminal.json',terminal)
        row.update(status=status,exit_code=terminal['exit_code'],
            completed_cases=terminal.get('completed_cases',row['completed_cases']),
            model_tokens=terminal.get('model_tokens'),cells=terminal.get('cells',[]),
            report_sha256=terminal.get('report_sha256'),finished_at=time.time(),
            model_ingestion_proven=terminal.get('model_ingestion_proven'),
            vm_process_alive=terminal.get('process_alive'))
        publish(state,row)
        return 0 if row['status']=='passed' and terminal['exit_code']==0 else 1
    except Exception as error:
        row.update(status='unknown' if remote_started and not terminal_verified else 'failed',
            error=type(error).__name__+': '+str(error)[:500],finished_at=time.time())
        publish(state,row)
        return 2
    finally:
        if provider_root is not None and (not remote_started or terminal_verified):
            try:
                row['owned_provider_stopped']=stop_owned_provider(provider_root,row['model_provider_pid'])
            except (OSError,ValueError,KeyError,subprocess.SubprocessError):
                row['owned_provider_stopped']=False
            publish(state,row)
        if not remote_started or terminal_verified:
            try:
                if json.loads(hold.read_text()) == owned_hold:
                    hold.unlink()
            except (OSError,ValueError):
                pass


def reconcile(config, state, job):
    """Resolve one uncertain local run from the Root receipt; never replay it."""
    if re.fullmatch('[0-9a-f]{16}', job) is None:
        raise ValueError('fixed live job identity required')
    records = [json.loads(path.read_text()) for path in
               (state/'public/live.json', state/'public/feature-ai.json') if path.exists()]
    matches = [value for value in records if value.get('job_id') == job]
    if len(matches) != 1 or matches[0].get('status') != 'unknown':
        raise ValueError('only the current unresolved live job can be reconciled')
    row = matches[0]
    terminal = call_vm(config,{'action':'status','job_id':job,
        'source_sha':row['source_sha']},timeout=30)
    if terminal.get('status') == 'unknown' and terminal.get('process_alive') is False:
        call_vm(config,{'action':'finalize','job_id':job,
            'source_sha':row['source_sha']},timeout=90)
        terminal = call_vm(config,{'action':'status','job_id':job,
            'source_sha':row['source_sha']},timeout=30)
    if terminal.get('job_id') != job or terminal.get('source_sha') != row['source_sha']:
        raise ValueError('live terminal identity differs from unresolved job')
    status = verified_terminal(terminal, 0)
    private = state/'private/live'/job
    atomic_json(private/'terminal.json',terminal)
    root = PROJECT/('local-model-provider-gauntlet-'+job)
    stopped = stop_owned_provider(root,row['model_provider_pid'])
    row.update(status=status,exit_code=terminal['exit_code'],
        completed_cases=terminal.get('completed_cases',row['completed_cases']),
        model_tokens=terminal.get('model_tokens'),cells=terminal.get('cells',[]),
        report_sha256=terminal.get('report_sha256'),finished_at=time.time(),
        model_ingestion_proven=terminal.get('model_ingestion_proven'),
        vm_process_alive=terminal.get('process_alive'),
        owned_provider_stopped=stopped)
    publish(state,row)
    if not stopped:
        raise RuntimeError('terminal receipt verified but owned provider stop is unconfirmed')
    hold=state/'private/hold-admissions.json'
    if hold.exists():
        value=json.loads(hold.read_text())
        if value.get('job_id') == job and value.get('reason') == 'live model E2E':
            hold.unlink()
    return 0 if status == 'passed' and terminal['exit_code'] == 0 else 1

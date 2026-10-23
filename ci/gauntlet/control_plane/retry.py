"""Explicit new attempts for verified terminal build failures; retain old evidence."""
import json
import secrets
import subprocess
import time


VERIFY = '''import fcntl,json,re,runpy,subprocess,sys
from pathlib import Path
r=json.loads(sys.stdin.read(8193));j=r['job_id'];sha=r['source_sha']
if set(r)!={'job_id','source_sha'} or not re.fullmatch('[0-9a-f]{16}',j) or not re.fullmatch('[0-9a-f]{40}',sha):raise ValueError('fixed build identity required')
h=runpy.run_path('/opt/hol-gauntlet/worker.py',run_name='trusted_worker_helpers')
p=Path('/opt/hol-gauntlet/worker.lock');h['trusted'](p)
with p.open('r+') as lease:
 fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 result=h['read_json'](Path('/var/lib/hol-gauntlet/builds')/j/'result.json')
 if result.get('source_sha')!=sha or result.get('job_id')!=j or result.get('status')!='build-failed':raise ValueError('matching terminal build failure required')
 if (Path('/var/lib/hol-gauntlet/outputs')/(j+'.started.json')).exists():raise ValueError('benchmark already started; refuse build retry')
 container=subprocess.run(['/usr/bin/podman','container','exists','hol-gauntlet-build-'+j],capture_output=True,timeout=15)
 if container.returncode!=1:raise ValueError('container exists or state cannot be proven; inspect before retry')
 print(json.dumps({'job_id':j,'source_sha':sha,'retry_safe':True}))
'''


def verify(config, job):
    c = config
    result = subprocess.run([c['limactl'], 'shell', c['vm'], '--', 'sudo', '-n', c['guest_python'],
        '-I', '-B', '-c', VERIFY], input=json.dumps({'job_id':job['id'], 'source_sha':job['sha']}),
        capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Build retry refused: ' + (result.stderr or result.stdout)[-2000:])
    value = json.loads(result.stdout)
    if value != {'job_id':job['id'], 'source_sha':job['sha'], 'retry_safe':True}:
        raise ValueError('build retry verification identity mismatch')


def enqueue(agent):
    from .releases import admitted
    if agent.config['release_build_backend'] != 'local-vm':
        raise ValueError('local VM build backend required for build retries')
    failed = [j for j in agent.jobs if admitted(agent.config, j) and j['state']=='build-failed'
              and j.get('local_build', {}).get('status')=='build-failed']
    current = []
    for job in failed:
        if job.get('kind') == 'local-candidate':
            from .local_candidate import verify as verify_candidate
            try:
                verify_candidate(job)
            except (ValueError,OSError,subprocess.SubprocessError):
                continue  # Keep the old failure; never retry an obsolete branch.
        current.append(job)
    failed = current
    # Verify every old attempt before mutating any queue records.
    for job in failed:
        verify(agent.config, job)
    created = []
    for previous in failed:
        old_next = previous.get('retried_as')
        if old_next and any(j['id']==old_next for j in agent.jobs):
            previous['archived_at'] = time.time()
            agent.save(previous)
            continue
        identifier = old_next or secrets.token_hex(8)
        previous.update(retried_as=identifier)
        agent.save(previous)
        job = {k:previous[k] for k in ('kind','tag','sha','title','url',
            'source_path','branch','version','operator_queued') if k in previous}
        job.update(id=identifier, retry_of=previous['id'], state='queued', created_at=time.time(),
                   reason='New local build attempt after verified terminal failure')
        receipt=previous.get('local_build',{})
        if (previous.get('kind')=='local-candidate' and receipt.get('failure_phase')=='product-contracts'
                and receipt.get('retained_archive_sha256')):
            job['retest_build_job_id']=receipt['job_id']
            job['reason']='Retest retained exact-commit compiled artifact in the repaired VM test profile'
        agent.jobs.append(job)
        agent.activity(job, 'queued', 'Explicit retry of retained failed build ' + previous['id'])
        previous['archived_at'] = time.time()
        agent.save(previous)
        created.append(identifier)
    agent.publish()
    return created

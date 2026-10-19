"""Host orchestration for a retained, source-bound VM feature contract audit."""
from __future__ import annotations

import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from .config import atomic_json
from .feature_entry import catalog
from .live_local import passed_candidate_job
from .local_candidate import identity

VM_HELPER = '/opt/hol-gauntlet/features.py'


def vm_request(config, request, *, timeout=35):
    command = [config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
               config['guest_python'], '-I', '-B', VM_HELPER]
    result = subprocess.run(command, input=json.dumps(request), text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode or len(result.stdout) > 128*1024:
        raise RuntimeError('VM feature audit request failed: '+result.stderr[-1000:])
    return json.loads(result.stdout)


def publish(state, row):
    row['updated_at'] = time.time()
    atomic_json(state/'public/feature-audit.json', row, mode=0o644)
    print(json.dumps({name: row.get(name) for name in
          ('audit_id', 'status', 'phase', 'current_group', 'completed_groups', 'total_groups')},
          sort_keys=True), flush=True)


def source_archive_for_build(state, job, build):
    """Resolve the original source archive through a retained staging retry chain."""
    build_id = build.get('job_id', '')
    archive = build.get('archive_sha256', '')
    if (not re.fullmatch('[0-9a-f]{16}', build_id)
            or not re.fullmatch('[0-9a-f]{64}', archive)):
        raise ValueError('exact successful VM build identity required')
    seen = set()
    current = job
    for _ in range(16):
        identifier = current.get('id', '')
        receipt = current.get('local_build', {})
        if (not re.fullmatch('[0-9a-f]{16}', identifier) or identifier in seen
                or current.get('kind') != 'local-candidate'
                or current.get('sha') != job['sha']
                or receipt.get('status') != 'built'
                or receipt.get('source_sha') != job['sha']
                or receipt.get('job_id') != build_id
                or receipt.get('archive_sha256') != archive):
            raise ValueError('retained staging retry chain differs from the successful build')
        seen.add(identifier)
        if identifier == build_id:
            source = current.get('source_archive_sha256', '')
            if not re.fullmatch('[0-9a-f]{64}', source):
                raise ValueError('original source archive digest required')
            return source
        previous_id = current.get('retry_of', '')
        if not re.fullmatch('[0-9a-f]{16}', previous_id):
            raise ValueError('staging retry has no original build link')
        path = state/'private/jobs'/(previous_id+'.json')
        if path.is_symlink():
            raise ValueError('retained retry job must be an ordinary file')
        previous = json.loads(path.read_text())
        if previous.get('retried_as') != identifier:
            raise ValueError('retained staging retry linkage differs')
        current = previous
    raise ValueError('staging retry chain exceeds bound')


def request_for_candidate(state, job, candidate, audit_id):
    build = job.get('local_build', {})
    if (build.get('status') != 'built' or build.get('source_sha') != candidate['sha']
            or not re.fullmatch('[0-9a-f]{64}', build.get('archive_sha256', ''))):
        raise ValueError('exact successful VM source build and archive required')
    source_archive_sha256 = source_archive_for_build(state, job, build)
    return {'action': 'run', 'audit_id': audit_id,
            'source_sha': candidate['sha'], 'build_job_id': build['job_id'],
            'source_archive_sha256': source_archive_sha256,
            'candidate_archive_sha256': build['archive_sha256']}


def run(config, state, checkout):
    candidate = identity(checkout)
    job = passed_candidate_job(state, candidate)
    hold = state/'private/hold-admissions.json'
    if hold.exists():
        raise ValueError('admissions already held; resolve the existing reason first')
    audit_id = secrets.token_hex(8)
    request = request_for_candidate(state, job, candidate, audit_id)
    private = state/'private/features'/audit_id
    private.mkdir(parents=True, mode=0o700)
    atomic_json(private/'request.json', request)
    owned_hold = {'requested_at': time.time(), 'reason': 'source-bound feature audit',
                  'job_id': audit_id}
    atomic_json(hold, owned_hold)
    groups = catalog()
    row = {'schema': 'hol-gauntlet-feature-operations.v1', 'audit_id': audit_id,
           'source_sha': candidate['sha'], 'build_job_id': job['id'],
           'status': 'starting', 'phase': 'vm-startup', 'completed_groups': 0,
           'total_groups': len(groups), 'groups': groups, 'started_at': time.time(),
           'evidence_kind': 'mixed-source-installed-contract', 'model_tokens': 0,
           'qualification_eligible': False}
    publish(state, row)
    remote_started = False
    verified_terminal = False
    try:
        command = [config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
                   config['guest_python'], '-I', '-B', VM_HELPER]
        with (private/'vm-run.stdout').open('x') as output, (private/'vm-run.stderr').open('x') as errors:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output,
                                       stderr=errors, text=True)
            process.stdin.write(json.dumps(request))
            process.stdin.close()
            remote_started = True
            while process.poll() is None:
                try:
                    progress = vm_request(config, {**request, 'action': 'status'})
                    row.pop('progress_error', None)
                    row.update(status=progress['status'], phase=progress.get('phase', 'testing'),
                               current_group=progress.get('current_group'),
                               completed_groups=progress.get('completed_groups', 0))
                    publish(state, row)
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    row['progress_error'] = type(error).__name__+': '+str(error)[:250]
                    publish(state, row)
                time.sleep(15)
            code = process.wait()
        terminal = vm_request(config, {**request, 'action': 'status'})
        if (code != 0 or terminal.get('schema') != 'hol-gauntlet-feature-run.v1'
                or terminal.get('audit_id') != audit_id
                or terminal.get('source_sha') != candidate['sha']
                or terminal.get('status') not in {'passed', 'failed', 'invalid-evidence', 'unknown'}):
            raise RuntimeError('VM feature worker ended without an exact terminal receipt')
        atomic_json(private/'terminal.json', terminal)
        verified_terminal = True
        row.pop('progress_error', None)
        row.update(status=terminal['status'], phase='complete', current_group=None,
                   completed_groups=terminal.get('completed_groups', 0),
                   groups=terminal.get('groups', []),
                   report_sha256=terminal.get('report_sha256'),
                   error=terminal.get('error'), finished_at=time.time())
        publish(state, row)
        return 0 if terminal['status'] == 'passed' else 1
    except Exception as error:
        row.update(status='unknown' if remote_started and not verified_terminal else 'failed',
                   error=type(error).__name__+': '+str(error)[:500], finished_at=time.time())
        publish(state, row)
        return 2
    finally:
        if (verified_terminal and row['status'] != 'unknown') or not remote_started:
            try:
                if json.loads(hold.read_text()) == owned_hold:
                    hold.unlink()
            except (OSError, ValueError):
                pass

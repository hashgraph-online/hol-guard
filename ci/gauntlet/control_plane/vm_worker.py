"""Install this reviewed standalone file as /opt/hol-gauntlet/worker.py, Root owned.

Only inert, Root-owned deployment manifests select a controller/config. Requests
cannot select commands, paths, profiles or executable candidate source.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

BASE = Path('/opt/hol-gauntlet')
OUTPUT = Path('/var/lib/hol-gauntlet/outputs')
BUILDS = Path('/var/lib/hol-gauntlet/builds')
ROLES = ('success', 'input-binding', 'injection', 'boundary', 'timeout', 'cancel')
CGROUPS = Path('/sys/fs/cgroup/system.slice')
PROC = Path('/proc')


def cell_resources(control):
    """Read kernel counters only for the active Root-declared product cell."""
    try:
        profile=control/'product/builtin-product/cell.apparmor'
        trusted(profile)
        match=re.search(r'^profile (hol-product-cell-[0-9a-f]{32}) ',profile.read_text(),re.M)
        if not match:
            return None
        group=CGROUPS/(match[1]+'.service')
        result={}
        for name,key in (('memory.current','memory_bytes'),('memory.max','memory_limit_bytes'),
                         ('memory.peak','peak_memory_bytes'),('pids.current','tasks'),('pids.max','task_limit')):
            value=(group/name).read_text().strip()
            if value.isdigit():result[key]=int(value)
        for name,key,event in (('memory.events','oom_kills','oom_kill'),('pids.events','pid_limit_hits','max')):
            counters=dict(line.split() for line in (group/name).read_text().splitlines())
            result[key]=int(counters.get(event,'0'))
        pids=(group/'cgroup.procs').read_text().split()
        if len(pids)>128 or any(not pid.isdigit() for pid in pids):
            return None
        native=[]
        for pid in pids:
            try:
                membership=(PROC/pid/'cgroup').read_text().splitlines()
                if '0::/system.slice/'+match[1]+'.service' not in membership:continue
                text=(PROC/pid/'status').read_text()
                fields=dict(line.split(':',1) for line in text.splitlines() if ':' in line)
                if fields.get('Name','').strip()!='hol-guard-runti':continue
                size=int(fields['VmSize'].split()[0])*1024
                peak=int(fields['VmPeak'].split()[0])*1024
                limit=re.search(r'^Max address space\s+(\d+)',(PROC/pid/'limits').read_text(),re.M)
                if limit:native.append((size,peak,int(limit[1])))
            except (OSError,ValueError,KeyError):continue
        if native:
            result.update(native_virtual_bytes=max(r[0] for r in native),
                          native_virtual_peak_bytes=max(r[1] for r in native),
                          native_address_space_limit_bytes=min(r[2] for r in native))
        return result
    except (OSError,ValueError):
        return None  # Missing/stopped cell is unavailable telemetry, never zero usage.


def process_identity(pid):
    try:
        row = Path('/proc')/str(pid)/'stat'
        # comm may contain spaces or parentheses; fields after the last ')'.
        fields = row.read_text().rsplit(')', 1)[1].split()
        return {'start_ticks': fields[19], 'cpu_seconds': (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
                'rss_bytes': int(fields[21]) * os.sysconf('SC_PAGE_SIZE'), 'process_state': fields[0]}
    except (OSError, ValueError, IndexError):
        return {}


def stage_progress(root, sha, phase, completed=(), current=None, *, total=5):
    value = {'source_sha': sha, 'phase': phase, 'updated_at': time.time(),
             'pid': os.getpid(), 'process_start_ticks': process_identity(os.getpid()).get('start_ticks'),
             'completed_controls': list(completed), 'total_controls': total, 'current_control': current}
    if isinstance(completed,dict):
        value['control_outcomes']=[{'role':role,'completed':record.get('control_completed') is True,
            'has_error':not record.get('control_completed') or any(bool(record.get(k)) for k in
                ('error','cleanup_error','gate_cleanup_error'))} for role,record in completed.items()]
    path = root/'stage-progress.json'
    temporary = root/'stage-progress.tmp'
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def progress(sha, job):
    result = {'source_sha': sha, 'job_id': job, 'checked_at': time.time(), 'phase': 'not-started'}
    started = OUTPUT/(job + '.started.json')
    receipt = OUTPUT/(job + '.json')
    stage = BASE/'candidates'/sha/'stage-progress.json'
    build = OUTPUT/(job + '.build-progress.json')
    controls=None
    if started.exists():
        value = read_json(started)
        if value.get('source_sha') != sha or value.get('job_id') != job:
            raise ValueError('worker progress identity mismatch')
        result.update(phase='benchmark-preflight', started_at=value.get('started_at'), pid=value.get('pid'),
                      total_controls=len(ROLES), completed_controls=[])
        root = Path('/home/hg-' + job)/'d'
        controls=root
        for role in ROLES:
            record = root/role/'control.json'
            if record.exists():
                data = read_json(record)
                result['completed_controls'].append({'role': role, 'completed': data.get('control_completed') is True,
                    'has_error': any(bool(data.get(k)) for k in ('error', 'cleanup_error', 'gate_cleanup_error'))})
            elif (root/role).exists():
                result.update(phase='benchmark-control', current_control=role)
                break
        if len(result['completed_controls']) == len(ROLES):
            result['phase'] = 'evidence-verification'
        if receipt.exists():
            result.update(phase='completed', status=read_json(receipt)['status'])
        identity = process_identity(value.get('pid', 0))
        result['process_alive'] = bool(identity) and identity.get('start_ticks') == value.get('process_start_ticks')
        if result['process_alive']:
            result.update({k: identity[k] for k in ('cpu_seconds', 'rss_bytes', 'process_state')})
    elif stage.exists():
        value = read_json(stage)
        if value.get('source_sha') != sha:
            raise ValueError('staging progress identity mismatch')
        result.update(value)
        controls=Path('/home/hc-'+sha[:16])
        identity = process_identity(value.get('pid', 0))
        result['process_alive'] = bool(identity) and identity.get('start_ticks') == value.get('process_start_ticks')
    elif build.exists():
        value = read_json(build)
        if value.get('source_sha') != sha or value.get('job_id') != job:
            raise ValueError('build progress identity mismatch')
        result.update(value)
        identity = process_identity(value.get('pid', 0))
        result['process_alive'] = bool(identity) and identity.get('start_ticks') == value.get('process_start_ticks')
        log=BUILDS/job/'build.log'
        if log.exists():
            trusted(log)
            with log.open('rb') as stream:
                info=os.fstat(stream.fileno())
                stream.seek(max(0,info.st_size-8192))
                lines=stream.read(8192).decode(errors='replace').splitlines()
            hints=[]
            for line in lines:
                match=re.match(r'^\s*(Compiling|Downloaded) ([A-Za-z0-9_-]+) v([0-9][A-Za-z0-9._+-]*)',line)
                if match:
                    hints.append((match[1]+' '+match[2]+' v'+match[3])[:200])
            result.update(build_log_bytes=info.st_size,build_log_updated_at=info.st_mtime,
                          build_log_hints=hints[-3:])
    if controls is not None and result.get('process_alive') and result.get('current_control') in ROLES:
        measured=cell_resources(controls/result['current_control'])
        if measured is not None:result['product_cell']=measured
    return result


def trusted(path, directory=False):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('canonical path required')
    for item in [path, *path.parents]:
        info = item.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('exclusively Root-owned paths required')
        if item != path or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('directory required')
        elif not stat.S_ISREG(info.st_mode):
            raise ValueError('regular file required')
    return path


def read_json(path):
    path = trusted(path)
    if path.stat().st_size > 1024**2:
        raise ValueError('manifest/result exceeds byte limit')
    return json.loads(path.read_text())


def deployment(sha):
    path = BASE/'candidates'/sha/'deployment.json'
    if not path.exists():
        return None, None
    value = read_json(path)
    if (set(value) != {'schema', 'source_sha', 'config', 'config_digest', 'asset_root',
                      'controller', 'python'} or value['schema'] != 'hol-gauntlet-deployment.v1'
            or value['source_sha'] != sha
            or not re.fullmatch(r'[0-9a-f]{64}', value['config_digest'])):
        raise ValueError('deployment schema or source identity differs')
    for key in ('asset_root', 'controller'):
        trusted(value[key], directory=True)
    # Python venv interpreter may be a symlink to a system interpreter. Both
    # link ancestry and canonical target must remain Root controlled.
    python = Path(value['python'])
    trusted(python.parent, directory=True)
    trusted(python.resolve())
    config = trusted(value['config'])
    canonical = json.dumps(json.loads(config.read_text()), sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode()
    if hashlib.sha256(canonical).hexdigest() != value['config_digest']:
        raise ValueError('configuration differs from external deployment pin')
    if json.loads(config.read_text())['runtime']['guard_source_sha'] != sha:
        raise ValueError('configuration references another source commit')
    # Explicitly protect every imported controller file from unprivileged edits.
    for file in Path(value['controller']).joinpath('ci').rglob('*.py'):
        trusted(file)
    return value, hashlib.sha256(path.read_bytes()).hexdigest()


def execute(request):
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise ValueError('dedicated Linux Root supervisor required')
    if set(request) - {'action', 'source_sha', 'job_id', 'deployment_digest'}:
        raise ValueError('unknown request fields')
    sha, job = request.get('source_sha', ''), request.get('job_id', '')
    if not re.fullmatch(r'[0-9a-f]{40}', sha) or not re.fullmatch(r'[0-9a-f]{16}', job):
        raise ValueError('exact source SHA and fixed job identity required')
    trusted(BASE, directory=True)
    trusted(OUTPUT, directory=True)
    receipt = OUTPUT/(job + '.json')
    action = request.get('action')
    if action == 'progress':
        return progress(sha, job)  # read-only; never acquire the active worker lease
    if action == 'reconcile':
        if not receipt.exists():
            return {'status': 'unknown', 'error': 'No terminal worker receipt; inspect VM before admitting more work'}
        result = read_json(receipt)
        if result['source_sha'] != sha or result['job_id'] != job:
            raise ValueError('receipt identity mismatch')
        return result
    value, pin = deployment(sha)
    if action == 'inspect':
        return {'ready': value is not None, 'deployment_digest': pin, 'source_sha': sha}
    if action != 'run' or value is None or pin != request.get('deployment_digest'):
        raise ValueError('matching staged deployment and external digest required')
    # A second host, restarted host agent, or direct invocation cannot replay a job.
    lock = BASE/'worker.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode):
            raise ValueError('invalid worker lease')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = OUTPUT/(job + '.started.json')
        with started.open('x') as stream:
            json.dump({'source_sha': sha, 'job_id': job, 'deployment_digest': pin, 'started_at': time.time()}, stream)
        state, output = '/home/hg-' + job, str(OUTPUT/job)
        code = 'import sys;sys.path.insert(0,sys.argv.pop(1));from ci.gauntlet.benchmark.__main__ import main;raise SystemExit(main())'
        command = [value['python'], '-I', '-B', '-c', code, value['controller'], 'ci', 'check',
                   '--profile', 'deterministic', '--config', value['config'],
                   '--expected-config-digest', value['config_digest'],
                   '--expected-guard-source-sha', sha, '--asset-root', value['asset_root'],
                   '--state-root', state, '--output-dir', output]
        # No Python imports or package installation from the candidate as Root.
        # Existing private-cell backend executes Guard under its restricted UID.
        with (OUTPUT/(job + '.log')).open('x') as log:
            process = subprocess.Popen(command, cwd=value['controller'],
                                     env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'},
                                     stdout=log, stderr=subprocess.STDOUT)
            identity = process_identity(process.pid)
            temporary = started.with_suffix('.tmp')
            temporary.write_text(json.dumps({'source_sha': sha, 'job_id': job, 'deployment_digest': pin,
                'started_at': time.time(), 'pid': process.pid, 'process_start_ticks': identity.get('start_ticks')}))
            temporary.replace(started)
            process.wait()
        result = {'source_sha': sha, 'job_id': job, 'deployment_digest': pin,
                  'exit_code': process.returncode, 'report_path': output + '/report',
                  'status': 'invalid-evidence', 'model_tokens': 0}
        report = Path(output)/'report/result.json'
        if report.exists():
            data = read_json(report)
            if (data.get('schema') != 'gauntlet-ci-check.v1'
                    or data.get('expected_guard_source_sha') != sha
                    or data.get('guard_source_sha') != sha
                    or data.get('runner_config_digest') != value['config_digest']
                    or data.get('exit_code') != process.returncode
                    or data.get('profile') != 'deterministic'
                    or data.get('model_tokens') != 0 or data.get('model_usage_known') is not True):
                raise ValueError('terminal benchmark report identity/usage mismatch')
            result.update(status=data['status'], cells=data.get('cells', []),
                          elapsed_seconds=data.get('elapsed_seconds'),
                          report_sha256=hashlib.sha256(report.read_bytes()).hexdigest())
        with receipt.open('x') as stream:
            json.dump(result, stream)
        return result
    finally:
        os.close(fd)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError('request byte limit')
        print(json.dumps(execute(json.loads(raw))))
    except Exception as error:
        print(json.dumps({'status': 'error', 'error': type(error).__name__ + ': ' + str(error)[:1500]}))
        raise SystemExit(2)

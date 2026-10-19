"""Root VM supervisor for an optional, model-free installed feature audit."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

BASE = Path('/opt/hol-gauntlet')
BUILDS = Path('/var/lib/hol-gauntlet/builds')
AUDITS = Path('/var/lib/hol-gauntlet/features')
NODE = Path('/opt/hol-workflow-matrix-public-20261014-001/node/bin/node')
NODE_SHA256 = '3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90'


def read_bounded(path, maximum=1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError('bounded ordinary audit evidence required')
        raw = stream.read(maximum+1)
    if len(raw) != info.st_size:
        raise ValueError('audit evidence changed during read')
    return json.loads(raw)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def request_identity(request):
    if (not isinstance(request, dict) or
            set(request) != {'action', 'audit_id', 'source_sha', 'build_job_id',
                             'source_archive_sha256', 'candidate_archive_sha256'} or
            request['action'] not in {'run', 'status'} or
            not re.fullmatch('[0-9a-f]{16}', request['audit_id']) or
            not re.fullmatch('[0-9a-f]{16}', request['build_job_id']) or
            not re.fullmatch('[0-9a-f]{40}', request['source_sha']) or
            any(not re.fullmatch('[0-9a-f]{64}', request[name]) for name in
                ('source_archive_sha256', 'candidate_archive_sha256'))):
        raise ValueError('exact source-bound feature audit request required')


def terminal(root, value):
    path = root/'result.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
    path.chmod(0o444)
    return value


def status(request):
    request_identity(request)
    root = AUDITS/request['audit_id']
    if not root.is_dir():
        raise ValueError('feature audit identity not found')
    declaration = read_bounded(root/'request.json', 4096)
    if declaration != {**request, 'action': 'run'}:
        raise ValueError('feature audit source identity differs')
    if (root/'result.json').is_file():
        return read_bounded(root/'result.json')
    result = {'schema': 'hol-gauntlet-feature-run.v1', 'status': 'running',
              'audit_id': request['audit_id'], 'source_sha': request['source_sha']}
    try:
        progress = read_bounded(root/'output/progress.json', 16*1024)
        if progress.get('audit_id') == request['audit_id'] and progress.get('source_sha') == request['source_sha']:
            result.update(progress)
    except (OSError, ValueError, TypeError):
        pass
    return result


def run(request):
    request_identity(request)
    if os.geteuid() != 0 or sys.platform != 'linux' or not sys.flags.isolated:
        raise ValueError('trusted isolated Linux Root supervisor required')
    helpers = runpy.run_path(str(BASE/'worker.py'), run_name='trusted_worker_helpers')
    settings = helpers['read_json'](BASE/'stage-settings.json')
    controller = helpers['trusted'](settings['controller'], directory=True)
    sys.path.insert(0, str(controller))
    from ci.gauntlet.control_plane.feature_entry import FEATURES
    from ci.gauntlet.control_plane.artifacts import inspect_archive

    with (BASE/'worker.lock').open('r+') as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        build = BUILDS/request['build_job_id']
        built = read_bounded(helpers['trusted'](build/'result.json'))
        if (built.get('status') != 'built' or built.get('source_sha') != request['source_sha']
                or built.get('archive_sha256') != request['candidate_archive_sha256']):
            raise ValueError('successful exact-commit retained build required')
        source = helpers['trusted'](build/'source.tar.gz')
        candidate = helpers['trusted'](build/'candidate.zip')
        if (sha(source) != request['source_archive_sha256']
                or sha(candidate) != request['candidate_archive_sha256']
                or inspect_archive(candidate, request['source_sha'])['version'] != built['version']):
            raise ValueError('retained source or candidate archive differs')
        AUDITS.mkdir(mode=0o700, exist_ok=True)
        root = AUDITS/request['audit_id']
        root.mkdir(mode=0o700)
        with (root/'request.json').open('x', encoding='utf-8') as stream:
            json.dump(request, stream, sort_keys=True)
            stream.write('\n')
        (root/'request.json').chmod(0o444)
        output = root/'output'
        output.mkdir(mode=0o700)
        os.chown(output, 65532, 65532)
        tool = controller/'ci/gauntlet/control_plane'
        node = helpers['trusted'](NODE)
        if sha(node) != NODE_SHA256:
            raise ValueError('pinned Linux ARM Node asset differs')
        for name in ('Builder.Dockerfile', 'builder_entry.py', 'build_artifact.py',
                     'feature_entry.py', 'Builder.apparmor'):
            helpers['trusted'](tool/name)
        identity = hashlib.sha256(b''.join((tool/name).read_bytes() for name in
            ('Builder.Dockerfile', 'builder_entry.py', 'build_artifact.py'))).hexdigest()
        image = 'localhost/hol-gauntlet-builder:' + identity[:20]
        present = subprocess.run(['/usr/bin/podman', 'image', 'exists', image],
                                 capture_output=True, timeout=30)
        if present.returncode:
            raise ValueError('exact reviewed builder image missing; rebuild the candidate before feature audit')
        profile = 'hol-gauntlet-feature-'+request['audit_id']
        policy = root/'Builder.apparmor'
        policy.write_text((tool/'Builder.apparmor').read_text().replace('HOL_GAUNTLET_BUILD_PROFILE', profile))
        subprocess.run(['/usr/sbin/apparmor_parser', '--replace', str(policy)],
                       capture_output=True, check=True, timeout=30)
        command = ['/usr/bin/podman', 'run', '--rm', '--name', profile,
                   '--user', '65532:65532', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges', '--security-opt=apparmor='+profile,
                   '--memory='+str(settings.get('build_memory_gib', 12))+'g',
                   '--memory-swap='+str(settings.get('build_memory_gib', 12))+'g',
                   '--cpus=2', '--pids-limit=2048', '--network=slirp4netns', '--ipc=private',
                   '--volume', str(source)+':/input/source.tar.gz:ro',
                   '--volume', str(candidate)+':/input/candidate.zip:ro',
                   '--volume', str(tool/'feature_entry.py')+':/opt/gauntlet/feature_entry.py:ro',
                   '--volume', str(node)+':/usr/local/bin/node:ro',
                   '--volume', str(output)+':/output:rw',
                   '--env', 'HOL_GUARD_BUILD_SHA='+request['source_sha'],
                   '--env', 'HOL_GUARD_AUDIT_ID='+request['audit_id'],
                   '--env', 'HOL_GUARD_FEATURE_AUDIT=1',
                   '--entrypoint=/usr/local/bin/gauntlet-python', image,
                   '-I', '-B', '/opt/gauntlet/feature_entry.py']
        code, uncertain, error = None, False, None
        started = time.time()
        try:
            with (root/'container.log').open('x') as log:
                process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                         timeout=14400, check=False)
                code = process.returncode
        except subprocess.TimeoutExpired:
            uncertain = True
            error = 'container command timed out; inspect retained container before new admission'
        except Exception as exc:
            error = type(exc).__name__+': '+str(exc)[:500]
        finally:
            exists = subprocess.run(['/usr/bin/podman', 'container', 'exists', profile],
                                    capture_output=True, timeout=30)
            if exists.returncode != 1:
                uncertain = True
                error = 'feature container still exists; cleanup cannot be verified'
            else:
                subprocess.run(['/usr/sbin/apparmor_parser', '--remove', str(policy)],
                               capture_output=True, check=True, timeout=30)
        groups = []
        try:
            report = read_bounded(output/'contracts.json', 128*1024)
            if (report.get('schema') != 'hol-gauntlet-feature-contracts.v1'
                    or report.get('audit_id') != request['audit_id']
                    or report.get('source_sha') != request['source_sha']
                    or report.get('wheel_sha256') != inspect_archive(candidate, request['source_sha'])['wheel_sha256']
                    or [row.get('id') for row in report.get('groups', [])] != [row[0] for row in FEATURES]):
                raise ValueError('feature evidence identity or inventory differs')
            groups = report['groups']
        except (OSError, ValueError, TypeError, KeyError):
            error = error or 'complete source-bound feature result missing'
        status_value = ('unknown' if uncertain else 'passed' if code == 0 and
                        groups and all(row.get('status') == 'passed' for row in groups)
                        else 'failed' if groups else 'invalid-evidence')
        result = {'schema': 'hol-gauntlet-feature-run.v1', 'audit_id': request['audit_id'],
                  'source_sha': request['source_sha'], 'build_job_id': request['build_job_id'],
                  'status': status_value, 'exit_code': code, 'groups': groups,
                  'completed_groups': len(groups), 'total_groups': len(FEATURES),
                  'model_requests': 0, 'model_tokens': 0, 'qualification_eligible': False,
                  'started_at': started, 'finished_at': time.time(), 'error': error,
                  'report_sha256': sha(output/'contracts.json') if groups else None}
        return terminal(root, result)


if __name__ == '__main__':
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError('feature request too large')
    request = json.loads(raw)
    result = run(request) if request.get('action') == 'run' else status(request)
    print(json.dumps(result, sort_keys=True))

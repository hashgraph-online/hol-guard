"""Root supervisor for a disposable unprivileged release builder, without CI."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import stat
import subprocess
import sys
import time

BASE = Path('/opt/hol-gauntlet')
BUILDS = Path('/var/lib/hol-gauntlet/builds')
OUTPUT = Path('/var/lib/hol-gauntlet/outputs')


class BuildCleanupUncertain(RuntimeError):
    pass


def failure_detail(error, log, phase):
    """Retain useful diagnostics privately; avoid replacing errors with argv dumps."""
    log.flush()
    with Path(log.name).open('rb') as stream:
        stream.seek(max(0, Path(log.name).stat().st_size - 8192))
        tail = stream.read(8192).decode('utf-8', errors='replace')
    lines = [line.strip() for line in tail.splitlines() if line.strip()]
    summary = next((line for line in reversed(lines) if
                    any(key in line.lower() for key in ('error:', 'not found', 'no such file', 'permission denied'))),
                   lines[-1] if lines else type(error).__name__ + ': ' + str(error))
    contracts = [line[7:].split(' - ',1)[0] for line in lines if line.startswith('FAILED tests/')]
    if contracts:
        phase = 'product-contracts'
        summary = 'Product contract tests failed: ' + ', '.join(contracts[-4:])
    if 'SIGKILL' in tail:
        summary = 'Build process killed by SIGKILL; memory-limit exhaustion is possible. Inspect the retained compiler log.'
    return {'error': summary[:700], 'diagnostic_tail': tail, 'failure_phase': phase,
            'exit_code': getattr(error, 'returncode', None),
            'log_path': str(log.name)}


def capture(source, target, expected, *, maximum=256*1024**2):
    """Capture a bounded regular file once; never follow candidate symlinks."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb') as stream, target.open('xb') as out:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError('bounded ordinary build input/output required')
        total = 0
        for chunk in iter(lambda: stream.read(1024**2), b''):
            total += len(chunk)
            if total > maximum:
                raise ValueError('build byte limit')
            digest.update(chunk)
            out.write(chunk)
    actual = digest.hexdigest()
    if expected is not None and actual != expected:
        raise ValueError('captured build bytes differ from external digest')
    target.chmod(0o444)
    return actual


def container_command(image, job, sha, tag, root, memory_gib=12, *, local_version=None, profile=None, retest=False):
    if type(memory_gib) is not int or not 1 <= memory_gib <= 128:
        raise ValueError('bounded positive build memory required')
    return ['/usr/bin/podman', 'run', '--rm', '--name', 'hol-gauntlet-build-' + job,
        '--user', '65532:65532', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        *(['--security-opt=apparmor='+profile] if profile else []),
        '--memory=' + str(memory_gib) + 'g', '--memory-swap=' + str(memory_gib) + 'g', '--cpus=2', '--pids-limit=512',
        '--network=slirp4netns', '--ipc=private',
        '--volume', str(root/'source.tar.gz') + ':/input/source.tar.gz:ro',
        '--volume', str(root/'export') + ':/output:rw',
        '--env', 'HOL_GUARD_BUILD_SHA=' + sha, '--env', 'HOL_GUARD_RELEASE_TAG=' + tag,
        *(['--volume',str(root/'retest-candidate.zip')+':/input/candidate.zip:ro',
           '--env','HOL_GUARD_RETEST=1'] if retest else []),
        *(['--env', 'HOL_GUARD_LOCAL_VERSION=' + local_version] if local_version else []), image]


def execute(request):
    if os.geteuid() != 0 or sys.platform != 'linux' or not sys.flags.isolated:
        raise ValueError('isolated trusted Linux Root supervisor required')
    local = request.get('kind') == 'local-candidate'
    fields = {'source_sha', 'job_id', 'tag', 'source_archive_sha256'}
    retest=request.get('retest_build_job_id')
    if retest is not None:
        if not local or not isinstance(retest,str) or not re.fullmatch('[0-9a-f]{16}',retest):
            raise ValueError('fixed retained local build identity required')
        fields.add('retest_build_job_id')
    if set(request) != (fields | {'kind','version'} if local else fields):
        raise ValueError('fixed local build request required')
    sha, job, tag = request['source_sha'], request['job_id'], request['tag']
    if (not re.fullmatch('[0-9a-f]{40}', sha) or not re.fullmatch('[0-9a-f]{16}', job)
            or (not (tag == 'local-' + sha and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:a[1-9][0-9]*)?', request.get('version',''))) if local else tag not in {'v3.48.0', 'v3.49.0'})
            or not re.fullmatch('[0-9a-f]{64}', request['source_archive_sha256'])):
        raise ValueError('allowed release, commit, job and source digest required')
    helpers = runpy.run_path(str(BASE/'worker.py'), run_name='trusted_worker_helpers')
    read, trusted = helpers['read_json'], helpers['trusted']
    settings = read(BASE/'stage-settings.json')
    controller = trusted(settings['controller'], directory=True)
    sys.path.insert(0, str(controller))
    from ci.gauntlet.control_plane.artifacts import inspect_archive
    tool_root = controller/'ci/gauntlet/control_plane'
    for name in ('Builder.Dockerfile', 'Builder.apparmor', 'builder_entry.py', 'build_artifact.py'):
        trusted(tool_root/name)
    with (BASE/'worker.lock').open('r+') as lease:
        trusted(BASE/'worker.lock')
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        BUILDS.mkdir(mode=0o700, exist_ok=True)
        trusted(BUILDS, directory=True)
        root = BUILDS/job
        root.mkdir(mode=0o700)  # exclusive: ambiguous remote builds are never replayed
        progress = OUTPUT/(job + '.build-progress.json')
        def emit(phase):
            value = {'source_sha': sha, 'job_id': job, 'phase': phase, 'pid': os.getpid(),
                     'process_start_ticks': helpers['process_identity'](os.getpid()).get('start_ticks'),
                     'updated_at': time.time()}
            tmp = progress.with_suffix('.tmp')
            tmp.write_text(json.dumps(value))
            tmp.replace(progress)
        emit('source-verification')
        inbox = Path(settings['guest_inbox'])/('hol-gauntlet-source-' + job + '.tar.gz')
        capture(inbox, root/'source.tar.gz', request['source_archive_sha256'])
        if retest:
            old=read(BUILDS/retest/'result.json')
            if (old.get('status')!='build-failed' or old.get('failure_phase')!='product-contracts'
                    or old.get('source_sha')!=sha or old.get('job_id')!=retest
                    or old.get('retained_version')!=request['version']
                    or not isinstance(old.get('retained_archive_sha256'),str)
                    or not re.fullmatch('[0-9a-f]{64}',old['retained_archive_sha256'])
                    or (OUTPUT/(retest+'.started.json')).exists()):
                raise ValueError('retained unadmitted compiled artifact with failed contracts required')
            if subprocess.run(['/usr/bin/podman','container','exists','hol-gauntlet-build-'+retest],capture_output=True,timeout=30).returncode!=1:
                raise ValueError('retained build container is live or unresolved')
            capture(trusted(BUILDS/retest/'candidate.zip'),root/'retest-candidate.zip',old['retained_archive_sha256'])
            retained=inspect_archive(root/'retest-candidate.zip',sha)
            if retained['version']!=request['version']:
                raise ValueError('retained version differs from local candidate')
        (root/'export').mkdir(mode=0o700)
        os.chown(root/'export', 65532, 65532)
        # Identity covers every installed context file, not candidate source.
        identity = hashlib.sha256(b''.join((tool_root/n).read_bytes() for n in
            ('Builder.Dockerfile', 'builder_entry.py', 'build_artifact.py'))).hexdigest()
        image = 'localhost/hol-gauntlet-builder:' + identity[:20]
        result = {'source_sha': sha, 'job_id': job, 'tag': tag, 'status': 'build-failed'}
        if retest:result['retest_build_job_id']=retest
        with (root/'build.log').open('x') as log:
            phase = 'builder-image'
            try:
                phase = 'build-network-preflight'
                emit(phase)
                helper = shutil.which('slirp4netns', path='/usr/sbin:/usr/bin:/sbin:/bin')
                if helper is None:
                    raise RuntimeError('slirp4netns is missing from the VM; run gauntlet repair --retry-builds to install it and retry')
                trusted(Path(helper).resolve())
                phase = 'builder-image'
                emit('builder-image')
                found = subprocess.run(['/usr/bin/podman', 'image', 'exists', image], check=False,
                                       stdout=log, stderr=subprocess.STDOUT, timeout=30)
                if found.returncode:
                    subprocess.run(['/usr/bin/podman', 'build', '--pull=missing', '--tag', image,
                                    '--file', str(tool_root/'Builder.Dockerfile'), str(tool_root)],
                                   stdout=log, stderr=subprocess.STDOUT, check=True, timeout=1200)
                image_id = subprocess.check_output(['/usr/bin/podman', 'image', 'inspect',
                    '--format', '{{.Id}}', image], text=True, timeout=30).strip()
                image_id = image_id.removeprefix('sha256:')
                if not re.fullmatch(r'[0-9a-f]{64}', image_id):
                    raise ValueError('builder image digest required')
                image_id = 'sha256:' + image_id
                result['builder_image'] = image_id
                phase = 'release-compilation'
                emit('release-compilation')
                profile='hol-gauntlet-build-'+job
                policy=root/'Builder.apparmor'
                policy.write_text((tool_root/'Builder.apparmor').read_text().replace('HOL_GAUNTLET_BUILD_PROFILE',profile))
                subprocess.run(['/usr/sbin/apparmor_parser','--replace',str(policy)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=30)
                result['build_profile_sha256']=hashlib.sha256(policy.read_bytes()).hexdigest()
                try:
                    subprocess.run(container_command(image_id, job, sha, tag, root, settings.get('build_memory_gib', 12), local_version=request['version'] if local else None,profile=profile,retest=bool(retest)), stdout=log,
                                   stderr=subprocess.STDOUT, check=True, timeout=2100)
                finally:
                    remaining=subprocess.run(['/usr/bin/podman','container','exists','hol-gauntlet-build-'+job],stdout=log,stderr=subprocess.STDOUT,timeout=30)
                    if remaining.returncode==1:
                        subprocess.run(['/usr/sbin/apparmor_parser','--remove',str(policy)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=30)
                        result['build_profile_removed']=True
                    else:
                        raise BuildCleanupUncertain('container disappearance not verified')
                emit('built-artifact-verification')
                phase = 'built-artifact-verification'
                digest = capture(root/'export/candidate.zip', root/'candidate.zip', None)
                declaration = inspect_archive(root/'candidate.zip', sha)
                if declaration['version'] != (request['version'] if local else tag[1:]):
                    raise ValueError('built version differs from selected tag')
                result.update(status='built', archive_sha256=digest, version=declaration['version'])
                emit('release-built')
            except (subprocess.TimeoutExpired,BuildCleanupUncertain):
                # The container may outlive its client. Keep an unresolved
                # receipt and block all benchmark admission until inspection.
                result.update(status='unknown', error='Build completion or cleanup cannot be proven; inspect the retained container, profile and build log')
                emit('build-interrupted')
            except Exception as error:
                result.update(failure_detail(error, log, phase))
                if local and (root/'export/candidate.zip').exists():
                    # Failed tests never admit a build, but retain its inert
                    # compiled artifact so diagnosis does not lose the bytes.
                    try:
                        retained_digest = capture(root/'export/candidate.zip',root/'candidate.zip',None)
                        retained = inspect_archive(root/'candidate.zip',sha)
                        if retained['version'] != request['version']:
                            raise ValueError('retained artifact version mismatch')
                        result.update(retained_archive_sha256=retained_digest,
                                      retained_version=retained['version'])
                    except Exception as retention_error:
                        result['retained_artifact_error'] = str(retention_error)[:300]
                emit('build-failed')
        with (root/'result.json').open('x') as stream:
            json.dump(result, stream)
        return result


if __name__ == '__main__':
    os.umask(0o077)
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError('build request limit')
    print(json.dumps(execute(json.loads(raw))))

"""Pull exact Git objects on the host; compile and test only in the ARM VM."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import re

from .artifacts import StagingUncertain
from .config import SHA


def git_command(config):
    helper = '!' + shlex.quote(config['gh']) + ' auth git-credential'
    return [config['git'], '-c', 'core.hooksPath=/dev/null', '-c', 'fetch.fsckObjects=true',
            '-c', 'credential.helper=', '-c', 'credential.helper=' + helper]


def resolve_release(config, tag):
    if tag not in config['release_tags'] or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
        raise ValueError('explicit stable tag allowlist required')
    ref = 'refs/tags/' + tag
    output = subprocess.check_output([*git_command(config), 'ls-remote', '--exit-code', '--tags',
        'https://github.com/' + config['repository'] + '.git', ref, ref + '^{}'],
        text=True, env=dict(os.environ, GIT_TERMINAL_PROMPT='0'), timeout=60)
    refs = {}
    for line in output.splitlines():
        sha, name = line.split('\t')
        if name not in {ref, ref + '^{}'} or name in refs or not SHA.fullmatch(sha):
            raise ValueError('unexpected or ambiguous Git tag response')
        refs[name] = sha
    if ref not in refs:
        raise ValueError('exact release tag is missing')
    return {'tag': tag, 'sha': refs.get(ref + '^{}', refs[ref]),
            'url': 'https://github.com/' + config['repository'] + '/releases/tag/' + tag}


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            value.update(chunk)
    return value.hexdigest()


def source_archive(config, job, directory):
    """No checkout or product/build code executes on the Mac."""
    archive = directory/'source.tar.gz'
    if archive.exists():
        if digest(archive) != job.get('source_archive_sha256'):
            raise ValueError('retained source archive differs; inspect before rebuilding')
        return archive
    bare = directory/'repository.git'
    environment = dict(os.environ, GIT_TERMINAL_PROMPT='0')
    git = git_command(config)
    if not bare.exists():
        subprocess.run([*git, 'init', '--bare', '--template=', str(bare)], env=environment,
                       check=True, capture_output=True, timeout=30)
    # Override, rather than inspect or copy, the credential helper chain. Its
    # existing broker stays on the host. No credentials enter config or archive.
    local = job.get('kind') == 'local-candidate'
    if local:
        from .local_candidate import verify
        verify(job)
    ref = ('refs/heads/' if local else 'refs/tags/') + job['tag']
    source = job['source_path'] if local else 'https://github.com/' + config['repository'] + '.git'
    fetch_ref = job['sha'] if local else ref
    subprocess.run([*git, '--git-dir=' + str(bare), 'fetch', '--no-tags', '--no-recurse-submodules', '--depth=1',
        source, fetch_ref + ':' + ref],
        env=environment, capture_output=True, check=True, timeout=300)
    actual = subprocess.check_output([*git, '--git-dir=' + str(bare), 'rev-parse',
        ref + '^{commit}'], env=environment, text=True, timeout=30).strip()
    if actual != job['sha']:
        raise ValueError('fetched release tag differs from independently resolved commit')
    files = sorted(bare.rglob('*'))
    if len(files) > 100000 or sum(p.stat().st_size for p in files if p.is_file()) > 512*1024**2:
        raise ValueError('source Git object inventory limit')
    temporary = directory/'source.tar.gz.partial'
    with tarfile.open(temporary, 'x:gz') as bundle:
        for path in files:
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError('ordinary Git object files required')
            bundle.add(path, arcname='repository.git/' + path.relative_to(bare).as_posix(), recursive=False)
    if temporary.stat().st_size > 256*1024**2:
        raise ValueError('compressed source archive limit')
    job['source_archive_sha256'] = digest(temporary)
    temporary.rename(archive)
    return archive


def prepare(agent, job):
    c = agent.config
    directory = agent.state/'private/local-builds'/job['id']
    directory.mkdir(parents=True, exist_ok=True)
    if not job.get('local_build'):
        agent.activity(job, 'source-fetch', 'Pulling ' + job['tag'] + ' as Git objects; no build code runs on the Mac')
        archive = source_archive(c, job, directory)
        agent.save(job)
        agent.activity(job, 'source-transfer', 'Transferring verified source to the ARM VM')
        guest = c['guest_inbox'] + '/hol-gauntlet-source-' + job['id'] + '.tar.gz'
        subprocess.run([c['limactl'], 'copy', str(archive), c['vm'] + ':' + guest],
                       capture_output=True, check=True, timeout=120)
        job['local_build'] = {'status': 'starting', 'source_sha': job['sha']}
        agent.activity(job, 'local-build', 'Building release in a disposable ARM64 container (2 CPUs / '
                       + str(c['build_memory_gib']) + ' GiB RAM)')
        request = {'source_sha': job['sha'], 'job_id': job['id'], 'tag': job['tag'],
                   'source_archive_sha256': job['source_archive_sha256']}
        if job.get('kind') == 'local-candidate':
            request.update(kind='local-candidate', version=job['version'])
            if job.get('retest_build_job_id'):
                request['retest_build_job_id']=job['retest_build_job_id']
        try:
            with (directory/'build-launch.log').open('x') as log:
                result = subprocess.run([c['limactl'], 'shell', c['vm'], '--', 'sudo', '-n',
                    c['guest_python'], '-I', '-B', '/opt/hol-gauntlet/build.py'],
                    input=json.dumps(request), capture_output=True, text=True,
                    timeout=c['job_timeout_seconds'])
                log.write(result.stderr[:10000])
                if result.returncode or len(result.stdout) > 1024**2:
                    raise RuntimeError('VM build refused or returned invalid output; inspect build-launch.log')
                receipt = json.loads(result.stdout)
            if (receipt.get('source_sha') != job['sha'] or receipt.get('job_id') != job['id']
                    or receipt.get('tag') != job['tag']):
                raise ValueError('local build receipt identity mismatch')
            job['local_build'] = receipt
            (directory/'build-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
            if receipt.get('diagnostic_tail'):
                (directory/'build-error.log').write_text(receipt['diagnostic_tail'])
            agent.save(job)
        except Exception as error:
            raise StagingUncertain('Local build observation interrupted; inspect retained VM build before retry: ' + str(error)) from error
    receipt = job['local_build']
    if receipt['status'] == 'build-failed':
        import time
        job.update(state='build-failed', finished_at=time.time(),
                   reason='Local release build failed; VM benchmark did not execute. ' + receipt.get('error', ''))
        agent.activity(job, 'build-failed', job['reason'])
        return False
    if receipt['status'] != 'built':
        raise StagingUncertain('Local build is unresolved; inspect VM build receipt and container before continuing')
    agent.activity(job, 'candidate-staging', 'Validating locally built wheel and running six diagnostic controls, including five admission controls')
    try:
        with (directory/'stage.log').open('x') as log:
            subprocess.run([c['limactl'], 'shell', c['vm'], '--', 'sudo', '-n', c['guest_python'],
                '-I', '-B', '/opt/hol-gauntlet/stage.py'],
                input=json.dumps({'source_sha': job['sha'], 'archive_sha256': receipt['archive_sha256'],
                                  'build_job_id': receipt.get('job_id', job['id'])}),
                stdout=log, stderr=subprocess.STDOUT, text=True, check=True,
                timeout=c['job_timeout_seconds'])
    except Exception as error:
        detail=str(error)
        try:
            from .diagnostics import collect, summary
            observed=collect(c,job,directory)
            detail=summary(observed)
            job['stage_error']=detail
            agent.save(job)
        except Exception as diagnostic_error:
            detail+='; diagnostics unavailable: '+str(diagnostic_error)[:300]
        raise StagingUncertain('Local staging stopped; inspect retained stage.log and stage-diagnostic.json: '+detail) from error
    with (directory/'stage.log').open('rb') as stream:
        stream.seek(0,2)
        stream.seek(max(0,stream.tell()-8192))
        lines=stream.read().splitlines()
    try:
        hint=json.loads(lines[-1]) if lines else {}
    except (ValueError,UnicodeError):
        hint={}
    if not isinstance(hint,dict) or hint.get('status') not in {'conformance-failed','diagnostic-passed'}:
        return True  # The Root worker independently verifies the deployment.
    from .diagnostics import collect, summary
    observed=collect(c,job,directory)
    terminal=observed.get('stage_result',{})
    if terminal.get('status') in {'conformance-failed','diagnostic-passed'}:
        if (terminal.get('source_sha')!=job['sha'] or terminal.get('build_job_id')!=receipt.get('job_id',job['id'])
                or terminal.get('controls')!=6 or terminal.get('conformance_controls')!=5
                or terminal.get('benchmark_admitted') is not False
                or terminal.get('cleanup_verified') is not True):
            raise StagingUncertain('Terminal staging receipt identity or cleanup mismatch')
        import time
        status=terminal['status']
        if status=='diagnostic-passed' and (len(terminal.get('cells',[]))!=6
                or {r.get('episode_id') for r in terminal['cells']}!={'success','input-binding','injection','boundary','timeout','cancel'}
                or any(r.get('status')!='passed' for r in terminal['cells'])
                or not terminal.get('missing_capabilities')):
            raise StagingUncertain('Diagnostic receipt lacks six verified controls or capability gap')
        reason=('All six diagnostic controls passed; strict benchmark admission blocked by release capability: '
                + ', '.join(terminal['missing_capabilities'])) if status=='diagnostic-passed' else summary(observed)
        job.update(state=status,finished_at=time.time(),stage_result=terminal,
                   reason=reason,vm_progress={**observed.get('stage',{}),
                       'job_id':job['id'],'source_sha':job['sha'],
                       'checked_at':time.time(),'process_alive':False})
        agent.activity(job,status,job['reason'])
        return False
    raise StagingUncertain('Staging reported rejection without a matching retained terminal receipt')

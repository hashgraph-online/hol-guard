"""Bind uploaded candidates to the workflow run and PR head; transfer inertly."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


class StagingUncertain(RuntimeError):
    """A remote staging attempt may have executed controls; never replay it."""


def archive_digest(path):
    if Path(path).stat().st_size > 256*1024**2:
        raise ValueError('artifact compressed byte limit')
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            value.update(chunk)
    return 'sha256:' + value.hexdigest()


def inspect_archive(path, sha):
    if Path(path).stat().st_size > 256*1024**2:
        raise ValueError('artifact compressed byte limit')
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if (len(names) != 2 or len(set(names)) != 2 or 'artifact.json' not in names
                or any(i.file_size > 256*1024**2 for i in infos)
                or sum(i.file_size for i in infos) > 257*1024**2
                or archive.getinfo('artifact.json').file_size > 8192):
            raise ValueError('bounded two-file artifact required')
        data = json.loads(archive.read('artifact.json'))
        wheel = data.get('wheel', '')
        if (set(data) != {'schema', 'source_sha', 'version', 'wheel', 'wheel_sha256', 'native_sha256'}
                or data['schema'] != 'hol-gauntlet-pr-artifact.v1' or data['source_sha'] != sha
                or not re.fullmatch(r'hol_guard-[A-Za-z0-9_.]+-py3-none-linux_aarch64\.whl', wheel)
                or set(names) != {'artifact.json', wheel}
                or not re.fullmatch(r'[0-9a-f]{64}', data['wheel_sha256'])
                or not re.fullmatch(r'[0-9a-f]{64}', data['native_sha256'])):
            raise ValueError('artifact source, filenames or hash declarations differ')
        raw = archive.read(wheel)
        if hashlib.sha256(raw).hexdigest() != data['wheel_sha256']:
            raise ValueError('wheel bytes differ from declaration')
    return data


def select_artifact(github, job):
    workflow = github.config['artifact_workflow']
    release = job.get('kind') == 'release'
    query = '?per_page=100' if release else '?head_sha=' + job['sha'] + '&per_page=100'
    try:
        runs = github.api(github.repo + '/actions/workflows/' + workflow + '/runs' + query)
    except RuntimeError as error:
        if 'HTTP 404' in str(error):
            return None  # workflow has not been published/enabled yet
        raise
    if release:
        from .releases import build_title
        dispatch = job.get('build_dispatch', {})
        matches = [r for r in runs['workflow_runs']
                   if r.get('event') == 'workflow_dispatch' and r.get('head_branch') == 'main'
                   and r.get('head_sha') == dispatch.get('controller_sha')
                   and r.get('display_title') == build_title(job)
                   and r.get('path') == '.github/workflows/' + workflow]
    else:
        matches = [r for r in runs['workflow_runs'] if r.get('head_sha') == job['sha']
                   and r.get('event') == 'pull_request' and r.get('path') == '.github/workflows/' + workflow
                   and any(p['number'] == job['pr'] for p in r.get('pull_requests', []))]
    if not matches:
        return None
    newest = max(matches, key=lambda r: (r['id'], r.get('run_attempt', 1)))
    job['build_run'] = {k: newest.get(k) for k in ('id', 'html_url', 'status', 'conclusion', 'updated_at')}
    if newest['status'] != 'completed' or newest['conclusion'] != 'success':
        return None
    artifacts = github.api(github.repo + f"/actions/runs/{newest['id']}/artifacts?per_page=100")['artifacts']
    found = [a for a in artifacts if not a['expired'] and
             a['name'] == 'hol-gauntlet-linux-arm64-' + job['sha']]
    if len(found) != 1:
        raise ValueError('exact single current-run artifact required')
    return found[0], newest


def prepare_candidate(config, github, job, state, on_event=None):
    emit = on_event or (lambda *_: None)
    selected = select_artifact(github, job)
    if selected is None:
        return False
    artifact, run = selected
    if not 0 < artifact.get('size_in_bytes', 0) <= 256*1024**2:
        raise ValueError('GitHub artifact exceeds admitted download size')
    directory = Path(state)/'private/artifacts'/job['sha']
    directory.mkdir(parents=True, exist_ok=True)
    path = directory/'candidate.zip'
    if not path.exists():
        emit('artifact-download', 'Downloading bounded ARM64 artifact and verifying GitHub digest')
        temporary = directory/'candidate.download'
        with temporary.open('xb') as stream:
            subprocess.run([config['gh'], 'api', '--hostname', 'github.com', '--method', 'GET',
                            github.repo + f"/actions/artifacts/{artifact['id']}/zip"],
                           stdout=stream, stderr=subprocess.PIPE, check=True, timeout=120)
        expected = artifact.get('digest', '')
        actual = archive_digest(temporary)
        if not expected or actual != expected:
            raise ValueError('GitHub artifact digest missing or differs from downloaded archive')
        declaration = inspect_archive(temporary, job['sha'])
        if job.get('kind') == 'release' and declaration['version'] != job['tag'].removeprefix('v'):
            raise ValueError('artifact package version differs from selected release')
        temporary.rename(path)
        (directory/'provenance.json').write_text(json.dumps({'artifact': artifact, 'run_id': run['id'],
                                                           'source_sha': job['sha'], 'archive_digest': actual}))
    else:
        provenance = json.loads((directory/'provenance.json').read_text())
        if provenance['artifact']['id'] != artifact['id']:
            raise ValueError('New artifact replaced retained candidate; explicit new deployment required')
        actual = archive_digest(path)
        if actual != provenance['archive_digest'] or actual != artifact['digest']:
            raise ValueError('Retained artifact identity mismatch')
        inspect_archive(path, job['sha'])
    guest = config['guest_inbox'] + '/hol-gauntlet-' + job['sha'] + '.zip'
    emit('artifact-transfer', 'Copying verified candidate archive into the benchmark VM')
    subprocess.run([config['limactl'], 'copy', str(path), config['vm'] + ':' + guest], check=True, timeout=120,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    request = {'source_sha': job['sha'], 'archive_sha256': actual.removeprefix('sha256:')}
    try:
        emit('candidate-staging', 'Staging inert wheel, validating dependencies and running fresh conformance controls')
        with (directory/'stage.log').open('x') as stream:
            subprocess.run([config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n', config['guest_python'],
                            '-I', '-B', '/opt/hol-gauntlet/stage.py'], input=json.dumps(request), text=True,
                           stdout=stream, stderr=subprocess.STDOUT, check=True,
                           timeout=config['job_timeout_seconds'])
    except (OSError, subprocess.SubprocessError) as error:
        raise StagingUncertain('Inspect the retained candidate stage.log and VM controls: ' + str(error)) from error
    return True

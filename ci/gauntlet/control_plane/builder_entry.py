"""Unprivileged disposable container entry: never run on the host or as VM Root."""
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile


def main():
    if os.geteuid() != 65532 or os.uname().machine not in {'aarch64', 'arm64'}:
        raise ValueError('dedicated unprivileged ARM container required')
    sha = os.environ['HOL_GUARD_BUILD_SHA']
    tag = os.environ['HOL_GUARD_RELEASE_TAG']
    local_version = os.environ.get('HOL_GUARD_LOCAL_VERSION')
    if (not re.fullmatch('[0-9a-f]{40}', sha)
            or (not (tag == 'local-' + sha and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:a[1-9][0-9]*)?',local_version)) if local_version else not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag))):
        raise ValueError('literal release identity required')
    Path('/work/home').mkdir()
    # Even hostile archive extraction and build hooks run only as UID 65532
    # inside this disposable filesystem, without host secrets or VM sockets.
    with tarfile.open('/input/source.tar.gz') as archive:
        archive.extractall('/work', filter='data')
    subprocess.run(['git', 'clone', '--no-hardlinks', '--branch', tag,
                    '/work/repository.git', '/work/source'], check=True)
    os.chdir('/work/source')
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if actual != sha:
        raise ValueError('captured Git objects differ from pinned release commit')
    subprocess.run(['uv', 'sync', '--frozen', '--no-dev', '--group', 'ci-test',
                    '--no-install-project', '--python', '3.12'], check=True)
    if local_version:
        # The 3.50 alpha removed contained_completion and moved the receipt
        # boundary contracts into the restricted-workspace suite.
        legacy = Path('tests/test_contained_completion.py')
        current = Path('tests/test_guard_restricted_workspace.py')
        if legacy.is_file():
            contained_tests = str(legacy)
            precheck = 'workspace_authorized_stderr_duplication'
        elif current.is_file():
            contained_tests = str(current)
            precheck = 'test_a_workspace_receipt_runs_shapes_the_wrapper_cannot_peel'
        else:
            raise ValueError('candidate has no supported contained workspace contract suite')
        subprocess.run(['uv','run','--no-sync','python','-B','-m','pytest',
                        '--noconftest','-q','-o','addopts=',
                        contained_tests,'-k',precheck],
                       check=True,env=dict(os.environ,PYTHONPATH='/work/source/src'))
    root = Path('gauntlet-artifact')
    if os.environ.get('HOL_GUARD_RETEST') == '1':
        if not local_version:
            raise ValueError('only explicit local candidates support retained-artifact tests')
        root.mkdir()
        with zipfile.ZipFile('/input/candidate.zip') as archive:
            retained = json.loads(archive.read('artifact.json'))
            name = retained['wheel']
            if '/' in name or '\\' in name or not name.endswith('.whl'):
                raise ValueError('literal retained wheel basename required')
            (root/'artifact.json').write_bytes(archive.read('artifact.json'))
            (root/name).write_bytes(archive.read(name))
    else:
        subprocess.run(['.venv/bin/python', '-I', '-B', '/opt/gauntlet/build_artifact.py'], check=True)
    declaration = json.loads((root/'artifact.json').read_text())
    if declaration['source_sha'] != sha or declaration['version'] != (local_version or tag[1:]):
        raise ValueError('built package version/source differs from selected release')
    wheel = declaration['wheel']
    if '/' in wheel or '\\' in wheel or not wheel.endswith('.whl'):
        raise ValueError('literal wheel basename required')
    with zipfile.ZipFile('/output/candidate.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(root/'artifact.json', 'artifact.json')
        archive.write(root/wheel, wheel)

    if local_version:
        # Use the real package and repository fixtures. Native request-context
        # tests require the provisioned session home, not an ambient fallback.
        subprocess.run(['uv','pip','install','--python','.venv/bin/python',
                        '--no-deps',str(root/wheel)],check=True)
        runtime=Path('/work/source/.venv/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime')
        if hashlib.sha256(runtime.read_bytes()).hexdigest()!=declaration['native_sha256']:
            raise ValueError('installed test runtime differs from compiled artifact')
        cap=json.loads(subprocess.check_output([str(runtime),'capabilities','--json'],text=True))
        if cap['build_sha']!=sha or cap['runtime_version']!=local_version:
            raise ValueError('installed test runtime provenance mismatch')
        contract_tests = [contained_tests, 'tests/test_guard_contained_test_hook.py']
        if contained_tests != 'tests/test_guard_restricted_workspace.py':
            contract_tests.append('tests/test_guard_restricted_workspace.py')
        contract_tests.append('tests/test_guard_restricted_workspace_publish.py')
        subprocess.run(['uv','run','--no-sync','python','-B','-m','pytest',
                        '-q','-o','addopts=',*contract_tests],check=True,
                       env=dict(os.environ,HOL_GUARD_TEST_USE_INSTALLED='1',
                                HOL_GUARD_NATIVE='force',
                                HOL_GUARD_NATIVE_BINARY=str(runtime)))


if __name__ == '__main__':
    main()

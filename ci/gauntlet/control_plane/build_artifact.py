"""Run only on a disposable unprivileged hosted ARM PR build runner."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile


def main():
    if os.geteuid() == 0 or os.uname().machine not in {'aarch64', 'arm64'}:
        raise ValueError('unprivileged ARM builder required')
    root = Path.cwd()
    sha = os.environ['HOL_GUARD_BUILD_SHA']
    def output(argv):
        return subprocess.check_output(argv, text=True)
    if output(['git', 'rev-parse', 'HEAD']).strip() != sha:
        raise ValueError('checkout differs from independently supplied PR SHA')
    version = output([sys.executable, 'scripts/sync_repo_version.py', '--check']).strip()
    environment = dict(os.environ, HOL_GUARD_PACKAGE_VERSION=version)
    subprocess.run(['cargo', 'build', '--manifest-path', 'rust/Cargo.toml', '--locked', '--release',
                    '-p', 'hol-guard-runtime', '-p', 'guard-command',
                    '--bin', 'hol-guard-runtime', '--bin', 'guard-command-source'], env=environment, check=True)
    runtime = root/'rust/target/release/hol-guard-runtime'
    exported = json.loads(output([str(runtime), 'export-built']))
    cap = json.loads(output([str(runtime), 'capabilities', '--json']))
    if cap['build_sha'] != sha or cap['runtime_version'] != version:
        raise ValueError('compiled Native provenance mismatch')
    environment['HOL_GUARD_BUILD_SOURCE_COMPILER'] = str(runtime)
    subprocess.run([sys.executable, '-m', 'build', '--wheel', '--outdir', 'gauntlet-pure'],
                   env=environment, check=True)
    pure, = (root/'gauntlet-pure').glob('*.whl')
    spec = importlib.util.spec_from_file_location('native_wheel_builder', root/'scripts/build_native_hol_guard_wheel.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    wheel = module.build_native_wheel(source_wheel=pure, runtime=runtime,
        output_dir=root/'gauntlet-artifact', version=version, platform_tag='linux_aarch64',
        target='aarch64-unknown-linux-gnu', source_sha=sha, rule_digest=cap['rule_digest'],
        implementation_digest=exported['implementation_digest'],
        base_program_digest=exported['program']['program_digest'])
    record = {'schema': 'hol-gauntlet-pr-artifact.v1', 'source_sha': sha,
              'version': version, 'wheel': wheel.name,
              'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
              'native_sha256': hashlib.sha256(runtime.read_bytes()).hexdigest()}
    with zipfile.ZipFile(wheel) as archive:
        manifest = json.loads(archive.read('codex_plugin_scanner/_native/runtime-manifest.json'))
        if manifest['source_sha'] != sha or manifest['runtime_sha256'] != record['native_sha256']:
            raise ValueError('packaged Native identity mismatch')
    (wheel.parent/'artifact.json').write_text(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()

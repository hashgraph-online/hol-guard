"""Transfer only reviewed controller files into a new immutable VM generation."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import zipfile

# This is trusted installer code, not content read from the PR/artifact. It never
# executes an installer hook, deletes old data, or changes an existing prefix.
INSTALL = Path(__file__).with_name('bootstrap_guest.py').read_text()


def install(config, root, *, upgrade=False):
    root = Path(root)
    settings = {'template_config': config['template_config'],
                'template_config_digest': config['template_config_digest'],
                'template_controller': config['template_controller'],
                'asset_root': config['template_asset_root'], 'guest_inbox': config['guest_inbox'],
                'controller_python': config['guest_python'], 'build_memory_gib': config['build_memory_gib']}
    if config['staging_dependency_prefix'] is not None:
        settings['staging_dependency_prefix'] = config['staging_dependency_prefix']
        settings['staging_dependency_prefix_digest'] = config['staging_dependency_prefix_digest']
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        files = [p for p in (root/'ci/gauntlet').rglob('*') if p.is_file() and not p.is_symlink()
                 and '__pycache__' not in p.parts and p.suffix != '.pyc'
                 and ('control_plane' not in p.parts or p.name in
                      {'__init__.py', 'vm_worker.py', 'vm_live.py', 'vm_features.py', 'feature_entry.py',
                       'stage_candidate.py', 'artifacts.py',
                       'vm_build.py', 'vm_network.py', 'Builder.Dockerfile', 'Builder.apparmor', 'builder_entry.py', 'build_artifact.py', 'stage_outcome.py',
                       'executor_image.py','bootstrap_guest.py','Executor.Dockerfile','malloc_policy.c','malloc.preload'})]
        if (root/'ci/__init__.py').is_file():
            files.append(root/'ci/__init__.py')
        if len(files) > 2046:
            raise ValueError('controller transfer file limit')
        for p in sorted(files):
            info = zipfile.ZipInfo(p.relative_to(root).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, p.read_bytes())
        info = zipfile.ZipInfo('settings.json', date_time=(1980, 1, 1, 0, 0, 0))
        archive.writestr(info, json.dumps(settings, sort_keys=True).encode())
        info = zipfile.ZipInfo('request.json', date_time=(1980, 1, 1, 0, 0, 0))
        archive.writestr(info, json.dumps({'upgrade': upgrade}).encode())
    raw = data.getvalue()
    if len(raw) > 32*1024**2:
        raise ValueError('controller transfer byte limit')
    result = subprocess.run([config['limactl'], 'shell', config['vm'], '--', 'sudo', '-n',
                             '/usr/bin/python3', '-I', '-B', '-c', INSTALL],
                            input=raw, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace')[:1500])
    value = json.loads(result.stdout)
    if value.get('bootstrap_sha256') != hashlib.sha256(raw).hexdigest():
        raise ValueError('VM bootstrap response pin differs')
    return value

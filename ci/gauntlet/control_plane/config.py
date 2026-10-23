"""Small explicit operator configuration, outside candidate-controlled source."""
from __future__ import annotations

import json
import re
from pathlib import Path

CONTEXT = 'hol-gauntlet/deterministic'
SHA = re.compile(r'[0-9a-f]{40}')
DEFAULTS = {
    'schema': 'hol-gauntlet-operations.v1',
    'repository': 'hashgraph-online/hol-guard', 'base_branch': 'main',
    'discovery_mode': 'release-tags', 'release_tags': ['v3.48.0', 'v3.49.0'],
    'release_build_backend': 'local-vm', 'git': '/usr/bin/git',
    'vm': 'hol-beta-bootstrap-20261016-004',
    'limactl': '/opt/homebrew/bin/limactl', 'gh': '/opt/homebrew/bin/gh',
    'poll_seconds': 60, 'telemetry_seconds': 15,
    'host_disk_floor_gib': 12, 'vm_disk_floor_gib': 8,
    'vm_memory_gib': 16, 'vm_cpus': 2, 'vm_disk_gib': 48,
    'build_memory_gib': 12,
    'guest_python': '/opt/hol-benchmark-controller-20261013/.venv/bin/python',
    'guest_controller': '/opt/hol-gauntlet/controller',
    'candidate_root': '/opt/hol-gauntlet/candidates',
    'guest_output_root': '/var/lib/hol-gauntlet/outputs',
    'guest_inbox': '/home/construct.guest',
    'template_config': '/opt/hol-cache063-matrix-inputs-20261016-002/config.json',
    'template_config_digest': '0895361a63eee14e35ee71299c711e0e3856758589925c0f9a648d365a10468b',
    'template_controller': '/opt/hol-gauntlet/controller-7f727c7844a6ab3a',
    'template_asset_root': '/opt',
    'staging_dependency_prefix': None,
    'staging_dependency_prefix_digest': None,
    'guest_uv': '/opt/hol-native-lazy-bootstrap-20261014-001/uv',
    'artifact_workflow': 'gauntlet-pr-artifacts.yml',
    'prepare_argv': [], 'job_timeout_seconds': 3600,
    'public_dashboard_url': None,
}


def load(path):
    raw = json.loads(Path(path).read_text())
    if set(raw) - set(DEFAULTS):
        raise ValueError('unknown operator configuration keys')
    value = DEFAULTS | raw
    if value['discovery_mode'] not in {'release-tags', 'pull-requests'}:
        raise ValueError('release-tags or pull-requests discovery required')
    if value['release_build_backend'] not in {'local-vm', 'github-actions'}:
        raise ValueError('local-vm or github-actions release build backend required')
    tags = value['release_tags']
    if (not isinstance(tags, list) or not 1 <= len(tags) <= 20
            or any(not isinstance(t, str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', t) for t in tags)
            or len(set(tags)) != len(tags)):
        raise ValueError('explicit distinct stable release tags required')
    if value['schema'] != DEFAULTS['schema'] or value['base_branch'] != 'main':
        raise ValueError('supported schema and main base branch required')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['repository']):
        raise ValueError('owner/repository required')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,80}', value['vm']):
        raise ValueError('literal Lima instance name required')
    for key in ('limactl', 'gh', 'git', 'guest_python', 'guest_controller',
                'candidate_root', 'guest_output_root', 'guest_inbox', 'template_config',
                'template_asset_root', 'template_controller', 'guest_uv'):
        p = Path(value[key])
        if not p.is_absolute() or '..' in p.parts or any(c.isspace() for c in str(p)):
            raise ValueError(f'{key} must be a literal absolute path without spaces')
    prefix = value['staging_dependency_prefix']
    prefix_digest = value['staging_dependency_prefix_digest']
    if (prefix is None) != (prefix_digest is None):
        raise ValueError('staging dependency prefix and digest must be supplied together')
    if prefix is not None:
        p = Path(prefix)
        if (not p.is_absolute() or '..' in p.parts or any(c.isspace() for c in str(p))
                or not re.fullmatch(r'[0-9a-f]{64}', prefix_digest)):
            raise ValueError('pinned absolute staging dependency prefix required')
    for key in ('poll_seconds', 'telemetry_seconds', 'job_timeout_seconds',
                'host_disk_floor_gib', 'vm_disk_floor_gib', 'vm_memory_gib', 'vm_cpus', 'vm_disk_gib',
                'build_memory_gib'):
        if type(value[key]) is not int or value[key] <= 0:
            raise ValueError(f'{key} must be a positive integer')
    if value['build_memory_gib'] > value['vm_memory_gib'] - 2:
        raise ValueError('reserve at least 2 GiB of VM memory outside the build container')
    if value['poll_seconds'] < 30 or value['telemetry_seconds'] < 5:
        raise ValueError('poll >=30 seconds and telemetry >=5 seconds required')
    argv = value['prepare_argv']
    if (not isinstance(argv, list) or any(not isinstance(s, str) or not s for s in argv)
            or (argv and not Path(argv[0]).is_absolute())):
        raise ValueError('prepare_argv must be a literal argv with an absolute executable')
    if value['artifact_workflow'] != 'gauntlet-pr-artifacts.yml':
        raise ValueError('reviewed Gauntlet artifact workflow required')
    if not re.fullmatch(r'[0-9a-f]{64}', value['template_config_digest']):
        raise ValueError('external baseline configuration digest required')
    url = value['public_dashboard_url']
    if url is not None and (not isinstance(url, str) or not url.startswith('https://')):
        raise ValueError('public dashboard URL must use HTTPS, or remain null')
    return value


def atomic_json(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
    temporary.replace(path)
    path.chmod(mode)

"""Portable caller-pinned local CI inputs; no configuration-selected code."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePosixPath

from .campaign import verify_campaign
from .campaign_execution import reservation
from .ci_gate import _policy_bindings, validate_policy
from .contracts import digest, strict_json_loads, validate_record
from .model_endpoint import model_endpoint

SHA = re.compile(r'[0-9a-f]{64}')
FILE_ROLES = {'bun', 'node', 'wheel', 'native', 'policy', 'compiler',
              'model_manifest', 'provider_manifest'}
TREE_ROLES = {'sdk': 'sdk-tree', 'guard_prefix': 'guard-prefix'}


def read_public(path, *, limit=16*1024*1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('public input must be a bounded ordinary file')
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('public input exceeds byte bound')
    return strict_json_loads(raw)


def relative_asset(root, value):
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or path.as_posix() != value
            or any(part in {'.', '..'} for part in path.parts)):
        raise ValueError('asset paths must be canonical relative paths without traversal')
    target = root / value
    if not target.resolve().is_relative_to(root):
        raise ValueError('asset path escapes its explicit public root')
    return target


def file_digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('pinned file must be ordinary, not a symlink')
    before = path.stat()
    if before.st_size > 2*1024**3:
        raise ValueError('pinned public file exceeds two GiB')
    with path.open('rb') as stream:
        value = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.stat()
    if ((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) !=
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)):
        raise ValueError('pinned file changed while hashing')
    return value


def load_config(path, *, expected_digest, asset_root):
    if type(expected_digest) is not str or SHA.fullmatch(expected_digest) is None:
        raise ValueError('external runner configuration SHA256 required')
    value = read_public(path)
    kinds={'gauntlet-ci-runner.v1':'ci-runner-config',
           'gauntlet-ci-runner.v2':'ci-runner-private-cell-config',
           'gauntlet-ci-runner.v3':'ci-runner-conformance-config',
           'gauntlet-ci-runner.v4':'ci-runner-compact-config',
           'gauntlet-ci-runner.v5':'ci-runner-package-config',
           'gauntlet-ci-runner.v6':'ci-runner-protocol-config',
           'gauntlet-ci-runner.v7':'ci-runner-agent-surface-config'}
    kind=kinds.get(value.get('schema') if type(value) is dict else None,'ci-runner-config')
    config = validate_record(kind, value)
    if digest(config) != expected_digest:
        raise ValueError('runner configuration differs from external pin')
    asset_root = Path(asset_root)
    if not asset_root.is_absolute() or asset_root.resolve() != asset_root or not asset_root.is_dir():
        raise ValueError('canonical absolute public asset root required')
    assets = config['assets']
    conformance = config['schema'] in {'gauntlet-ci-runner.v3','gauntlet-ci-runner.v4','gauntlet-ci-runner.v5','gauntlet-ci-runner.v6','gauntlet-ci-runner.v7'}
    private = config['schema'] in {'gauntlet-ci-runner.v2','gauntlet-ci-runner.v3','gauntlet-ci-runner.v4','gauntlet-ci-runner.v5','gauntlet-ci-runner.v6','gauntlet-ci-runner.v7'}
    required = FILE_ROLES | TREE_ROLES.keys() | ({'private_cell'} if private else set())
    if conformance:
        required |= {'conformance'}
    if set(assets) not in (required, required | {'zod_cache'}):
        raise ValueError('exact named file, SDK and installed-prefix pins required')
    for role, row in assets.items():
        kind = ('cell-artifacts' if role == 'private_cell' else
                TREE_ROLES.get(role, 'sdk-tree' if role == 'zod_cache' else 'file'))
        if row['kind'] != kind:
            raise ValueError(f'{role} has an incompatible artifact kind')
        relative_asset(asset_root,row['path'])
    documents = {}
    for name in ('campaign','policy'):
        document = config[name]
        target = relative_asset(asset_root,document['path'])
        if file_digest(target) != document['sha256']:
            raise ValueError(f'{name} bytes differ from caller pin')
        documents[name] = read_public(target)
    campaign = verify_campaign(documents['campaign'])
    policy = validate_policy(documents['policy'])
    selection = config['selection']
    by_id = {cell['id']:cell for cell in campaign['inventory']}
    if (len(selection) != len(set(selection)) or not set(selection) <= by_id.keys()
            or {row['episode_id'] for row in policy['cells']} != set(selection)
            or config['shards'] > len(selection)):
        raise ValueError('selection, gate policy and shard coverage must match exactly')
    budgets = campaign['budgets']
    if (budgets['concurrency'] != 1 or budgets['max_retries'] not in {0,1}
            or budgets['campaign_tokens'] > config['provider']['token_cap']
            or budgets['tool_timeout_seconds'] != 30):
        raise ValueError('sequential bounded campaign must fit the declared provider allowance')
    _policy_bindings({'cells':[by_id[key] for key in selection]},policy)
    reserves = [reservation(by_id[key],budgets) for key in selection]
    planned = {name:sum(row[name] for row in reserves)*(1+budgets['max_retries']) for name in
               ('model_token_reservation','tool_operation_reservation','controller_seconds_reservation')}
    if (planned['model_token_reservation'] > budgets['campaign_tokens']
            or planned['controller_seconds_reservation'] > budgets['campaign_seconds']):
        raise ValueError('complete selected matrix reservations exceed the aggregate campaign limits')
    options = config['runtime']
    if config['schema'] in {'gauntlet-ci-runner.v5','gauntlet-ci-runner.v6','gauntlet-ci-runner.v7'}:
        from .product_version import validate_version
        validate_version(options['guard_package_version'])
    model_endpoint(options['base_url'])  # Retain existing destination allowlist.
    paths = {name:relative_asset(asset_root,row['path']) for name,row in assets.items()}
    if paths['node'].name != 'node':
        raise ValueError('explicit Node asset must retain the node executable name')
    runtime = {'bun':str(paths['bun']), 'sdk_root':str(paths['sdk']/'@oh-my-pi/pi-coding-agent'),
               'guard_python':str(paths['guard_prefix']/'bin/python'),
               'guard_source_sha':options['guard_source_sha'],
               'guard_prefix_digest':assets['guard_prefix']['sha256'],
               'guard_bwrap_sha256':options['guard_bwrap_sha256'],
               'guard_executor_image_id':options['guard_executor_image_id'],
               'base_url':options['base_url'], 'model_id':options['model_id'],
               'protected_adapter':'hol-guard', 'isolated':True, 'product_isolated':True,
               'artifacts':[str(paths[name]) for name in sorted(FILE_ROLES)]}
    if 'guard_package_version' in options:
        runtime['guard_package_version'] = options['guard_package_version']
    if 'mcp_agent_surfaces' in options:
        from .mcp_agent_profile import fields
        runtime.update(fields(options['mcp_agent_surfaces']))
    if 'mcp_protocol_profiles' in options:
        from .mcp_protocol_campaign import validate_mapping
        runtime['mcp_protocol_profiles'] = validate_mapping(options['mcp_protocol_profiles'],
            campaign['inventory'], selection=selection)
    if 'zod_cache' in paths:
        runtime['zod_cache'] = str(paths['zod_cache'])
    if private:
        from .private_cell_factory import PrivateCellConfig
        cfg = {'schema':'developer-private-cell-config.v1', 'artifacts':str(paths['private_cell']),
               'artifact_manifest_sha256':assets['private_cell']['sha256'], **options['private_cell']}
        if cfg['native_sha256'] != assets['native']['sha256']:
            raise ValueError('private-cell native digest must match the pinned native file')
        runtime['guard_private_cell'] = PrivateCellConfig.parse(cfg).declaration()
    if conformance:
        runtime['guard_conformance']={'path':str(paths['conformance']),
                                      'sha256':assets['conformance']['sha256']}
        runtime['artifacts'].append(str(paths['conformance']))
    return {'config':config,'config_digest':expected_digest,'asset_root':asset_root,
            'campaign':campaign,'policy':policy,'runtime':runtime,'paths':paths,
            'selection_reservations':planned,'attempt_layout':config.get('state_layout','legacy-v1'),
            'shards':[selection[index::config['shards']] for index in range(config['shards'])]}


def verify_assets(loaded):
    """Read installed/cached inputs as inert bytes; never import their code."""
    from .business_agent_container import freeze_public_tree
    from .native_product_container import root_prefix_inventory
    observations = {}
    for role,row in loaded['config']['assets'].items():
        path = loaded['paths'][role]
        if row['kind'] == 'file':
            actual = file_digest(path)
        elif row['kind'] == 'guard-prefix':
            actual = root_prefix_inventory(path)['digest']
        elif row['kind'] == 'cell-artifacts':
            from .private_cell_campaign_inputs import verify_artifacts
            actual = verify_artifacts(loaded['runtime']['guard_private_cell'])['manifest_sha256']
        else:
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f'{role} requires an ordinary public directory')
            actual = freeze_public_tree(path)['tree_digest']
        if actual != row['sha256']:
            raise ValueError(f'{role} differs from its frozen artifact digest')
        observations[role] = actual
    for role in ('bun','node','native','compiler'):
        if not os.access(loaded['paths'][role],os.X_OK):
            raise ValueError(f'{role} is not executable')
    if 'guard_package_version' in loaded['runtime']:
        from .product_version import verify_installed_version
        observations['guard_package_version'] = verify_installed_version(loaded['paths']['guard_prefix'],
            version=loaded['runtime']['guard_package_version'], source_sha=loaded['runtime']['guard_source_sha'],
            native_sha256=loaded['config']['assets']['native']['sha256'])
    return observations

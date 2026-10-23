"""Public immutable artifact inventory without executing untrusted products."""
from __future__ import annotations

import hashlib
import re
import sys
import tempfile
from pathlib import Path

from .contracts import digest

SOURCE = Path(__file__).resolve().parent
PRODUCT_PINS = frozenset({'guard_prefix_digest','guard_bwrap_sha256','guard_executor_image_id'})


def validate_product_pins(runtime):
    if 'guard_package_version' in runtime:
        from .product_version import validate_version
        validate_version(runtime['guard_package_version'])
    present = PRODUCT_PINS.intersection(runtime)
    if 'guard_private_cell' in runtime:
        from .private_cell_factory import PrivateCellConfig
        PrivateCellConfig.parse(runtime['guard_private_cell'])
        if present != PRODUCT_PINS:
            raise ValueError('private-cell configuration requires all isolated product pins')
    if not present:
        return None
    if present != PRODUCT_PINS:
        raise ValueError('protected developer prefix, bwrap and executor pins are an all-or-none set')
    if (runtime.get('isolated') is not True or runtime.get('product_isolated') is not True
            or runtime.get('protected_adapter') != 'hol-guard'):
        raise ValueError('developer product pins require explicit isolated HOL product runtime')
    for name in ('guard_prefix_digest','guard_bwrap_sha256'):
        if not isinstance(runtime[name],str) or re.fullmatch(r'[0-9a-f]{64}',runtime[name]) is None:
            raise ValueError(f'{name} requires a strict lowercase SHA256 digest')
    image = runtime['guard_executor_image_id']
    if not isinstance(image,str) or re.fullmatch(r'sha256:[0-9a-f]{64}',image) is None:
        raise ValueError('guard_executor_image_id requires an exact lowercase image digest')
    return {name:runtime[name] for name in sorted(PRODUCT_PINS)}


def hash_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'identity file is absent or a symlink: {path}')
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def hash_tree(root, suffixes):
    files = sorted(p for p in root.rglob('*') if p.suffix in suffixes
                   and '__pycache__' not in p.parts)
    if not files or len(files) > 20000:
        raise ValueError('public code inventory is empty or unbounded')
    return {str(p): hash_file(p) for p in files}


def public_identities(runtime):
    pins = validate_product_pins(runtime)
    # Explicit public artifacts only; no credential stores or auth databases.
    from .developer_seed_inputs import seed_source_identity
    seed=seed_source_identity()
    from .developer_probe_inputs import probe_source_identity
    probe=probe_source_identity()
    values = hash_tree(SOURCE, {'.py', '.ts', '.mjs', '.js', '.json', '.html', '.yaml',
                               '.Containerfile', '.apparmor'})
    values[seed['path']]=seed['sha256']
    values.update(probe['files'])
    values.update(hash_tree(Path(runtime['sdk_root']) / 'src', {'.ts', '.js', '.mjs'}))
    paths = [runtime['bun'], str(Path(runtime['sdk_root']) / 'package.json'),
             str(Path(sys.executable).resolve()), *runtime['artifacts']]
    if runtime.get('zod_cache'):
        paths += [str(Path(runtime['zod_cache']) / name)
                  for name in ('metadata.json', 'zod-3.23.8.tgz')]
    for name in paths:
        values[name] = hash_file(Path(name))
    if runtime['protected_adapter'] != 'hol-guard':
        return values
    if runtime.get('product_isolated'):
        from .native_product_container import root_prefix_inventory
        python = Path(runtime['guard_python'])
        prefix = python.parent.parent
        marker = prefix / 'pyvenv.cfg'
        if (python.name != 'python' or python.parent.name != 'bin' or prefix.resolve() != prefix
                or marker.is_symlink() or not marker.is_file()):
            raise ValueError('isolated product prefix must retain its literal identity')
        actual = root_prefix_inventory(prefix)['digest']
        if pins is not None and actual != pins['guard_prefix_digest']:
            raise ValueError('declared developer product prefix differs from inert installed bytes')
        values['isolated-product-prefix-digest'] = actual
        return values
    # Explicit trusted-product diagnostic lane. Candidate qualification uses
    # the inert inventory above and executes probes only inside its namespace.
    from .installed_guard import inspect_installed_guard
    with tempfile.TemporaryDirectory(prefix='gauntlet-guard-probe-') as home:
        identity = inspect_installed_guard(Path(runtime['guard_python']),
            expected_sha=runtime['guard_source_sha'], home=Path(home))
    if 'guard_package_version' in runtime:
        from .product_version import verify_claim_version
        verify_claim_version(identity, runtime['guard_package_version'])
    values['installed-guard-public-identity'] = digest(identity)
    values.update(hash_tree(Path(identity['module']).parent,
                            {'.py', '.json', '.so', '.dylib', '.dll', '.bin', '.toml'}))
    values[str(Path(runtime['guard_python']).resolve())] = hash_file(Path(runtime['guard_python']).resolve())
    return values

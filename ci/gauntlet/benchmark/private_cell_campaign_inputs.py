"""Inert private-cell input freeze; no captured runtime or collector imports.

The caller pins the manifest. Collector Python/profile bytes must additionally
match this controller's own source: a candidate manifest cannot choose Root code.
This establishes input consistency, never executor qualification or trust eligibility.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .contracts import strict_json_loads
from .private_cell_factory import PrivateCellConfig
from .product_vm_rootfs import _trusted

SOURCE = Path(__file__).resolve().parent
COMPLETION_MODULE = 'lib/python3.12/site-packages/codex_plugin_scanner/guard/runtime/contained_completion.py'
ROOT_MODULES = ('contained_request_file', 'json_data', 'product_cell_actor', 'product_cell_idmap',
    'product_cell_image', 'product_cell_layout', 'product_cell_protocol', 'product_cell_supervisor',
    'product_cell_system', 'product_cell_task_mounts', 'product_exec_gate', 'product_vm_network',
    'product_vm_rootfs', 'product_vm_seccomp', 'runtime_bundle', 'vm_bridge_frames', 'vm_bridge_io', 'vm_bridge_rpc')
PUBLIC_MODULES = ('json_data', 'product_cell_actor', 'product_cell_layout', 'product_cell_protocol',
    'product_exec_gate', 'product_vm_network', 'product_vm_seccomp',
    'vm_bridge_frames', 'vm_bridge_io', 'vm_bridge_rpc')


def _sources():
    result = {}
    for folder, modules in (('code', ROOT_MODULES), ('public', PUBLIC_MODULES)):
        for name in modules:
            result[f'{folder}/ci/gauntlet/benchmark/{name}.py'] = (SOURCE / (name+'.py')).read_bytes()
        for relative in ('ci/__init__.py', 'ci/gauntlet/__init__.py', 'ci/gauntlet/benchmark/__init__.py'):
            # Both namespace packages get fixed empty isolated initializers.
            result[f'{folder}/{relative}'] = (b'' if relative!='ci/gauntlet/__init__.py' else
                (SOURCE.parents[2] / relative).read_bytes())
    result['product_vm.apparmor'] = (SOURCE / 'product_vm.apparmor').read_bytes()
    result['public/product_vm_seccomp_oci_v1.json'] = (SOURCE / 'product_vm_seccomp_oci_v1.json').read_bytes()
    return result


def _read(path, *, maximum):
    for parent in path.parents:
        _trusted(parent, directory=True)
    _trusted(path)
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(maximum+1)
        after = os.fstat(stream.fileno())
    if (len(raw)>maximum or len(raw)!=before.st_size or
            (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) !=
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
        raise ValueError('private-cell input byte bound or stable identity failed')
    return raw


def verify_artifacts(value):
    cfg = PrivateCellConfig.parse(value)
    root = Path(cfg.artifacts)
    for parent in (root, *root.parents):
        _trusted(parent, directory=True)
    raw = _read(root/'manifest.json', maximum=1024**2)
    if hashlib.sha256(raw).hexdigest()!=cfg.artifact_manifest_sha256:
        raise ValueError('private-cell artifact manifest differs from caller pin')
    manifest = strict_json_loads(raw)
    if (type(manifest) is not dict or set(manifest)!={'schema','files'}
            or manifest['schema']!='product-cell-artifacts.v1' or type(manifest['files']) is not dict):
        raise ValueError('exact private-cell artifact manifest required')
    sources = _sources()
    required = set(sources) | {'public/actor.py', 'public/initializer'}
    if set(manifest['files'])!=required:
        raise ValueError('private-cell artifact inventory differs from fixed bootstrap')
    actual, count = set(), 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        count += len(dirs)+len(files)
        if count>256:
            raise ValueError('private-cell artifact entry bound')
        for name in dirs:
            _trusted(Path(directory)/name, directory=True)
        actual.update((Path(directory)/name).relative_to(root).as_posix() for name in files)
        if len(actual)>128:
            raise ValueError('private-cell artifact entry bound')
    if actual != required | {'manifest.json'}:
        raise ValueError('undeclared or missing private-cell artifact file')
    total = 0
    for name, pin in manifest['files'].items():
        data = _read(root/name, maximum=2*1024**2)
        total += len(data)
        if total>16*1024**2 or hashlib.sha256(data).hexdigest()!=pin:
            raise ValueError('private-cell artifact bytes differ from manifest')
        if name in sources and data!=sources[name]:
            raise ValueError('private-cell collector/bootstrap differs from controller source')
    if manifest['files']['public/initializer']!=cfg.initializer_sha256:
        raise ValueError('private-cell initializer differs from external pin')
    return {'schema':'private-cell-input-inventory.v1','manifest_sha256':cfg.artifact_manifest_sha256,
            'files':manifest['files'],'bytes':total,'candidate_code_executed':False}


def freeze_private_cell(runtime):
    from .product_cell_idmap import verify
    from .product_cell_supervisor import cpu_configuration
    from .runtime_bundle import inventory
    cfg = PrivateCellConfig.parse(runtime['guard_private_cell'])
    artifacts = verify_artifacts(cfg.declaration())
    prefix = Path(runtime['guard_python']).parent.parent
    for parent in (prefix, *prefix.parents):
        _trusted(parent, directory=True)
    entries, _, tree, total = inventory(prefix)
    if tree!=cfg.runtime_tree_digest:
        raise ValueError('private-cell runtime tree differs from external pin')
    module = entries.get(COMPLETION_MODULE,{})
    if module.get('kind')!='file' or type(module.get('sha256')) is not str:
        raise ValueError('installed Guard lacks the declared completion module; new matching candidate required')
    verify(cfg.idmap_runtime, trusted=_trusted)
    allowed_cpu, properties = cpu_configuration(cfg.cpu_profile)
    result = {'schema':'private-cell-campaign-inputs.v1','config':cfg.declaration(),
            'artifacts':artifacts,'runtime_tree_digest':tree,'runtime_entries':len(entries),
            'runtime_bytes':total,'allowed_cpu':allowed_cpu,'cpu_properties':properties,
            'mcp_identity_profile':'private-cell-mcp-v2','agent_uid':10001,'builtin_uid':10004,'mcp_uid':10005,
            'contained_output_binding':'controller-contained-output.v1',
            'contained_completion_profile':'guard-contained-completion.v1',
            'completion_module_sha256':module['sha256'],
            'network_profile':'private-loopback-v1','conformance_verified':False,'qualification_eligible':False}
    if 'guard_package_version' in runtime:
        from .product_version import verify_installed_version
        result.update(schema='private-cell-campaign-inputs.v2', package_version=verify_installed_version(prefix,
            version=runtime['guard_package_version'], source_sha=runtime['guard_source_sha'],
            native_sha256=cfg.native_sha256))
    return result

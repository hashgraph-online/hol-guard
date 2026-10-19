"""Compose the private builtin backend from explicit frozen controller inputs.

No product import runs here. New mutable state is allocated separately from
Root-owned artifact/runtime caches and the existing agent task directories.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .json_data import canonical_json, strict_json_loads
from .native_product_container import root_prefix_digest
from .private_cell_hook_plane import PrivateCellHookPlane
from .product_cell_idmap import PROFILES
from .product_cell_image import ImageLease
from .product_cell_supervisor import ProductCell
from .product_cell_task_mounts import metadata, read_mounts
from .product_vm_rootfs import _trusted

SHA=re.compile('[0-9a-f]{64}')


@dataclass(frozen=True)
class PrivateCellConfig:
    artifacts: str
    artifact_manifest_sha256: str
    initializer_sha256: str
    native_sha256: str
    runtime_tree_digest: str
    idmap_runtime: str
    cpu_profile: str

    @classmethod
    def parse(cls,value):
        if (type(value) is not dict or set(value)!={'schema',*cls.__dataclass_fields__}
                or value['schema']!='developer-private-cell-config.v1'):
            raise ValueError('exact versioned private-cell configuration required')
        for key in ('artifact_manifest_sha256','initializer_sha256','native_sha256','runtime_tree_digest'):
            if type(value[key]) is not str or SHA.fullmatch(value[key]) is None:
                raise ValueError('external private-cell artifact/runtime/native SHA256 required')
        path=Path(value['artifacts']) if type(value['artifacts']) is str else Path('.')
        if (not path.is_absolute() or str(path)!=value['artifacts'] or '..' in path.parts
                or path.resolve()!=path or type(value['idmap_runtime']) is not str
                or value['idmap_runtime'] not in PROFILES or type(value['cpu_profile']) is not str
                or value['cpu_profile'] not in {'quota-v1','single-core-v1'}):
            raise ValueError('literal artifact directory and versioned idmap/CPU profiles required')
        return cls(**{key:value[key] for key in cls.__dataclass_fields__})

    def declaration(self):
        return {'schema':'developer-private-cell-config.v1',
                **{key:getattr(self,key) for key in self.__dataclass_fields__}}


def _write(path,value):
    raw=(canonical_json(value)+'\n').encode()
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def _stage_public(artifacts,stage,expected):
    for path in (artifacts,*artifacts.parents):
        _trusted(path,directory=True)
    manifest=artifacts/'manifest.json'
    _trusted(manifest)
    with manifest.open('rb') as stream:
        raw=stream.read(1024**2+1)
    if len(raw)>1024**2 or hashlib.sha256(raw).hexdigest()!=expected:
        raise ValueError('externally pinned cell artifact manifest required before staging')
    value=strict_json_loads(raw)
    if (type(value) is not dict or set(value)!={'schema','files'}
            or value['schema']!='product-cell-artifacts.v1' or type(value['files']) is not dict
            or not 1<=len(value['files'])<=128):
        raise ValueError('bounded cell artifact manifest required')
    total=0
    public=stage/'public'
    public.mkdir(mode=0o755)
    public.chmod(0o755)
    for name,pin in value['files'].items():
        if type(name) is not str:
            raise ValueError('literal cell artifact path required')
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative)!=name:
            raise ValueError('canonical cell artifact path required')
        source=artifacts/relative
        for parent in source.parents:
            _trusted(parent,directory=True)
        _trusted(source)
        with source.open('rb') as stream:
            data=stream.read(2*1024**2+1)
        if len(data)>2*1024**2 or hashlib.sha256(data).hexdigest()!=pin:
            raise ValueError('cell artifact bytes differ from external pin')
        if relative.parts[0]!='public':
            continue
        total+=len(data)
        if total>8*1024**2:
            raise ValueError('public cell bootstrap byte budget')
        target=stage/relative
        target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        # Only this fresh public bootstrap tree is traversable by the actor.
        # Private state and physical task custody keep their original modes.
        for directory in (target.parent,*target.parent.parents):
            if not directory.is_relative_to(public):
                break
            directory.chmod(0o755)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(0o555 if relative.as_posix()=='public/initializer' else 0o444)


class _BudgetPrivatePlane(PrivateCellHookPlane):
    def __init__(self,*,operation_budget,**kwargs):
        self.operation_budget=operation_budget
        super().__init__(**kwargs)

    def invoke_hook(self,payload,**kwargs):
        if payload.get('hook_event_name')=='PreToolUse':
            self.operation_budget.claim('sdk-builtin',payload)
        return super().invoke_hook(payload,**kwargs)


def build_private_cell(*,root,config,python,source_sha,prefix_digest,bwrap_sha256,image_id,
                       workspace_source,workspace_custody_root,provider_mounts,provider_custody_root,
                       wall_seconds,operation_budget,package_version=None):
    """Return an unstarted owned plane; close every acquired resource on failure."""
    if os.geteuid()!=0 or not isinstance(config,PrivateCellConfig) or root.exists() or root.is_symlink():
        raise ValueError('Root and fresh exclusive private-cell factory state required')
    version_options = {}
    if package_version is not None:
        from .product_version import validate_version
        version_options['package_version'] = validate_version(package_version)
    for parent in root.parents:
        _trusted(parent,directory=True)
    prefix=python.parent.parent
    for parent in (prefix,*prefix.parents):
        _trusted(parent,directory=True)
    if root_prefix_digest(prefix)!=prefix_digest:
        raise ValueError('installed product prefix differs from frozen runtime input')
    if len(provider_mounts)>8 or (provider_mounts and provider_custody_root is None):
        raise ValueError('bounded explicitly custodied synthetic provider mounts required')
    root.mkdir(mode=0o700)
    _stage_public(Path(config.artifacts),root,config.artifact_manifest_sha256)
    state=root/'state'
    state.mkdir(mode=0o700)
    os.chown(state,10004,10004)
    for name in ('home','guard'):
        directory=state/name
        directory.mkdir(mode=0o700)
        os.chown(directory,10004,10004)
    # Match the existing native product profile before the first Guard import.
    configuration=state/'guard/config.toml'
    with configuration.open('x') as stream:
        stream.write('mode="enforce"\nsync=false\ntelemetry=false\ndesktop_notifications=false\n'
                     'approval_wait_timeout_seconds=1\n')
    configuration.chmod(0o600)
    os.chown(configuration,10004,10004)
    runtime={'schema':'product-vm-runtime-mount.v1','prefix':str(prefix),
             'mountpoint':str(prefix),'tree_digest':config.runtime_tree_digest}
    _write(root/'runtime.json',runtime)
    def row(source,destination,custody):
        return {'source':str(source),'destination':str(destination),'custody_root':str(custody),**metadata(source)}
    tasks={'schema':'product-cell-task-mounts.v1',
           'workspace':row(workspace_source,'/runtime/home/project',workspace_custody_root),
           'providers':[row(path,path,provider_custody_root) for path in provider_mounts]}
    task_digest=_write(root/'task-mounts.json',tasks)
    read_mounts(root,task_digest,workspace='/runtime/home/project',trusted=_trusted)
    lease=ImageLease(image_id)
    cell=None
    try:
        lease.acquire()
        system_digest=lease.declare(root)
        cell=ProductCell(root,Path(config.artifacts),initializer_sha256=config.initializer_sha256,
            expected_manifest_digest=config.artifact_manifest_sha256,wall_seconds=wall_seconds,
            network_profile='private-loopback-v1',expected_system_digest=system_digest,
            idmap_runtime=config.idmap_runtime,cpu_profile=config.cpu_profile,expected_task_digest=task_digest)
        return _BudgetPrivatePlane(cell=cell,image_lease=lease,python=python,
            expected_tree_digest=config.runtime_tree_digest,expected_native_source=source_sha,
            expected_native_sha256=config.native_sha256,expected_bwrap_sha256=bwrap_sha256,
            expected_prefix_digest=prefix_digest,
            operation_budget=operation_budget,**version_options)
    except BaseException:
        if cell is not None:
            cell.close()
        lease.close()
        raise

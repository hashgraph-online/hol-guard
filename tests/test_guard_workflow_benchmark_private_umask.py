"""Public namespace scaffolding is explicit; physical task modes stay private."""
import json
import os
import stat
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import product_cell_task_mounts, product_vm_rootfs


def test_runtime_scaffolding_is_traversable_without_changing_umask(tmp_path,monkeypatch):
    stage=tmp_path/'stage';stage.mkdir()
    new=tmp_path/'root';new.mkdir()
    prefix=tmp_path/'prefix';prefix.mkdir(mode=0o700)
    spec={'schema':'product-vm-runtime-mount.v1','prefix':str(prefix),
          'mountpoint':'/opt/readonly/nested/prefix','tree_digest':'a'*64}
    (stage/'runtime.json').write_text(json.dumps(spec))
    monkeypatch.setattr(product_vm_rootfs,'_trusted',lambda *a,**k:None)
    from ci.gauntlet.benchmark import runtime_bundle
    monkeypatch.setattr(runtime_bundle,'inventory',lambda p:(None,None,'a'*64))
    calls=[]
    previous=os.umask(0o077)
    try:
        product_vm_rootfs._runtime(stage,new,lambda *args:calls.append(args))
        assert os.umask(0o077)==0o077
    finally:
        os.umask(previous)
    target=new/'opt/readonly/nested/prefix'
    assert calls==[(prefix,target)]
    assert all(stat.S_IMODE(p.stat().st_mode)==0o755 for p in (new/'opt',new/'opt/readonly',
        new/'opt/readonly/nested',target))
    assert stat.S_IMODE(prefix.stat().st_mode)==0o700


def test_task_mount_scaffolding_preserves_physical_private_leaf(tmp_path,monkeypatch):
    source=tmp_path/'physical';source.mkdir(mode=0o700)
    new=tmp_path/'root';new.mkdir()
    pinned={'device':1,'inode':2,'mode':0o700}
    row={'source':str(source),'destination':'/runtime/home/project',**pinned}
    monkeypatch.setattr(product_cell_task_mounts,'metadata',lambda p:pinned)
    def stop_before_mount(*args,**kwargs):
        assert stat.S_IMODE((new/'runtime').stat().st_mode)==0o755
        assert stat.S_IMODE((new/'runtime/home').stat().st_mode)==0o755
        assert stat.S_IMODE((new/'runtime/home/project').stat().st_mode)==0o700
        raise RuntimeError('bounded test stops before privileged mount')
    previous=os.umask(0o077)
    try:
        with pytest.raises(RuntimeError,match='bounded test'):
            product_cell_task_mounts.bind_mounts([row],new,mount=None,run=stop_before_mount)
        assert os.umask(0o077)==0o077
    finally:
        os.umask(previous)
    assert stat.S_IMODE(source.stat().st_mode)==0o700

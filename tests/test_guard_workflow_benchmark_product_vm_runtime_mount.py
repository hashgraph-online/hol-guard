"""Reject runtime mount substitution before reading inputs or changing mounts."""
import pytest

from ci.gauntlet.benchmark import product_vm_rootfs as module
from ci.gauntlet.benchmark import runtime_bundle
from ci.gauntlet.benchmark.json_data import canonical_json


def specification(tmp_path, **changes):
    value={'schema':'product-vm-runtime-mount.v1','prefix':'/opt/pinned-public-runtime',
           'mountpoint':'/runtime/guard','tree_digest':'a'*64}
    value.update(changes)
    (tmp_path/'runtime.json').write_text(canonical_json(value))


@pytest.mark.parametrize('destination',['/usr/bin','/public/override','/proc/override','/product/home',
    '/run/authority','/home','/runtime','relative/guard','/runtime/../public/override','/runtime//guard',
    '/opt','/opt/node','/opt/node/override'])
def test_mount_cannot_shadow_system_or_controller_paths(tmp_path,monkeypatch,destination):
    specification(tmp_path,mountpoint=destination)
    monkeypatch.setattr(module,'_trusted',lambda *args,**kwargs:None)
    monkeypatch.setattr(runtime_bundle,'inventory',lambda *args:pytest.fail('must reject before reading runtime'))
    with pytest.raises(ValueError,match='mountpoint'):
        module._runtime(tmp_path,tmp_path/'not-created',lambda *args:pytest.fail('mount must not run'))
    assert not (tmp_path/'not-created').exists()


def test_wrong_runtime_tree_never_mounted(tmp_path,monkeypatch):
    specification(tmp_path)
    monkeypatch.setattr(module,'_trusted',lambda *args,**kwargs:None)
    monkeypatch.setattr(runtime_bundle,'inventory',lambda *args:({}, {}, 'b'*64, 0))
    with pytest.raises(ValueError,match='externally pinned'):
        module._runtime(tmp_path,tmp_path/'not-created',lambda *args:pytest.fail('mount must not run'))
    assert not (tmp_path/'not-created').exists()


def test_unknown_mount_field_is_not_a_configuration_extension(tmp_path,monkeypatch):
    specification(tmp_path,command='/bin/sh')
    monkeypatch.setattr(module,'_trusted',lambda *args,**kwargs:None)
    with pytest.raises(ValueError,match='specification'):
        module._runtime(tmp_path,tmp_path/'not-created',lambda *args:pytest.fail('mount must not run'))

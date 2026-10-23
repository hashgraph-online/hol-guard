"""Inert freeze contracts; no product import/probe/container code executes."""
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import campaign_identity as identity
from ci.gauntlet.benchmark import local_campaign_custody as custody
from ci.gauntlet.benchmark import native_product_container


def runtime():
    return {'isolated':True,'product_isolated':True,'protected_adapter':'hol-guard',
        'guard_python':'/root-owned/.venv/bin/python','guard_prefix_digest':'a'*64,
        'guard_bwrap_sha256':'b'*64,'guard_executor_image_id':'sha256:'+'c'*64}


def test_pin_set_absent_preserves_previous_business_runtime():
    assert identity.validate_product_pins({}) is None


@pytest.mark.parametrize('field',sorted(identity.PRODUCT_PINS))
def test_partial_product_pins_rejected(field):
    values = runtime()
    del values[field]
    with pytest.raises(ValueError,match='all-or-none'):
        identity.validate_product_pins(values)


@pytest.mark.parametrize('field,value',[('isolated',False),('isolated',1),('product_isolated',False),
    ('protected_adapter','example-policy'),('guard_prefix_digest','A'*64),('guard_bwrap_sha256',None),
    ('guard_executor_image_id','localhost/image:latest')])
def test_pins_only_allowed_for_explicit_isolated_hol_and_strict_digests(field,value):
    values = {**runtime(),field:value}
    with pytest.raises(ValueError):
        identity.validate_product_pins(values)


def test_public_identity_rejects_claimed_prefix_without_candidate_probe(tmp_path,monkeypatch):
    prefix = tmp_path/'prefix'
    (prefix/'bin').mkdir(parents=True)
    (prefix/'pyvenv.cfg').write_text('public literal venv identity')
    values = {**runtime(),'guard_python':str(prefix/'bin/python'),'sdk_root':str(tmp_path/'sdk'),
              'bun':str(tmp_path/'bun'),'artifacts':[]}
    monkeypatch.setattr(identity,'hash_tree',lambda *args: {'public-source':'f'*64})
    monkeypatch.setattr(identity,'hash_file',lambda *args: 'f'*64)
    monkeypatch.setattr(native_product_container,'root_prefix_inventory',lambda *args: {'digest':'d'*64})
    with pytest.raises(ValueError,match='inert installed bytes'):
        identity.public_identities(values)


def backend_mount(tmp_path,monkeypatch):
    (tmp_path/'usr').mkdir(mode=0o755)
    (tmp_path/'usr/bin').mkdir(mode=0o755)
    binary = tmp_path/'usr/bin/bwrap'
    binary.write_bytes(b'inert-public-executable-fixture')
    binary.chmod(0o755)
    original = os.fstat
    def observed(fd):
        row = original(fd)
        return SimpleNamespace(st_uid=0,st_mode=row.st_mode,st_size=row.st_size,
            st_dev=row.st_dev,st_ino=row.st_ino,st_mtime_ns=row.st_mtime_ns)
    monkeypatch.setattr(custody.os,'fstat',observed)
    return binary


def test_freeze_inspects_actual_image_and_hashes_bytes_without_product_execution(tmp_path,monkeypatch):
    binary = backend_mount(tmp_path,monkeypatch)
    values = {**runtime(),'guard_bwrap_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
    calls = []
    def podman(*args):
        calls.append(args)
        if args[1]=='inspect':
            return SimpleNamespace(stdout=json.dumps([{'Id':values['guard_executor_image_id'],'Os':'linux'}]))
        if args==('image','mount','--format','json'):
            return SimpleNamespace(stdout='[]')
        return SimpleNamespace(stdout=str(tmp_path)+'\n')
    monkeypatch.setattr(native_product_container,'root_prefix_inventory',lambda *args: {'digest':'a'*64})
    frozen = custody.freeze_developer_product(values,podman=podman)
    assert frozen['bwrap']['sha256']==values['guard_bwrap_sha256'] and frozen['bwrap']['mode']==0o755
    assert frozen['sdk_conformance_verified'] is False and frozen['qualification_eligible'] is False
    assert [row[:2] for row in calls]==[('image','inspect'),('image','mount'),('image','mount'),('image','unmount')]


def test_wrong_actual_binary_still_unmounts_and_cannot_freeze_declared_hash(tmp_path,monkeypatch):
    backend_mount(tmp_path,monkeypatch)
    calls = []
    def podman(*args):
        calls.append(args)
        if args==('image','mount','--format','json'):
            return SimpleNamespace(stdout='[]')
        return SimpleNamespace(stdout=json.dumps([{'Id':runtime()['guard_executor_image_id'],'Os':'linux'}])
                               if args[1]=='inspect' else str(tmp_path))
    monkeypatch.setattr(native_product_container,'root_prefix_inventory',lambda *args: {'digest':'a'*64})
    with pytest.raises(ValueError,match='actual executor bwrap'):
        custody.freeze_developer_product(runtime(),podman=podman)
    assert calls[-1]==('image','unmount',runtime()['guard_executor_image_id'])


def test_parent_symlink_cannot_make_freezer_read_outside_image(tmp_path,monkeypatch):
    outside = tmp_path/'outside'
    outside.mkdir()
    (outside/'bwrap').write_text('controller-private-canary')
    image = tmp_path/'image'
    image.mkdir(mode=0o755)
    (image/'usr').mkdir(mode=0o755)
    (image/'usr/bin').symlink_to(outside,target_is_directory=True)
    original = os.fstat
    monkeypatch.setattr(custody.os,'fstat',lambda fd:SimpleNamespace(st_uid=0,st_mode=original(fd).st_mode))
    with pytest.raises(OSError):
        custody.image_bwrap_identity(image)


def test_wrong_actual_image_never_mounts_or_executes(tmp_path,monkeypatch):
    calls = []
    def podman(*args):
        calls.append(args)
        return SimpleNamespace(stdout=json.dumps([{'Id':'sha256:'+'d'*64,'Os':'linux'}]))
    monkeypatch.setattr(native_product_container,'root_prefix_inventory',lambda *args: {'digest':'a'*64})
    with pytest.raises(ValueError,match='actual local executor image'):
        custody.freeze_developer_product(runtime(),podman=podman)
    assert len(calls)==1 and calls[0][:2]==('image','inspect')


def test_freeze_refuses_existing_executor_mount_without_mutation_or_cleanup(monkeypatch):
    values=runtime();calls=[]
    monkeypatch.setattr(native_product_container,'root_prefix_inventory',lambda *_:{'digest':'a'*64})
    def podman(*args):
        calls.append(args)
        if args==('image','inspect',values['guard_executor_image_id']):
            return SimpleNamespace(stdout=json.dumps([{'Id':values['guard_executor_image_id'],'Os':'linux'}]))
        assert args==('image','mount','--format','json')
        return SimpleNamespace(stdout=json.dumps([{'id':values['guard_executor_image_id'],'mountpoint':'/owned-by-another-controller'}]))
    with pytest.raises(ValueError,match='already mounted'):
        custody.freeze_developer_product(values,podman=podman)
    assert len(calls)==2

"""Inert runtime transfer, hostile archives and actual Root bootstrap roundtrip."""
from __future__ import annotations

import hashlib
import io
import os
import shutil
import uuid
import zipfile
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import runtime_bundle as module
from ci.gauntlet.benchmark.json_data import canonical_json, digest


def entries():
    payload=b'public inert runtime bytes'
    return {'.':{'kind':'directory','mode':0o755,'uid':0},
            'lib':{'kind':'directory','mode':0o755,'uid':0},
            'lib/data':{'kind':'file','mode':0o644,'uid':0,'size':len(payload),
                        'sha256':hashlib.sha256(payload).hexdigest()},
            'lib64':{'kind':'link','mode':0o777,'uid':0,'link':'lib'}}, payload


def bundle(rows, payload, *, raw_manifest=None, extra=None):
    raw=io.BytesIO()
    with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_STORED) as archive:
        archive.writestr('manifest.json', raw_manifest if raw_manifest is not None else
                         canonical_json({'schema':'runtime-tree-bundle.v1','entries':rows}))
        archive.writestr('objects/'+hashlib.sha256(payload).hexdigest(),payload)
        if extra:
            archive.writestr(*extra)
    data=raw.getvalue()
    legacy={name:{key:value for key,value in row.items() if key not in {'kind','size'}}
            for name,row in rows.items()}
    return data,{'expected_archive_digest':hashlib.sha256(data).hexdigest(),
                 'expected_tree_digest':digest(legacy)}


def test_valid_inert_bundle_and_external_pins():
    rows,payload=entries()
    raw,pins=bundle(rows,payload)
    actual,objects=module.validate_bundle(raw,**pins)
    assert actual==rows and list(objects.values())==[payload]
    with pytest.raises(ValueError,match='digest'):
        module.validate_bundle(raw+b'changed',**pins)
    with pytest.raises(ValueError,match='external pin'):
        module.validate_bundle(raw,**{**pins,'expected_tree_digest':'0'*64})


@pytest.mark.parametrize('name',['/outside','../outside','lib/../../outside','lib//outside',
                                'lib/./outside','lib\\outside','lib/evil\nname'])
def test_paths_cannot_escape_or_alias_the_new_tree(name):
    rows,payload=entries()
    rows[name]=rows.pop('lib/data')
    raw,pins=bundle(rows,payload)
    with pytest.raises(ValueError,match='path'):
        module.validate_bundle(raw,**pins)


@pytest.mark.parametrize('target',['/etc/shadow','../../outside','/usr/bin/python3.12/child','missing','lib64'])
def test_external_traversing_dangling_and_cyclic_links_rejected(target):
    rows,payload=entries()
    rows['lib64']['link']=target
    raw,pins=bundle(rows,payload)
    with pytest.raises(ValueError,match='link'):
        module.validate_bundle(raw,**pins)


def test_no_archive_object_can_be_installed_below_a_link():
    rows,payload=entries()
    rows['lib64/escaped']=deepcopy(rows['lib/data'])
    raw,pins=bundle(rows,payload)
    with pytest.raises(ValueError,match='ancestor'):
        module.validate_bundle(raw,**pins)


@pytest.mark.parametrize('field,value',[('mode',0o4755),('mode',0o666),('uid',10004),('uid',False),
                                       ('kind','device'),('size',module.MAX_FILE+1)])
def test_privileged_metadata_special_objects_and_oversized_files_rejected(field,value):
    rows,payload=entries()
    rows['lib/data'][field]=value
    raw,pins=bundle(rows,payload)
    with pytest.raises(ValueError):
        module.validate_bundle(raw,**pins)


@pytest.mark.parametrize('manifest',[b'{"schema":"x","schema":"y"}',b'{"entries":NaN}',b'{"entries":Infinity}'])
def test_ambiguous_json_is_not_accepted(manifest):
    rows,payload=entries()
    raw,pins=bundle(rows,payload,raw_manifest=manifest)
    with pytest.raises(ValueError):
        module.validate_bundle(raw,**pins)


def test_undeclared_object_and_corrupted_payload_rejected():
    rows,payload=entries()
    raw,pins=bundle(rows,payload,extra=('objects/'+'0'*64,b'unbound'))
    with pytest.raises(ValueError,match='undeclared'):
        module.validate_bundle(raw,**pins)
    raw,pins=bundle(rows,payload)
    changed=raw.replace(payload,b'X'*len(payload),1)
    with pytest.raises((ValueError,zipfile.BadZipFile)):
        module.validate_bundle(changed,**{**pins,'expected_archive_digest':hashlib.sha256(changed).hexdigest()})


def test_duplicate_zip_members_rejected():
    rows,payload=entries()
    with pytest.warns(UserWarning,match='Duplicate name'):
        raw,pins=bundle(rows,payload,extra=('manifest.json',b'{}'))
    with pytest.raises(ValueError,match='structure'):
        module.validate_bundle(raw,**pins)


@pytest.mark.skipif(os.geteuid()!=0,reason='requires actual Root-owned exclusive runtime ancestry')
def test_actual_root_roundtrip_preserves_runtime_tree_without_executing_payloads():
    root=Path('/opt')/('hol-runtime-bundle-test-'+uuid.uuid4().hex)
    root.mkdir(mode=0o755)
    try:
        prefix=root/'input'
        prefix.mkdir(mode=0o755)
        (prefix/'lib').mkdir(mode=0o755)
        (prefix/'bin').mkdir(mode=0o755)
        (prefix/'lib64').symlink_to('lib')
        (prefix/'bin/python').symlink_to('/usr/bin/python3.12')
        marker=root/'never-execute'
        payload='import pathlib; pathlib.Path('+repr(str(marker))+').touch()\n'
        (prefix/'lib/hostile.pth').write_text(payload)
        (prefix/'lib/hostile.pth').chmod(0o644)
        original=module.inventory(prefix)[2]
        archive=root/'runtime.zip'
        record=module.create_bundle(prefix,archive,expected_tree_digest=original)
        second=module.create_bundle(prefix,root/'again.zip',expected_tree_digest=original)
        assert second['archive_sha256']==record['archive_sha256']
        pins={'expected_archive_digest':record['archive_sha256'],'expected_tree_digest':original}
        installed=module.install_bundle(archive,root/'installed',**pins)
        assert installed['candidate_code_executed'] is False
        assert module.inventory(root/'installed')[2]==original
        assert os.readlink(root/'installed/bin/python')=='/usr/bin/python3.12'
        assert (root/'installed/lib/hostile.pth').read_text()==payload and not marker.exists()
        with pytest.raises(ValueError,match='exclusive'):
            module.install_bundle(archive,root/'installed',**pins)
        bad_rows,content=entries()
        bad_rows['../escape']=bad_rows.pop('lib/data')
        bad_raw,bad_pins=bundle(bad_rows,content)
        (root/'bad.zip').write_bytes(bad_raw)
        with pytest.raises(ValueError,match='path'):
            module.install_bundle(root/'bad.zip',root/'rejected',**bad_pins)
        assert not (root/'rejected').exists() and not (root/'escape').exists()
    finally:
        shutil.rmtree(root)

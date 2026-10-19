"""SDK transfer corruption and namespace mutations cannot become installed input."""
import hashlib
import os
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import public_tree_transfer as transfer


def example():
    return {'lib':{'kind':'directory','uid':0,'gid':0,'mode':0o755},
        'lib/input':{'kind':'file','uid':501,'gid':0,'mode':0o644,'size':3,
                     'sha256':hashlib.sha256(b'abc').hexdigest()},
        'alias':{'kind':'link','uid':0,'gid':0,'mode':0o777,'symlink':'lib/input'}}


@pytest.mark.parametrize('mutate',[
    lambda e:e.update({'../escape':e.pop('lib')}),
    lambda e:e.update({'/absolute':e.pop('lib')}),
    lambda e:e['lib/input'].update(uid=10001),
    lambda e:e['lib/input'].update(mode=0o666),
    lambda e:e['lib/input'].update(mode=0o4644),
    lambda e:e['lib/input'].update(gid=10001,mode=0o664),
    lambda e:e['lib/input'].update(size=transfer.MAX_BYTES+1),
    lambda e:e['lib/input'].update(size=True),
    lambda e:e['lib/input'].update(sha256='not-pinned'),
    lambda e:e['alias'].update(symlink='/usr/bin/python3'),
    lambda e:e['alias'].update(symlink='../external'),
    lambda e:e['alias'].update(symlink='alias'),
    lambda e:e['alias'].update(symlink='missing'),
    lambda e:e['lib'].update(kind='link',mode=0o777,symlink='alias'),
])
def test_mutated_public_tree_cannot_enter_transfer_profile(mutate):
    entries=example();mutate(entries)
    with pytest.raises(ValueError):transfer._validate(entries)


def source(tmp_path):
    root=tmp_path/'source';root.mkdir()
    (root/'lib').mkdir();(root/'lib/input').write_bytes(b'abc')
    (root/'alias').symlink_to('lib/input')
    if hasattr(os,'lchmod'):
        os.lchmod(root/'alias',0o777)  # Match Linux's immutable symlink mode in this inert fixture.
    (root/'setup.py').write_text("raise RuntimeError('must never import tree code')\n")
    return root


@pytest.mark.skipif(os.geteuid() not in {0, 501}, reason='fixture requires an approved public SDK uid')
def test_bundle_is_inert_and_preserves_existing_sdk_inventory_contract(tmp_path):
    from ci.gauntlet.benchmark.business_agent_container import freeze_public_tree
    root=source(tmp_path)
    _,tree,total=transfer.inventory(root)
    existing=freeze_public_tree(root)
    assert (tree,total)==(existing['tree_digest'],existing['bytes'])
    record=transfer.create_bundle(root,tmp_path/'sdk.zip',expected_tree_digest=tree)
    assert record['tree_digest']==tree
    assert record['archive_sha256']==hashlib.sha256((tmp_path/'sdk.zip').read_bytes()).hexdigest()
    with pytest.raises(ValueError,match='external pin'):
        transfer.create_bundle(root,tmp_path/'wrong.zip',expected_tree_digest='0'*64)


@pytest.mark.skipif(os.geteuid()!=0,reason='exact Root custody install control runs separately in owned Linux VM')
def test_root_install_roundtrip_and_corrupt_archive_rejection(tmp_path):
    # Root-only private staging; /tmp shared ancestry is deliberately unsupported.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='hol-transfer-control-',dir='/opt') as directory:
        stage=Path(directory);root=source(stage)
        _,tree,_=transfer.inventory(root)
        record=transfer.create_bundle(root,stage/'sdk.zip',expected_tree_digest=tree)
        with pytest.raises(ValueError,match='external pin'):
            transfer.install_bundle(stage/'sdk.zip',stage/'bad',expected_archive_digest='0'*64,
                                    expected_tree_digest=tree)
        assert not (stage/'bad').exists()
        installed=transfer.install_bundle(stage/'sdk.zip',stage/'installed',
            expected_archive_digest=record['archive_sha256'],expected_tree_digest=tree)
        assert installed['tree_digest']==tree
        assert transfer.inventory(stage/'installed')[0]==transfer.inventory(root)[0]
        with pytest.raises(ValueError,match='new absolute'):
            transfer.install_bundle(stage/'sdk.zip',stage/'installed',
                expected_archive_digest=record['archive_sha256'],expected_tree_digest=tree)

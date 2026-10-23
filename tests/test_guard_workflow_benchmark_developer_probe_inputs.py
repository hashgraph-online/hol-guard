"""The real grader's complete inert asset closure is required before inference."""
import hashlib

import pytest

from ci.gauntlet.benchmark import developer_probe_inputs as module


@pytest.fixture
def source(tmp_path,monkeypatch):
    for name in module.ASSET_NAMES:
        (tmp_path/name).write_bytes(b'raise RuntimeError("must never execute captured asset")\n')
    monkeypatch.setattr(module,'SOURCE',tmp_path)
    return tmp_path


def test_inventory_includes_nonpython_assets_and_never_executes_them(source):
    result=module.probe_source_identity()
    assert set(result['files'])=={str(source/name) for name in module.ASSET_NAMES}
    assert 'developer_node_bridge.mjs' in module.ASSET_NAMES
    assert 'developer_browser_probe.mjs' in module.ASSET_NAMES
    assert 'json_data.py' in module.ASSET_NAMES
    assert all(pin==hashlib.sha256((source/name).read_bytes()).hexdigest()
               for name in module.ASSET_NAMES for path,pin in result['files'].items()
               if path==str(source/name))


def test_staged_oracle_module_set_covers_its_relative_import_closure():
    import ast
    from pathlib import Path
    from ci.gauntlet.benchmark import developer_oracles
    names=set(developer_oracles.ORACLE_MODULES)
    assert names <= set(developer_oracles.ASSET_NAMES)
    for name in names:
        data=Path(developer_oracles.__file__).with_name(name).read_text()
        for node in ast.walk(ast.parse(data)):
            if isinstance(node,ast.ImportFrom) and node.level:
                assert node.level==1 and node.module and node.module+'.py' in names


@pytest.mark.parametrize('kind',['missing','symlink','directory','oversize'])
def test_invalid_grader_asset_is_rejected(source,kind):
    path=source/'developer_node_bridge.mjs'
    path.unlink()
    if kind=='symlink':
        path.symlink_to(source/'developer_browser_probe.mjs')
    elif kind=='directory':
        path.mkdir()
    elif kind=='oversize':
        path.write_bytes(b'x'*(2*1024**2+1))
    with pytest.raises(ValueError,match='probe asset'):
        module.probe_source_identity()

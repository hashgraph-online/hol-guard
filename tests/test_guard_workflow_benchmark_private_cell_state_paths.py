"""Reject unsupported provider backing paths before private state or inference."""
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import ci_runner


def loaded():
    return {'asset_root': Path('/opt'), 'attempt_layout': 'compact-v1',
            'runtime': {'guard_private_cell': {'schema': 'developer-private-cell-config.v1'}}}


@pytest.mark.parametrize('root', ['/var/ad0', '/srv/ad0', '/tmp/ad0'])
@pytest.mark.parametrize('operation', ['freeze', 'resume'])
def test_private_provider_location_rejected_before_state_or_inference(monkeypatch, root, operation):
    touched = []
    def private_state(*args, **kwargs):
        touched.append('state')
        raise AssertionError('unsupported location reached state creation or lookup')
    monkeypatch.setattr(ci_runner, 'private_state', private_state)
    with pytest.raises(ValueError, match='private-cell provider backing paths'):
        if operation == 'freeze':
            ci_runner.freeze(loaded(), Path(root))
        else:
            ci_runner.load_frozen(loaded(), Path(root), expected_manifest_digest='a'*64)
    assert touched == []


@pytest.mark.parametrize('root', ['/home/ae0', '/opt/ae0'])
def test_supported_provider_location_reaches_normal_state_checks(monkeypatch, root):
    value = loaded()
    value['asset_root'] = Path('/public-assets')
    calls = []
    def private_state(path, **kwargs):
        calls.append((path, kwargs))
        raise RuntimeError('normal custody checks retained')
    monkeypatch.setattr(ci_runner, 'private_state', private_state)
    with pytest.raises(RuntimeError, match='normal custody checks retained'):
        ci_runner.freeze(value, Path(root))
    assert calls == [(Path(root), {'create': True, 'immutable_ancestry': True})]

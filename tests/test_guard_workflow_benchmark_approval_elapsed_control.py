"""Actual clock progression and MCP service effects; no model or held clock."""
import copy
import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.approval_elapsed_control import (
    cli_summary,
    run_approval_elapsed_control,
    verify_elapsed_control,
)
from ci.gauntlet.benchmark.contracts import canonical_json


@pytest.fixture(scope='module')
def actual_control(tmp_path_factory):
    key = Ed25519PrivateKey.generate()
    root = tmp_path_factory.mktemp('actual-elapsed-controller') / 'new-control'
    envelope = run_approval_elapsed_control(root, signing_key=key)
    return key, root, envelope


def test_actual_elapsed_expiry_and_before_expiry_commit(actual_control):
    key, root, envelope = actual_control
    record = verify_elapsed_control(envelope, trusted_public_key=key.public_key().public_bytes_raw(),
        expected_sources=envelope['record']['sources_before'], require_root=False)
    committed, expired = record['lanes']
    assert committed['issued_at'] <= committed['applied_at'] < committed['expires_at']
    assert expired['attempted_at'] >= expired['expires_at']
    assert expired['attempted_monotonic'] - expired['issued_monotonic'] >= 2
    assert expired['before'] == expired['after']
    assert expired['receipts'] == expired['before_receipts']
    assert record['lifecycle'] == {'started': 2, 'closed': 2, 'active': 0}
    assert record['qualification'] is False and record['actual_model_execution'] is False
    assert (root / 'report.json').is_file()


def test_elapsed_control_requires_external_anchor_and_new_output(actual_control):
    _, root, envelope = actual_control
    other = Ed25519PrivateKey.generate()
    with pytest.raises(InvalidSignature):
        verify_elapsed_control(envelope, trusted_public_key=other.public_key().public_bytes_raw(), require_root=False)
    with pytest.raises(ValueError, match='new absolute'):
        run_approval_elapsed_control(root, signing_key=other)


def test_cli_hash_matches_actual_saved_bytes_and_labels_canonical_digest(actual_control):
    key, root, envelope = actual_control
    summary = cli_summary(root, envelope, key.public_key().public_bytes_raw().hex())
    assert summary['report_sha256'] == hashlib.sha256((root / 'report.json').read_bytes()).hexdigest()
    assert summary['envelope_canonical_sha256'] == hashlib.sha256(canonical_json(envelope).encode()).hexdigest()
    assert summary['report_sha256'] != summary['envelope_canonical_sha256']


@pytest.mark.parametrize('corruption', ['claim-time', 'expired-effect', 'held-clock', 'cleanup', 'source'])
def test_even_controller_signed_inconsistent_observations_are_rejected(actual_control, corruption):
    key, _, envelope = actual_control
    altered = copy.deepcopy(envelope)
    record = altered['record']
    if corruption == 'claim-time':
        record['lanes'][0]['applied_at'] = record['lanes'][0]['expires_at']
    elif corruption == 'expired-effect':
        record['lanes'][1]['after'] = record['lanes'][0]['after']
    elif corruption == 'held-clock':
        lane = record['lanes'][1]
        lane['attempted_monotonic'] = lane['issued_monotonic']
    elif corruption == 'cleanup':
        record['lifecycle']['active'] = 1
    else:
        record['sources_after']['approval.py'] = '0' * 64
    altered['signature'] = key.sign(canonical_json(record).encode()).hex()
    with pytest.raises(ValueError):
        verify_elapsed_control(altered, trusted_public_key=key.public_key().public_bytes_raw(), require_root=False)

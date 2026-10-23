"""Fresh, never-run campaigns must report missing outcomes without losing proof."""
import hashlib
import os
import stat
import sys

import pytest

from ci.gauntlet.benchmark.ci_gate import GateEvidenceError, gate_campaign, validate_policy
from ci.gauntlet.benchmark.contracts import digest
from ci.gauntlet.benchmark.local_campaign import load_local_campaign
from tests.test_guard_workflow_benchmark_local_campaign import freeze


@pytest.mark.parametrize('layout', ['legacy-v1', 'compact-v1'])
def test_freeze_initializes_private_empty_ledger_without_creating_attempts(tmp_path, layout):
    root, _ = freeze(tmp_path, attempt_layout=layout)
    ledger = root / 'attempts.jsonl'
    assert ledger.is_file() and ledger.read_bytes() == b''
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600
    state = load_local_campaign(root)
    assert state['ledger'] == []
    directory = root / ('a' if layout == 'compact-v1' else 'attempts')
    assert list(directory.iterdir()) == []


@pytest.mark.skipif(sys.platform != 'linux' or os.geteuid() != 0,
                    reason='exact private Linux Root controller audit')
@pytest.mark.parametrize('layout', ['legacy-v1', 'compact-v1'])
def test_unstarted_gate_retains_missing_cells_and_deleted_ledger_stays_invalid(tmp_path, layout):
    root, _ = freeze(tmp_path, attempt_layout=layout)
    state = load_local_campaign(root)
    policy = validate_policy({'schema': 'gauntlet-ci-gate-policy.v1', 'id': 'unstarted-campaign',
        'cells': [{'episode_id': cell['id'], 'outcome': 'secure-completion', 'required_surfaces': []}
                  for cell in state['config']['cells']]})
    pins = {'expected_policy_digest': digest(policy),
            'expected_config_digest': state['config']['config_digest']}
    result = gate_campaign(root, policy, **pins)
    assert result['exit_code'] == 1 and result['status'] == 'failed'
    assert result['ledger_sha256'] == hashlib.sha256(b'').hexdigest()
    assert result['charged_model_tokens_all_attempts'] == 0
    assert {row['episode_id'] for row in result['cells']} == {row['id'] for row in state['config']['cells']}
    assert all(row['status'] == 'failed' and row['reasons'] == ['scheduled-outcome-missing']
               for row in result['cells'])
    (root / 'attempts.jsonl').unlink()
    with pytest.raises(GateEvidenceError, match='attempts.jsonl'):
        gate_campaign(root, policy, **pins)

"""The beta selection must not waive Guard failures or lose comparison cells."""
from collections import Counter
import json

import pytest

from ci.gauntlet.benchmark.beta_profile import WORKFLOWS, build_profile, export_profile
from ci.gauntlet.benchmark.contracts import validate_record
from ci.gauntlet.benchmark.campaign_execution import reservation


def test_exact_paired_matrix_uses_existing_gate_contracts():
    campaign, selection, policy = build_profile()
    validate_record('campaign', campaign)
    cells = [row for row in campaign['inventory'] if row['id'] in selection]
    assert len(selection) == len(set(selection)) == len(cells) == 12
    assert Counter(row['workflow_id'] for row in cells) == dict.fromkeys(WORKFLOWS, 4)
    assert Counter((row['variant'], row['protected']) for row in cells) == {
        ('clean', False): 3, ('clean', True): 3,
        ('text-injection', False): 3, ('text-injection', True): 3}
    by_id = {row['episode_id']: row for row in policy['cells']}
    assert set(by_id) == set(selection)
    for row in cells:
        gate = by_id[row['id']]
        assert (gate['outcome'] == 'attacked-baseline-measurement') == (
            not row['protected'] and row['variant'] != 'clean')
        if row['protected']:
            assert 'native-mcp' in gate['required_surfaces']
    calibration = {row['id']: row for row in cells}
    assert all(calibration[key]['variant'] == 'clean' and
               calibration[key]['workflow_id'] == WORKFLOWS[0] for key in selection[:2])
    assert {calibration[key]['protected'] for key in selection[:2]} == {False, True}
    assert campaign['budgets']['max_retries'] == 0
    assert campaign['budgets']['campaign_tokens'] == 1_300_000
    reserves = [reservation(row, campaign['budgets']) for row in cells]
    assert sum(row['controller_seconds_reservation'] for row in reserves) <= campaign['budgets']['campaign_seconds']
    assert sum(row['model_token_reservation'] for row in reserves) <= campaign['budgets']['campaign_tokens']


def test_export_is_reproducible_and_never_overwrites(tmp_path):
    first, second = tmp_path/'first', tmp_path/'second'
    assert export_profile(first) == export_profile(second)
    for path in first.iterdir():
        assert path.read_bytes() == (second/path.name).read_bytes()
    original = (first/'selection.json').read_bytes()
    with pytest.raises(FileExistsError):
        export_profile(first)
    assert (first/'selection.json').read_bytes() == original
    assert len(json.loads((first/'calibration-selection.json').read_bytes())) == 2

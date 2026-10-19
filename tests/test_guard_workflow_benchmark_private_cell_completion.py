"""Retained real SDK/native completion; no real-model episode is inferred."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.contained_output_binding import captured_output
from ci.gauntlet.benchmark.private_cell_runtime_custody import verify_private_cell_runtime

KEY=bytes.fromhex('058c4157473f3d7dafc1980440c2be4fd088d7f16dee9a646bd9089bcac5bbb1')
ROOT='/opt/hol-private-cell-plane-control-20261014-052'


@pytest.fixture
def case():
    raw=(Path(__file__).parent/'fixtures/workflow_benchmark/private_cell_runtime_052.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='5c398c491e0e7970d2e9e3572ee874248a077acd2457eedd4ab395abf520ae90'
    value=json.loads(raw)
    record=value['evidence']['record']
    options={'trusted_public_key':KEY,'expected_settings':deepcopy(record['settings']),
        'expected_session_id':ROOT.rsplit('/',1)[1],'expected_prompt_digest':record['public_prompt_digest'],
        'workspace_source':ROOT+'/tasks/checkout','provider_mounts':(ROOT+'/tasks/remote',ROOT+'/tasks/home'),
        'require_mcp':True,**value['outside_observations']}
    return value,options


def test_actual_sdk_receives_exact_successful_reviewed_contained_output(case):
    value,options=case
    summary=verify_private_cell_runtime(value['evidence'],**options)
    assert summary['custody_verified'] and summary['native_hook_count']==3
    record=value['evidence']['record']
    assert record['schema_version']=='4.0'
    assert record['settings']['contained_completion_profile']=='guard-contained-completion.v1'
    plane=record['native_builtin_audit']['record']['product_plane']
    assert plane['executions'][0]['exit_code']==0
    post=plane['hooks'][-1]['response']
    assert post['decision']=='allow' and post['model_output_action']=='allow_original'
    assert post['artifact_name']=='bash completed contained output'
    sdk=value['sdk_result']
    assert all(row['isError'] is False for row in sdk['results'])
    assert sdk['results'][1]['content']==captured_output(plane['executions'][0])['tool_response']
    assert sdk['modelExercised'] is False and sdk['providerRequests']==0
    assert summary['product_claims_authenticated'] is summary['qualification_eligible'] is False


@pytest.mark.parametrize('profile',[None,'unknown-profile',True])
def test_completion_support_cannot_be_relabelled_under_unbound_external_settings(case,profile):
    value,options=case
    if profile is None:
        del options['expected_settings']['contained_completion_profile']
    else:
        options['expected_settings']['contained_completion_profile']=profile
    with pytest.raises(ValueError):
        verify_private_cell_runtime(value['evidence'],**options)

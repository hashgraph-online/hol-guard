"""Actual v3 custody plus re-signed binding mutants; zero new SUT executions."""
import base64
import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.contracts import canonical_json
from ci.gauntlet.benchmark.private_cell_runtime_custody import verify_private_cell_runtime

KEY=bytes.fromhex('bfb5a56c6f540608372ef09424ac8b30a62d01fa64a88b0bc899f913c1d641c2')
ROOT='/opt/hol-private-cell-plane-control-20261014-049'


@pytest.fixture
def case():
    raw=(Path(__file__).parent/'fixtures/workflow_benchmark/private_cell_runtime_049.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='83d1b1bf62a6c05061f8c0e5004013977aa8e6337cc8bc80f49aae07074430d4'
    value=json.loads(raw)
    options={'trusted_public_key':KEY,'expected_settings':deepcopy(value['evidence']['record']['settings']),
        'expected_session_id':ROOT.rsplit('/',1)[1],
        'expected_prompt_digest':value['evidence']['record']['public_prompt_digest'],
        'workspace_source':ROOT+'/tasks/checkout','provider_mounts':(ROOT+'/tasks/remote',ROOT+'/tasks/home'),
        'require_mcp':True,**value['outside_observations']}
    return value,options


def sign(value,key):
    if isinstance(value,list):
        return [sign(item,key) for item in value]
    if isinstance(value,dict):
        result={name:sign(item,key) for name,item in value.items()}
        if set(result)=={'record','signature'}:
            result['signature']=base64.b64encode(key.sign(canonical_json(result['record']).encode())).decode()
        return result
    return value


def test_real_v3_post_is_bound_to_capture_without_model_or_utility_credit(case):
    value,options=case
    assert verify_private_cell_runtime(value['evidence'],**options)['custody_verified']
    assert value['evidence']['record']['schema_version']=='3.0'
    builtin=value['evidence']['record']['native_builtin_audit']['record']
    event=next(row for row in builtin['transport_observations'] if row['kind']=='actual-contained-output-binding')
    post=next(row for row in builtin['transport_observations'] if row.get('hook_event_name')=='PostToolUse')
    assert event['output_sha256']==post['actual_output_sha256']!=event['sdk_output_sha256']
    assert value['sdk_result']['results'][1]['isError'] is True  # Real benign Post block remains visible.
    assert value['sdk_result']['modelExercised'] is False


@pytest.mark.parametrize('mutation',['missing','wrong-result','wrong-call','wrong-output','old-sdk-output','old-version'])
def test_signed_binding_changes_cannot_promote_unreviewed_sink_output(case,mutation):
    value,options=case
    record=value['evidence']['record']
    builtin=record['native_builtin_audit']['record']
    event=next(row for row in builtin['transport_observations'] if row['kind']=='actual-contained-output-binding')
    if mutation=='missing':
        builtin['transport_observations'].remove(event)
    elif mutation=='wrong-result':
        event['result_digest']='0'*64
    elif mutation=='wrong-call':
        event['tool_call_id']='other-call'
    elif mutation=='wrong-output':
        event['output_sha256']='0'*64
    elif mutation=='old-sdk-output':
        event['output_sha256']=event['sdk_output_sha256']
    else:
        record['schema_version']='2.0'
    key=Ed25519PrivateKey.generate()
    options['trusted_public_key']=key.public_key().public_bytes_raw()
    with pytest.raises(ValueError):
        verify_private_cell_runtime(sign(value['evidence'],key),**options)

"""Captured sink/output authority contracts, no modeled product decisions credited."""
import hashlib
from copy import deepcopy
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import contained_hook_router as module
from ci.gauntlet.benchmark.contained_output_binding import captured_output
from ci.gauntlet.benchmark.contained_output_custody import verify_contained_outputs
from ci.gauntlet.benchmark.contracts import digest


def result(payload,code=0):
    out={'exit_code':code,'stdout':'actual command output','stderr':'actual diagnostic',
         'payload_digest':digest(payload)}
    out.update({name+'_sha256':hashlib.sha256(out[name].encode()).hexdigest() for name in ('stdout','stderr')})
    return out


def router():
    payload={'hook_event_name':'PreToolUse','tool_call_id':'call','tool_name':'bash','tool_input':{'command':'tests'}}
    plane=SimpleNamespace(supports_contained_execution=True,requires_contained_output_binding=True,
        execute_contained=lambda payload,**_:result(payload))
    route=module.ContainedHookRouter(plane)
    token=route.prepare(payload,{'decision':'deny','policy_action':'sandbox-required',
        'required_execution_profile':'workspace-contained-v1'},request_digest='a'*64)
    return route,payload,token


def test_only_completed_detached_result_can_supply_post_text():
    route,payload,token=router()
    binding={name:payload[name] for name in ('tool_name','tool_input')}
    with pytest.raises(ValueError,match='completed original'):
        route.output_for_post('call',binding)
    returned=route.execute(token,peer_pid=42)
    returned['result']['stdout']='SDK cannot mutate stored capture'
    output=route.output_for_post('call',binding)
    assert output['tool_response'][0]['text']==(
        'Exit code: 0\nSTDOUT:\nactual command output\nSTDERR:\nactual diagnostic')
    assert output['is_error'] is False
    assert route.output_for_post('unrelated',binding) is None
    with pytest.raises(ValueError,match='completed original'):
        route.output_for_post('call',{**binding,'tool_input':{'command':'other'}})
    with pytest.raises(ValueError,match='already consumed'):
        route.execute(token,peer_pid=42)


@pytest.mark.parametrize('mutation',[
    lambda r:r.update(exit_code=True),lambda r:r.update(stdout='fabricated'),
    lambda r:r.update(stderr_sha256='0'*64),lambda r:r.update(stdout='x'*1048576,
        stdout_sha256=hashlib.sha256(b'x'*1048576).hexdigest()),
])
def test_unknown_or_unbounded_output_cannot_become_reviewed(mutation):
    row=result({})
    mutation(row)
    with pytest.raises(ValueError):
        captured_output(row)


def test_signed_custody_cannot_pair_fake_post_with_different_sink():
    route,payload,token=router()
    execution=route.execute(token,peer_pid=42)['result']
    expected=captured_output(execution)
    pre={'kind':'actual-hook-response','hook_event_name':'PreToolUse','payload_digest':digest(payload),'tool_call_id':'call'}
    post={'kind':'actual-hook-response','hook_event_name':'PostToolUse','payload_digest':'b'*64,
          'tool_call_id':'call','actual_output_sha256':expected['output_sha256']}
    binding={'sequence':3,'kind':'actual-contained-output-binding','schema':expected['schema'],'tool_call_id':'call',
        'pre_payload_digest':digest(payload),'payload_digest':post['payload_digest'],
        'result_digest':expected['result_digest'],'output_sha256':expected['output_sha256'],'sdk_output_sha256':'c'*64}
    builtin={'transport_observations':[pre,post,binding],'contained_transport_observations':route.events,
             'product_plane':{'executions':[execution]}}
    assert verify_contained_outputs(builtin)==1
    for name,change in [('missing',None),('fake-output','d'*64),('wrong-sink','e'*64),('wrong-call','another')]:
        bad=deepcopy(builtin)
        if name=='missing':
            bad['transport_observations'].pop()
        elif name=='fake-output':
            bad['transport_observations'][1]['actual_output_sha256']=change
        elif name=='wrong-sink':
            bad['transport_observations'][2]['result_digest']=change
        else:
            bad['transport_observations'][2]['tool_call_id']=change
        with pytest.raises(ValueError):
            verify_contained_outputs(bad)

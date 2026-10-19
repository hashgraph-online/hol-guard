"""Matching v4 lifecycle evidence never establishes task utility or qualification."""
import hashlib
import json
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.private_cell_runtime_custody import verify_private_cell_runtime


def _case(number, pin, key):
    path=Path(__file__).parent/f'fixtures/workflow_benchmark/private_cell_runtime_{number}.json'
    raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==pin
    value=json.loads(raw)
    record=value['evidence']['record']
    root=f'/opt/hol-private-cell-plane-control-20261014-{number}'
    options={'trusted_public_key':bytes.fromhex(key),'expected_settings':record['settings'],
        'expected_session_id':root.rsplit('/',1)[1],
        'expected_prompt_digest':record['public_prompt_digest'],'workspace_source':root+'/tasks/checkout',
        'provider_mounts':(root+'/tasks/remote',root+'/tasks/home'),'require_mcp':True,
        **value['outside_observations']}
    assert record['schema_version']=='4.0'
    assert record['settings']['prefix_digest']=='ee3fdbe9e91cd6550e721568ae71e7c2d7444dc0e24b33efdb86971dabc2c69b'
    return value,options


def test_current_native_timeout_preserves_failed_sdk_result_and_exactly_one_post():
    value,options=_case('053','934308c73ce6bccd7f1f048228822a37f3cd2d21dfa022174523e624cbeeeaa8',
        'c4a61acc5b5115c5058e084f766981b19f48bc669b179ee7d7bd9aeda31103ed')
    summary=verify_private_cell_runtime(value['evidence'],**options)
    builtin=value['evidence']['record']['native_builtin_audit']['record']
    plane=builtin['product_plane']
    assert summary['custody_verified'] and summary['native_hook_count']==3
    assert plane['executions'][0]['exit_code']==124
    assert [row['hook_event_name'] for row in plane['hooks']]==[
        'UserPromptSubmit','PreToolUse','PostToolUse']
    assert builtin['review_summary']['post_review_counts']=={'sdk-contained-control':1}
    assert value['sdk_result']['results'][1]['isError'] is True
    assert summary['qualification_eligible'] is False and 'utility_passed' not in summary


def test_current_native_cancellation_keeps_partial_evidence_and_refuses_completed_custody():
    value,options=_case('054','399e6c2d70d14b84b5820729ee13da1b6d4f0ba83b5218f56f2c831401d8b230',
        '63c9fb56133ce432d539b127581a7eee3e7e89b4d6be5146fe6cac3dc781792c')
    builtin=value['evidence']['record']['native_builtin_audit']['record']
    plane=builtin['product_plane']
    failures=[row for row in plane['observations'] if row['kind']=='actual-native-capture-failure']
    assert len(failures)==1 and failures[0]['exception_type']=='InterruptedError'
    assert failures[0]['cell_closed'] is True and len(failures[0]['kernel_process_samples'])==5
    assert plane['executions']==[]
    assert builtin['review_summary']['missing_required_post_call_ids']==['sdk-contained-control']
    with pytest.raises(ValueError):
        verify_private_cell_runtime(value['evidence'],**options)

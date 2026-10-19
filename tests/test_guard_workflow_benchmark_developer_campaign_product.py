"""Native review-history units; no real SDK or product execution is claimed."""
import copy

import pytest

from ci.gauntlet.benchmark.developer_campaign_product import verify_builtin_review_history


def event(phase, decision='allow'):
    return {'kind': 'actual-hook-response', 'hook_event_name': phase, 'tool_call_id': 'call-1',
            'tool_name': 'bash', 'payload_digest': 'payload-pre' if phase == 'PreToolUse' else 'payload-post',
            'original_input_digest': 'input', 'actual_output_sha256': 'a'*64 if phase == 'PostToolUse' else None,
            'product_response': {'decision': decision}}


def record(events, contained=()):
    return {'transport_observations': events, 'contained_transport_observations': list(contained)}


def test_actual_native_refusal_needs_no_backend_output_and_is_not_unsupported():
    assert verify_builtin_review_history(record([event('PreToolUse', 'deny')])) == {
        'builtin_pre_count': 1, 'builtin_post_count': 0}


def test_allow_and_actual_output_review_are_both_required():
    assert verify_builtin_review_history(record([event('PreToolUse'), event('PostToolUse')])) == {
        'builtin_pre_count': 1, 'builtin_post_count': 1}
    with pytest.raises(ValueError, match='mandatory actual output'):
        verify_builtin_review_history(record([event('PreToolUse')]))


def test_consumed_real_sink_requires_post_even_when_original_native_decision_is_deny():
    pre = event('PreToolUse', 'deny')
    pre['product_response'].update(required_execution_profile='workspace-contained-v1',
                                   policy_action='sandbox-required')
    consumed = [{'kind': 'contained-route-consumed', 'payload_digest': pre['payload_digest']}]
    with pytest.raises(ValueError, match='mandatory actual output'):
        verify_builtin_review_history(record([pre], consumed))
    verify_builtin_review_history(record([pre, event('PostToolUse')], consumed))


@pytest.mark.parametrize('failure', ['changed-input', 'orphan-post', 'duplicate-pre', 'mcp', 'missing-output'])
def test_missing_or_wrong_review_cannot_gain_custody_coverage(failure):
    rows = [event('PreToolUse'), event('PostToolUse')]
    if failure == 'changed-input':
        rows[1]['original_input_digest'] = 'other-input'
    elif failure == 'orphan-post':
        rows = rows[1:]
    elif failure == 'duplicate-pre':
        rows.insert(1, copy.deepcopy(rows[0]))
    elif failure == 'mcp':
        rows[0]['tool_name'] = 'mcp_docs_read'
    else:
        rows[1]['actual_output_sha256'] = None
    with pytest.raises(ValueError):
        verify_builtin_review_history(record(rows))

"""Availability fallbacks are observations, never completed native review proof.

Kept as inert benchmark data: trusted collectors/verifiers must not import the
candidate Guard package. A source-contract test detects producer vocabulary drift.
"""
UNREVIEWABLE_REASONS=frozenset({
    'native_policy_not_ready','native_policy_update_in_progress','native_hook_event_unavailable','native_pre_tool_unavailable',
    'native_post_tool_unavailable','native_overloaded','native_hook_worker_unavailable',
    'native_hook_worker_unavailable_before_compatibility','native_hook_worker_unsupported',
    'native_hook_worker_exception','native_hook_compatibility_disabled','native_hook_edge_invalid_response',
    'native_hook_edge_unavailable','python_hook_oracle_unavailable','python_oracle_exception',
    'watch_recording_only','daemon_hook_queue_capacity','daemon_hook_deadline_exhausted',
    'daemon_hook_process_deadline_exhausted','daemon_hook_process_not_ready','daemon_hook_process_failed',
    'daemon_hook_process_invalid_request','daemon_hook_process_guard_home_mismatch','daemon_worker_exception',
    'harness_not_managed','invalid_hook_payload_reference','daemon_hook_queue_bytes','native_prompt_unavailable',
})


def review_completed(response):
    return (type(response) is dict and response.get('reason_code') not in UNREVIEWABLE_REASONS
            and response.get('recording_only') is not True and response.get('observe_mode') is not True)

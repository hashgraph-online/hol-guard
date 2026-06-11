## Review Local Queue Contract

Guard Local owns live pending requests. Guard Cloud may mirror or reuse this data,
but it does not replace the local queue.

### Pending request payload

Local pending request payload is already defined by
`src/codex_plugin_scanner/guard/store_approvals.py` `_row_to_payload(...)` and is
surfaced through both:

- daemon `GET /v1/requests`
- `build_runtime_snapshot(..., include_items=True)`

Current payload keys include:

- `request_id`
- `harness`
- `artifact_id`, `artifact_name`, `artifact_type`, `artifact_hash`
- `policy_action`, `recommended_scope`, `source_scope`
- `workspace`, `publisher`, `config_path`, `launch_target`
- `action_identity`, `queue_group_id`, `dedupe_count`, `last_seen_at`
- `risk_summary`, `risk_signals`, `why_now`, `trigger_summary`, `launch_summary`
- `review_command`, `approval_url`
- `status`, `resolution_action`, `resolution_scope`, `reason`
- `created_at`, `resolved_at`

### Resolution scopes

Runtime ask-flow scopes currently exposed in
`src/codex_plugin_scanner/guard/runtime/decisions.py` are:

- `artifact`
- `workspace`
- `publisher`
- `harness`

Resolution logic in `src/codex_plugin_scanner/guard/approvals.py`
`apply_approval_resolution(...)` also supports broader local persistence for:

- `global`

### Local lifecycle events

Local queue lifecycle emits:

- `approval.created` when a new pending request row is created
- `approval.resolved` when a pending request is resolved

Duplicate requeues reuse the first pending request id and should not emit a second
`approval.created` event for the same pending row.

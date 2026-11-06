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
- `policy_action`, `recommended_scope`, `source_scope`, `oauth_source`
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

### Cloud connection ownership

Each newly created approval request is permanently bound to the normalized OAuth
connection source that created it. Its live-request outbox event carries the same
source plus non-reversible OAuth-subject, workspace, machine, and local
installation bindings resolved by application code in the request transaction.
SQLite triggers never read OAuth state. Queue deduplication, ready selection,
acknowledgement, retry, and sync health state are identity-scoped. The default
source retains the original command behavior and sync-state key.

Changing or reconnecting a source does not move events that were already bound to
another workspace. The source's sync status reports those events as
`other_workspace_depth`; they are retained locally rather than delivered to the
new workspace. Events created while the source has no workspace remain visible as
`unbound_depth` and are claimed only by that same source.

During migration, rows created before source ownership was recorded are treated
as ambiguous. Guard clears any previously inferred workspace and reports them as
`legacy_unbound_depth`. No sync worker adopts these rows automatically. After
verifying the destination account, an operator can explicitly approve a bulk
reassignment with:

```bash
hol-guard connect reassign-quarantined \
  --source SOURCE \
  --confirm-source SOURCE \
  --confirm-workspace WORKSPACE_ID
```

Both confirmations must exactly match the active source and its current OAuth
workspace; otherwise Guard leaves every row quarantined. The `binding_state`
diagnostic distinguishes `healthy`, `awaiting_workspace_claim`,
`workspace_mismatch`, `identity_mismatch`, and `legacy_ambiguous`, with a
non-sensitive `binding_hint` when operator action may be needed.

//! The `guard_review_outbox_after_update` trigger `_update_trigger` in
//! `store_review_event_outbox_schema.py` renders: it records a resolved or refreshed event for every approval row update.
//! The text is the Python rendering byte for byte;
//! `tests/test_native_schema_review_outbox_parity.py` holds the copies equal.

pub(super) const UPDATE_TRIGGER: &str = r##"
        create trigger if not exists guard_review_outbox_after_update
        after update on approval_requests
        begin
          insert into guard_review_outbox_request_sequences (
            local_request_id, last_sequence, updated_at
          ) values (new.request_id, 1, coalesce(new.resolved_at, new.last_seen_at, new.created_at))
          on conflict(local_request_id) do update set
            last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
            updated_at = excluded.updated_at;
          insert into guard_review_outbox_events (
            event_id, local_request_id, request_sequence, event_type,
            event_schema_version, payload_json, payload_hash, occurred_at,
            oauth_source, oauth_subject_hash, workspace_id, machine_id,
            machine_installation_id, binding_status, quarantine_reason
          ) values (
            lower(hex(randomblob(16))),
            new.request_id,
            (select last_sequence from guard_review_outbox_request_sequences
             where local_request_id = new.request_id),
            case when old.status <> new.status then 'review.request.resolved' else 'review.request.refreshed' end,
            1,
            case when old.status <> new.status then json_object(
      'schema', 'guard-cloud-review-event-v2',
      'localRequestId', new.request_id,
      'eventType', 'review.request.resolved',
      'occurredAt', coalesce(new.resolved_at, new.last_seen_at, new.created_at),
      'status', new.status,
      'resolutionAction', new.resolution_action,
      'resolutionScope', new.resolution_scope,
      'reason', new.reason,
      'oauthSource', new.oauth_source,
      'requestSnapshot', json_object(
        'request_id', new.request_id,
        'harness', new.harness,
        'artifact_id', new.artifact_id,
        'artifact_name', new.artifact_name,
        'artifact_type', new.artifact_type,
        'artifact_hash', new.artifact_hash,
        'publisher', new.publisher,
        'policy_action', new.policy_action,
        'recommended_scope', new.recommended_scope,
        'changed_fields_json', new.changed_fields_json,
        'source_scope', new.source_scope,
        'oauth_source', new.oauth_source,
        'config_path', new.config_path,
        'workspace', new.workspace,
        'launch_target', new.launch_target,
        'normalized_identity_key', new.normalized_identity_key,
        'action_identity', new.action_identity,
        'queue_group_id', new.queue_group_id,
        'dedupe_count', new.dedupe_count,
        'last_seen_at', new.last_seen_at,
        'transport', new.transport,
        'risk_summary', new.risk_summary,
        'risk_signals_json', new.risk_signals_json,
        'artifact_label', new.artifact_label,
        'source_label', new.source_label,
        'trigger_summary', new.trigger_summary,
        'why_now', new.why_now,
        'launch_summary', new.launch_summary,
        'risk_headline', new.risk_headline,
        'action_envelope_json', new.action_envelope_json,
        'decision_v2_json', new.decision_v2_json,
        'fallback_cli_command', new.fallback_cli_command,
        'scanner_evidence_json', new.scanner_evidence_json,
        'browser_intent_json', new.browser_intent_json,
        'continuation_snapshot_json', new.continuation_snapshot_json,
        'desktop_notified_at', new.desktop_notified_at,
        'raw_command_text', new.raw_command_text,
        'guard_version', new.guard_version,
        'first_seen_guard_version', new.first_seen_guard_version,
        'last_seen_guard_version', new.last_seen_guard_version,
        'watch_only_observation', new.watch_only_observation,
        'review_command', new.review_command,
        'approval_url', new.approval_url,
        'status', new.status,
        'resolution_action', new.resolution_action,
        'resolution_scope', new.resolution_scope,
        'reason', new.reason,
        'created_at', new.created_at,
        'resolved_at', new.resolved_at
      )
    ) else json_object(
      'schema', 'guard-cloud-review-event-v2',
      'localRequestId', new.request_id,
      'eventType', 'review.request.refreshed',
      'occurredAt', coalesce(new.resolved_at, new.last_seen_at, new.created_at),
      'status', new.status,
      'resolutionAction', new.resolution_action,
      'resolutionScope', new.resolution_scope,
      'reason', new.reason,
      'oauthSource', new.oauth_source,
      'requestSnapshot', json_object(
        'request_id', new.request_id,
        'harness', new.harness,
        'artifact_id', new.artifact_id,
        'artifact_name', new.artifact_name,
        'artifact_type', new.artifact_type,
        'artifact_hash', new.artifact_hash,
        'publisher', new.publisher,
        'policy_action', new.policy_action,
        'recommended_scope', new.recommended_scope,
        'changed_fields_json', new.changed_fields_json,
        'source_scope', new.source_scope,
        'oauth_source', new.oauth_source,
        'config_path', new.config_path,
        'workspace', new.workspace,
        'launch_target', new.launch_target,
        'normalized_identity_key', new.normalized_identity_key,
        'action_identity', new.action_identity,
        'queue_group_id', new.queue_group_id,
        'dedupe_count', new.dedupe_count,
        'last_seen_at', new.last_seen_at,
        'transport', new.transport,
        'risk_summary', new.risk_summary,
        'risk_signals_json', new.risk_signals_json,
        'artifact_label', new.artifact_label,
        'source_label', new.source_label,
        'trigger_summary', new.trigger_summary,
        'why_now', new.why_now,
        'launch_summary', new.launch_summary,
        'risk_headline', new.risk_headline,
        'action_envelope_json', new.action_envelope_json,
        'decision_v2_json', new.decision_v2_json,
        'fallback_cli_command', new.fallback_cli_command,
        'scanner_evidence_json', new.scanner_evidence_json,
        'browser_intent_json', new.browser_intent_json,
        'continuation_snapshot_json', new.continuation_snapshot_json,
        'desktop_notified_at', new.desktop_notified_at,
        'raw_command_text', new.raw_command_text,
        'guard_version', new.guard_version,
        'first_seen_guard_version', new.first_seen_guard_version,
        'last_seen_guard_version', new.last_seen_guard_version,
        'watch_only_observation', new.watch_only_observation,
        'review_command', new.review_command,
        'approval_url', new.approval_url,
        'status', new.status,
        'resolution_action', new.resolution_action,
        'resolution_scope', new.resolution_scope,
        'reason', new.reason,
        'created_at', new.created_at,
        'resolved_at', new.resolved_at
      )
    ) end,
            '',
            coalesce(new.resolved_at, new.last_seen_at, new.created_at),
            coalesce((
      select oauth_source
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ), new.oauth_source),
            (
      select oauth_subject_hash
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ),
            (
      select workspace_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ),
            (
      select machine_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ),
            (
      select machine_installation_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ),
            case when (
      select oauth_subject_hash
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null and (
      select workspace_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null and (
      select machine_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null and (
      select machine_installation_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null then 'ready' else 'quarantined' end,
            case when (
      select oauth_subject_hash
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null and (
      select workspace_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null and (
      select machine_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null and (
      select machine_installation_id
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    ) is not null then null else 'identity_incomplete' end
          );
        end
    "##;

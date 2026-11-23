"""Columns and indexes the store adds to tables created by older releases.

Each list names the columns a table gained after it first shipped, in the
order the store adds them. The native runtime keeps its own copy
(``guard_store_schema_columns.rs``), and a parity test holds the two equal.
"""

from __future__ import annotations

import sqlite3

POLICY_COLUMNS: tuple[tuple[str, str], ...] = (
    ("publisher", "text"),
    ("artifact_hash", "text"),
    ("owner", "text"),
    ("source", "text not null default 'local'"),
    ("expires_at", "text"),
    ("integrity_version", "integer"),
    ("integrity_generation", "integer"),
    ("payload_hash", "text"),
    ("payload_mac", "text"),
    ("integrity_key_id", "text"),
    ("signed_at", "text"),
    ("policy_document_schema_version", "text"),
    ("policy_document_id", "text"),
    ("policy_document_digest", "text"),
    ("policy_rule_id", "text"),
    ("policy_provenance_json", "text"),
)

LOCAL_ONCE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("integrity_version", "integer"),
    ("payload_hash", "text"),
    ("payload_mac", "text"),
    ("integrity_key_id", "text"),
    ("signed_at", "text"),
    ("authority_kind", "text"),
)

RECEIPT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("capabilities_summary", "text not null default ''"),
    ("scanner_evidence_json", "text not null default '[]'"),
    ("diff_summary", "text"),
    ("approval_source", "text"),
    ("approval_request_id", "text"),
    ("raw_command_text", "text"),
)

APPROVAL_COLUMNS: tuple[tuple[str, str], ...] = (
    ("artifact_type", "text not null default 'artifact'"),
    ("launch_target", "text"),
    ("transport", "text"),
    ("risk_summary", "text"),
    ("risk_signals_json", "text not null default '[]'"),
    ("artifact_label", "text"),
    ("source_label", "text"),
    ("trigger_summary", "text"),
    ("why_now", "text"),
    ("launch_summary", "text"),
    ("risk_headline", "text"),
    ("action_envelope_json", "text"),
    ("decision_v2_json", "text"),
    ("workspace", "text"),
    ("normalized_identity_key", "text"),
    ("action_identity", "text"),
    ("queue_group_id", "text"),
    ("dedupe_count", "integer not null default 1"),
    ("last_seen_at", "text"),
    ("fallback_cli_command", "text"),
    ("scanner_evidence_json", "text not null default '[]'"),
    ("browser_intent_json", "text"),
    ("desktop_notified_at", "text"),
    ("raw_command_text", "text"),
    ("continuation_snapshot_json", "text"),
    ("extension_allow_hint_json", "text"),
)

ATTACHMENT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("lease_id", "text not null default ''"),
    ("lease_expires_at", "text"),
)

POLICY_INDEX_STATEMENTS = (
    """
    create index if not exists idx_policy_decisions_reuse_artifact
    on policy_decisions (action, harness, artifact_id, updated_at desc, decision_id desc)
    """,
    """
    create index if not exists idx_policy_decisions_reuse_hash
    on policy_decisions (action, harness, artifact_hash, updated_at desc, decision_id desc)
    """,
    """
    create index if not exists idx_policy_decisions_reuse_publisher
    on policy_decisions (action, harness, publisher, updated_at desc, decision_id desc)
    """,
    """
    create index if not exists idx_policy_decisions_lookup_artifact
    on policy_decisions (artifact_id, harness, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'artifact'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_workspace
    on policy_decisions (workspace, harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'workspace'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_publisher
    on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'publisher'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_publisher_legacy
    on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'publisher' and artifact_hash is not null
      and artifact_hash not like 'guard-approval-context:v1:%'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_harness
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'harness'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_harness_legacy
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'harness' and artifact_hash is not null
      and artifact_hash not like 'guard-approval-context:v1:%'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_global
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'global'
    """,
    """
    create index if not exists idx_policy_decisions_lookup_global_legacy
    on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
    where scope = 'global' and artifact_hash is not null
      and artifact_hash not like 'guard-approval-context:v1:%'
    """,
    """
    create index if not exists idx_policy_decisions_diagnostic_harness_broad
    on policy_decisions (harness, updated_at desc, decision_id desc)
    where scope = 'harness' and action = 'allow' and artifact_id is null
    """,
    """
    create index if not exists idx_policy_decisions_diagnostic_global_broad
    on policy_decisions (harness, updated_at desc, decision_id desc)
    where scope = 'global' and action = 'allow' and artifact_id is null
    """,
    """
    create index if not exists idx_policy_decisions_diagnostic_publisher
    on policy_decisions (harness, publisher, updated_at desc, decision_id desc)
    where scope = 'publisher' and action = 'allow'
    """,
)

LOCAL_ONCE_INDEX_STATEMENT = """
create index if not exists idx_guard_exact_cloud_local_once_lookup
on guard_local_once_approvals (authority_kind, request_id, claimed_at, expires_at)
"""


def ensure_columns(connection: sqlite3.Connection, table_name: str, columns: tuple[tuple[str, str], ...]) -> None:
    """Add each column the table does not have yet, in list order."""
    rows = connection.execute(f"pragma table_info({table_name})").fetchall()
    existing = {str(row[1]) for row in rows}
    for column_name, column_type in columns:
        if column_name in existing:
            continue
        connection.execute(f"alter table {table_name} add column {column_name} {column_type}")
        existing.add(column_name)

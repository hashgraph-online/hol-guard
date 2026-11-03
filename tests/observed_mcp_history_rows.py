"""Seed the paused requests and receipts the resident reads for the connector scan."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from codex_plugin_scanner.guard.store import GuardStore


def seed_observed_mcp_history(
    store: GuardStore,
    *,
    approvals: Sequence[Mapping[str, object]] = (),
    receipts: Sequence[Mapping[str, object]] = (),
) -> None:
    """Write history rows; a time a row leaves out is empty, so the scan falls back to its own."""

    with store._connect() as connection:
        for row in approvals:
            (count,) = connection.execute("select count(*) from approval_requests").fetchone()
            connection.execute(
                "insert into approval_requests (request_id, harness, artifact_id, artifact_name, "
                "artifact_type, artifact_hash, policy_action, recommended_scope, changed_fields_json, "
                "source_scope, config_path, review_command, approval_url, status, created_at, "
                "last_seen_at, raw_command_text) "
                "values (?, ?, '', ?, 'tool_call', '', 'review', 'artifact', '[]', 'global', '', '', '', "
                "'pending', ?, ?, ?)",
                (
                    f"observed-request-{count}",
                    row["harness"],
                    row.get("artifact_name", ""),
                    row.get("created_at", ""),
                    row.get("last_seen_at"),
                    row.get("raw_command_text"),
                ),
            )
        for row in receipts:
            (count,) = connection.execute("select count(*) from runtime_receipts").fetchone()
            connection.execute(
                "insert into runtime_receipts (receipt_id, harness, artifact_id, artifact_hash, "
                "policy_decision, changed_capabilities_json, provenance_summary, timestamp, "
                "artifact_name, raw_command_text) "
                "values (?, ?, '', '', 'allow', '[]', '', ?, ?, ?)",
                (
                    f"observed-receipt-{count}",
                    row["harness"],
                    row.get("timestamp", ""),
                    row.get("artifact_name"),
                    row.get("raw_command_text"),
                ),
            )
        connection.commit()

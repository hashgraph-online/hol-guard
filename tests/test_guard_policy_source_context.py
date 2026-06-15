"""Tests for remembered-rule display enrichment."""

from __future__ import annotations

import sqlite3

from codex_plugin_scanner.guard.store_policy_source_context import (
    _build_policy_source_context_from_rows,
    _is_human_policy_label,
)


def _approval_row(
    *,
    trigger_summary: str | None = None,
    launch_target: str | None = None,
    workspace: str | None = "/srv/projects/sample-portal",
    artifact_name: str | None = "tool action",
) -> sqlite3.Row:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        create table approval_requests (
            request_id text,
            artifact_name text,
            launch_summary text,
            launch_target text,
            workspace text,
            resolved_at text,
            trigger_summary text,
            resolution_scope text
        )
        """
    )
    connection.execute(
        """
        insert into approval_requests values (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "req-1",
            artifact_name,
            "Shell command review",
            launch_target,
            workspace,
            "2026-06-11T12:00:00Z",
            trigger_summary,
            "workspace",
        ),
    )
    row = connection.execute("select * from approval_requests").fetchone()
    assert row is not None
    return row


def _receipt_row(*, artifact_name: str) -> sqlite3.Row:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        create table runtime_receipts (
            receipt_id text,
            artifact_name text,
            capabilities_summary text,
            provenance_summary text,
            source_scope text,
            scanner_evidence_json text,
            artifact_id text
        )
        """
    )
    connection.execute(
        """
        insert into runtime_receipts values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "receipt-1",
            artifact_name,
            "Bash credential-looking output",
            "evaluated from /srv/projects/sample-portal",
            "/srv/projects/sample-portal",
            None,
            "cursor:project:tool-action:abc",
        ),
    )
    row = connection.execute("select * from runtime_receipts").fetchone()
    assert row is not None
    return row


def test_scanner_generated_labels_are_rejected() -> None:
    assert not _is_human_policy_label("Bash credential-looking output")


def test_approval_backtick_command_wins_over_scanner_receipt_name() -> None:
    context = _build_policy_source_context_from_rows(
        receipt_row=_receipt_row(artifact_name="Bash credential-looking output"),
        inventory_row=None,
        approval_row=_approval_row(trigger_summary="Guard paused `git status` in this project."),
        workspace="workspace:hash",
        reason="approved in review",
    )
    assert context is not None
    assert context["remembered_command"] == "git status"
    assert context["source_receipt_id"] == "receipt-1"
    assert context["workspace_label"] == "sample-portal"


def test_null_approval_name_does_not_become_remembered_command() -> None:
    context = _build_policy_source_context_from_rows(
        receipt_row=None,
        inventory_row=None,
        approval_row=_approval_row(trigger_summary=None, launch_target=None, artifact_name=None),
        workspace=None,
        reason="approved in review",
    )
    assert context is not None
    assert context.get("remembered_command") != "None"

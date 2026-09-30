from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard.adapters.capability_report import (
    CAPABILITY_REPORT_SCHEMA,
    build_capability_report,
    render_capability_report_json,
    render_capability_report_markdown,
    validate_capability_report,
)
from codex_plugin_scanner.guard.adapters.contracts import contract_for


def _report_payload() -> dict[str, object]:
    return build_capability_report(build_id="test-build", commit="abc123").to_dict()


def _rows(payload: dict[str, object]) -> list[dict[str, object]]:
    rows = payload["capabilities"]
    assert isinstance(rows, list)
    return [row for row in rows if isinstance(row, dict)]


def test_default_report_is_versioned_conservative_and_schema_valid() -> None:
    payload = _report_payload()
    assert payload["schema_version"] == "harness-capability-report.v1"
    assert payload["build"] == "test-build"
    assert payload["commit"] == "abc123"
    assert payload["requested_host"] is None
    assert _rows(payload)
    assert all(row["deployment_health"] == "unverified" for row in _rows(payload))
    assert all(row["evidence_level"] == "not_run" for row in _rows(payload))
    declared_actions = {action for row in _rows(payload) for action in row["declared_actions"]}
    assert declared_actions <= {
        "inspect",
        "observe",
        "block",
        "approval",
        "suggest",
        "rewrite",
        "redact-before-forward",
        "inventory",
        "unavailable",
    }
    Draft202012Validator.check_schema(CAPABILITY_REPORT_SCHEMA)
    validate_capability_report(payload)


def test_json_and_markdown_are_deterministic_views_of_the_same_rows() -> None:
    report = build_capability_report(build_id="build-a", commit="commit-a")
    first_json = render_capability_report_json(report)
    second_json = render_capability_report_json(report)
    first_markdown = render_capability_report_markdown(report)
    second_markdown = render_capability_report_markdown(report)

    assert first_json == second_json
    assert first_markdown == second_markdown
    json_payload = json.loads(first_json)
    assert json_payload == report.to_dict()
    assert "| Harness | Adapter |" in first_markdown
    assert "unverified" in first_markdown
    assert "not_run" in first_markdown
    assert "synthetic canaries do not establish a live block" in first_markdown
    lines = first_markdown.splitlines()
    header_index = next(index for index, line in enumerate(lines) if line.startswith("| Harness | Adapter |"))
    assert lines[header_index].count("|") == lines[header_index + 1].count("|")
    assert lines[header_index + 1].count("---") == lines[header_index].count("|") - 1


def test_markdown_preserves_a_backslash_before_a_literal_pipe() -> None:
    payload = _report_payload()
    _rows(payload)[0]["source_reference"] = r"path\|part"
    assert r"path\\\|part" in render_capability_report_markdown(payload)


def test_host_scope_cannot_be_applied_to_every_registered_host() -> None:
    with pytest.raises(ValueError, match="one requested host"):
        build_capability_report(host_version_scope="claude-code@2.1.179")


def test_missing_hook_rows_are_explicit_and_not_claimed_by_legacy_surfaces() -> None:
    claude = contract_for("claude-code")
    cursor = contract_for("cursor")
    assert claude is not None and cursor is not None
    assert "prompt" not in claude.event_surfaces
    assert "prompt submission" in cursor.known_blind_spots.lower()

    payload = build_capability_report(requested_host="claude-code").to_dict()
    claude_prompt = [row for row in _rows(payload) if row["event"] == "UserPromptSubmit"]
    assert len(claude_prompt) == 1
    assert claude_prompt[0]["transport"] == "none"
    assert claude_prompt[0]["mode"] == "unsupported"
    assert claude_prompt[0]["declared_actions"] == ["unavailable"]
    assert "not intercepted" in str(claude_prompt[0]["known_blind_spots"])

    cursor_payload = build_capability_report(requested_host="cursor").to_dict()
    cursor_prompt = [row for row in _rows(cursor_payload) if row["event"] == "UserPromptSubmit"]
    assert len(cursor_prompt) == 1
    assert cursor_prompt[0]["transport"] == "none"
    assert cursor_prompt[0]["mode"] == "unsupported"

    opencode_payload = build_capability_report(requested_host="opencode").to_dict()
    opencode_prompt = [row for row in _rows(opencode_payload) if row["event"] == "UserPromptSubmit"]
    assert len(opencode_prompt) == 1
    assert opencode_prompt[0]["mode"] == "unsupported"


def test_pi_cline_and_native_hook_rows_stay_separate() -> None:
    report = build_capability_report()
    rows = _rows(report.to_dict())

    pi_events = {(str(row["event"]), str(row["transport"])) for row in rows if row["harness"] == "pi"}
    assert ("PreToolUse", "managed_extension") in pi_events
    assert ("PostToolUse", "managed_extension") in pi_events
    omp_events = {(str(row["event"]), str(row["transport"])) for row in rows if row["harness"] == "omp"}
    assert {
        ("UserPromptSubmit", "managed_extension"),
        ("PreToolUse", "managed_extension"),
        ("PostToolUse", "managed_extension"),
    } <= omp_events
    grok_rows = {row["event"]: row for row in rows if row["harness"] == "grok"}
    assert grok_rows["PreToolUse"]["mode"] == "blocking"
    assert grok_rows["UserPromptSubmit"]["mode"] == "observe"

    cline_post = [row for row in rows if row["harness"] == "cline" and row["event"] == "PostToolUse"]
    assert {row["transport"] for row in cline_post} == {"native_hook", "agent_plugin"}
    plugin_row = next(row for row in cline_post if row["transport"] == "agent_plugin")
    native_row = next(row for row in cline_post if row["transport"] == "native_hook")
    assert plugin_row["mode"] == "replace_or_withhold"
    assert native_row["mode"] == "observe"
    cline_prompt = next(row for row in rows if row["harness"] == "cline" and row["event"] == "UserPromptSubmit")
    assert cline_prompt["mode"] == "observe"
    assert cline_prompt["declared_actions"] == ["observe"]
    cline_pretool = next(
        row
        for row in rows
        if row["harness"] == "cline" and row["event"] == "PreToolUse" and row["transport"] == "native_hook"
    )
    assert "emergency-safe inspection" in str(cline_pretool["error_behavior"])
    cline_events = {row["event"] for row in rows if row["harness"] == "cline"}
    assert {"TaskStart", "TaskError", "SessionShutdown"} <= cline_events

    codex_events = {row["event"] for row in rows if row["harness"] == "codex"}
    claude_events = {row["event"] for row in rows if row["harness"] == "claude-code"}
    cursor_events = {row["event"] for row in rows if row["harness"] == "cursor"}
    assert {"PreToolUse", "PostToolUse", "UserPromptSubmit"} <= codex_events
    assert {"PreToolUse", "PostToolUse", "PermissionRequest"} <= claude_events
    assert {"beforeShellExecution", "beforeMCPExecution", "beforeReadFile"} <= cursor_events


def test_unknown_cowork_is_an_explicit_unsupported_row_without_adapter_registration() -> None:
    assert contract_for("cowork") is None
    report = build_capability_report(build_id="b", commit="c", requested_host="Cowork")
    payload = report.to_dict()
    assert payload["requested_host"] == "Cowork"
    rows = _rows(payload)
    assert len(rows) == 1
    assert rows[0]["harness"] == "cowork"
    assert rows[0]["adapter"] == "unsupported"
    assert rows[0]["transport"] == "none"
    assert rows[0]["deployment_health"] == "unverified"
    assert rows[0]["evidence_level"] == "not_run"


def test_untrusted_host_label_is_safe_in_markdown_and_cannot_become_live_block() -> None:
    report = build_capability_report(
        build_id="b",
        commit="c",
        requested_host="<script>`|Cowork",
        host_version_scope="host@1",
        os_arch="linux/x86_64",
    )
    markdown = render_capability_report_markdown(report)
    assert "<script>" not in markdown
    assert "&lt;script&gt;&#96;\\|Cowork" in markdown
    payload = report.to_dict()
    row = _rows(payload)[0]
    row.update(
        {
            "deployment_health": "healthy",
            "evidence_level": "live_block",
            "observed_at": "2026-09-22T00:00:00Z",
            "expires_at": "2026-09-30T00:00:00Z",
            "evidence_reference": "synthetic/example",
            "evidence_build": "b",
            "evidence_host_version_scope": "host@1",
            "evidence_os_arch": "linux/x86_64",
            "denied_witness_reference": "synthetic/denied",
            "allowed_witness_reference": "synthetic/allowed",
            "compatibility_verified": True,
        }
    )
    with pytest.raises(ValueError, match="declared blocking boundary"):
        validate_capability_report(payload, now=datetime(2026, 9, 23, tzinfo=timezone.utc))


def test_invalid_and_stale_evidence_are_rejected_without_upgrading_canaries() -> None:
    invalid = deepcopy(_report_payload())
    invalid_rows = _rows(invalid)
    invalid_rows[0]["evidence_level"] = "file_presence"
    with pytest.raises(ValidationError):
        validate_capability_report(invalid)

    stale = deepcopy(_report_payload())
    stale_row = _rows(stale)[0]
    stale_row.update(
        {
            "evidence_level": "synthetic_canary",
            "observed_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-02T00:00:00Z",
            "evidence_reference": "tests/fixtures/generic-canary.json",
        }
    )
    with pytest.raises(ValueError, match="stale"):
        validate_capability_report(stale, now=datetime(2026, 9, 23, tzinfo=timezone.utc))
    assert stale_row["evidence_level"] == "synthetic_canary"

    live_without_health = deepcopy(_report_payload())
    live_row = _rows(live_without_health)[0]
    live_row.update(
        {
            "evidence_level": "live_block",
            "observed_at": "2026-09-22T00:00:00Z",
            "expires_at": "2026-09-30T00:00:00Z",
            "evidence_reference": "tests/fixtures/generic-live-block.json",
            "evidence_build": "test-build",
            "evidence_host_version_scope": "unknown",
            "evidence_os_arch": "unknown",
            "denied_witness_reference": "tests/fixtures/denied.json",
            "allowed_witness_reference": "tests/fixtures/allowed.json",
        }
    )
    with pytest.raises(ValueError, match="known declared"):
        validate_capability_report(live_without_health, now=datetime(2026, 9, 23, tzinfo=timezone.utc))

    healthy = build_capability_report(
        build_id="test-build",
        commit="abc123",
        requested_host="codex",
        host_version_scope="synthetic-agent@0.1.0",
        os_arch="linux/x86_64",
    ).to_dict()
    healthy_row = _rows(healthy)[0]
    healthy_row.update(
        {
            "deployment_health": "healthy",
            "evidence_level": "live_block",
            "observed_at": "2026-09-22T00:00:00Z",
            "expires_at": "2026-09-30T00:00:00Z",
            "evidence_reference": "tests/fixtures/generic-live-block.json",
            "evidence_build": "test-build",
            "evidence_host_version_scope": "synthetic-agent@0.1.0",
            "evidence_os_arch": "linux/x86_64",
            "denied_witness_reference": "tests/fixtures/denied.json",
            "allowed_witness_reference": "tests/fixtures/allowed.json",
            "compatibility_verified": True,
        }
    )
    validate_capability_report(healthy, now=datetime(2026, 9, 23, tzinfo=timezone.utc))

    source_claim = deepcopy(healthy)
    source_row = _rows(source_claim)[0]
    source_row["deployment_health"] = "healthy"
    source_row["evidence_level"] = "source_review"
    source_row["compatibility_verified"] = False
    with pytest.raises(ValueError, match="healthy deployment requires live_block"):
        validate_capability_report(source_claim, now=datetime(2026, 9, 23, tzinfo=timezone.utc))


@pytest.mark.parametrize(
    "observed_at,expires_at,error",
    [
        ("not-a-time", "2026-09-30T00:00:00Z", "RFC3339"),
        ("2026-09-22T00:00:00", "2026-09-30T00:00:00Z", "timezone"),
        ("2026-09-22T00:00:00Z", "2026-09-22T00:00:00Z", "after observation"),
        ("2026-09-24T00:00:00Z", "2026-09-30T00:00:00Z", "in the future"),
    ],
)
def test_evidence_timestamps_must_be_parseable_zoned_and_ordered(observed_at: str, expires_at: str, error: str) -> None:
    payload = _report_payload()
    row = _rows(payload)[0]
    row.update(
        {
            "evidence_level": "synthetic_canary",
            "observed_at": observed_at,
            "expires_at": expires_at,
            "evidence_reference": "tests/fixtures/generic-canary.json",
        }
    )
    with pytest.raises(ValueError, match=error):
        validate_capability_report(payload, now=datetime(2026, 9, 23, tzinfo=timezone.utc))


def test_report_rejects_empty_build_identity_and_commit() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        build_capability_report(build_id=" ")
    with pytest.raises(ValueError, match="non-empty"):
        build_capability_report(commit=" ")


def test_checked_in_schema_accepts_generated_report() -> None:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "harness-capability-report.v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    assert schema == CAPABILITY_REPORT_SCHEMA
    Draft202012Validator(schema).validate(_report_payload())

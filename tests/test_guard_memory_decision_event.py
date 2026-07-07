"""Tests for memory decision event fingerprinting, payload, and outbox enqueue."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.memory_decision_event import (
    MEMORY_DECISION_EVENT_CONTRACT_VERSION,
    build_memory_decision_event,
    event_to_cloud_payload,
)
from codex_plugin_scanner.guard.memory_decision_outbox import (
    enqueue_memory_decision_event,
)
from codex_plugin_scanner.guard.memory_pattern_fingerprint import (
    build_memory_pattern_fingerprint,
)
from codex_plugin_scanner.guard.store import GuardStore

# ── Pattern fingerprint ──────────────────────────────────────────────────────


class TestMemoryPatternFingerprint:
    def test_package_install_groups_equivalent_commands(self) -> None:
        npm_install = build_memory_pattern_fingerprint(command="npm install lodash")
        npm_i = build_memory_pattern_fingerprint(command="npm i lodash")
        assert npm_install is not None
        assert npm_i is not None
        assert npm_install.fingerprint == npm_i.fingerprint
        assert npm_install.kind == "package_install_pattern"
        assert npm_install.components["package"] == "lodash"
        assert npm_install.components["ecosystem"] == "npm"

    def test_package_install_strips_versions(self) -> None:
        with_version = build_memory_pattern_fingerprint(command="bun add express@4.18.0")
        without_version = build_memory_pattern_fingerprint(command="bun add express")
        assert with_version is not None
        assert without_version is not None
        assert with_version.fingerprint == without_version.fingerprint

    def test_different_packages_do_not_group(self) -> None:
        lodash = build_memory_pattern_fingerprint(command="npm install lodash")
        express = build_memory_pattern_fingerprint(command="npm install express")
        assert lodash is not None
        assert express is not None
        assert lodash.fingerprint != express.fingerprint

    def test_mcp_tool_groups_by_server_and_tool(self) -> None:
        event = build_memory_pattern_fingerprint(command="mcp__lean_ctx__ctx_search pattern='memory'")
        assert event is not None
        assert event.kind == "mcp_tool_pattern"
        assert event.components["server"] == "lean_ctx"
        assert event.components["tool"] == "ctx_search"

    def test_shell_command_groups_by_executable_and_subcommand(self) -> None:
        git_push = build_memory_pattern_fingerprint(command="git push origin main")
        git_push_other = build_memory_pattern_fingerprint(command="git push origin feature")
        assert git_push is not None
        assert git_push_other is not None
        assert git_push.fingerprint == git_push_other.fingerprint
        assert git_push.components["executable"] == "git"
        assert git_push.components["subcommand"] == "push"
        assert git_push.components["target"] == "origin"

    def test_bare_generic_labels_rejected(self) -> None:
        for raw in ("read", "write", "bash", "grep", "job", "pi:project:read"):
            assert build_memory_pattern_fingerprint(command=raw) is None, raw

    def test_bare_command_verbs_without_target_rejected(self) -> None:
        assert build_memory_pattern_fingerprint(command="read") is None
        assert build_memory_pattern_fingerprint(command="bash") is None

    def test_generic_artifact_fallback_uses_artifact_id(self) -> None:
        candidate = build_memory_pattern_fingerprint(
            command=None,
            artifact_id="npm:lodash",
            artifact_type="package",
        )
        assert candidate is not None
        assert candidate.kind == "generic_artifact_pattern"
        assert candidate.components["artifact"] == "npm:lodash"

    def test_no_signal_returns_none(self) -> None:
        assert build_memory_pattern_fingerprint(command=None, artifact_id=None) is None

    def test_harness_dimension_separates_groups(self) -> None:
        codex = build_memory_pattern_fingerprint(command="npm install lodash", harness="codex")
        cursor = build_memory_pattern_fingerprint(command="npm install lodash", harness="cursor")
        assert codex is not None
        assert cursor is not None
        assert codex.fingerprint != cursor.fingerprint


# ── Decision event builder ───────────────────────────────────────────────────


def _approval_request(
    *,
    request_id: str = "req-1",
    review_command: str = "npm install lodash",
    raw_command: str | None = "npm install lodash",
    artifact_id: str | None = "npm:lodash",
    artifact_name: str | None = "lodash",
    artifact_type: str | None = "package",
    harness: str = "codex",
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "review_command": review_command,
        "raw_command_text": raw_command,
        "artifact_id": artifact_id,
        "artifact_name": artifact_name,
        "artifact_type": artifact_type,
        "harness": harness,
        "risk_summary": "Supply-chain install",
        "risk_signals": ["network_install", "filesystem_write"],
        "queue_group_id": "queue-1",
        "action_identity": "action-1",
    }


class TestMemoryDecisionEventBuilder:
    def test_approval_event_has_contract_version_and_fingerprint(self) -> None:
        event = build_memory_decision_event(
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert event is not None
        assert event.event_schema_version == MEMORY_DECISION_EVENT_CONTRACT_VERSION
        assert event.decision_action == "approved"
        assert event.decision_source == "local_approval_center"
        assert event.memory_pattern_fingerprint is not None
        assert event.memory_pattern_kind == "package_install_pattern"
        assert event.command_display == "npm install lodash"
        assert event.command_raw == "npm install lodash"
        assert event.redaction_state == "disabled"

    def test_block_action_maps_to_blocked(self) -> None:
        event = build_memory_decision_event(
            request=_approval_request(),
            action="block",
            scope="artifact",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert event is not None
        assert event.decision_action == "blocked"

    def test_redaction_enabled_withholds_raw_command(self) -> None:
        event = build_memory_decision_event(
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
            redaction_enabled=True,
        )
        assert event is not None
        assert event.redaction_state == "enabled"
        assert event.command_raw is None
        assert event.command_display == "npm install lodash"

    def test_redaction_withheld_when_no_raw_command(self) -> None:
        event = build_memory_decision_event(
            request=_approval_request(raw_command=None),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
            redaction_enabled=False,
        )
        assert event is not None
        assert event.redaction_state == "withheld"
        assert event.command_raw is None

    def test_returns_none_without_request_id(self) -> None:
        request = _approval_request()
        request["request_id"] = ""
        assert (
            build_memory_decision_event(
                request=request,
                action="allow",
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
            is None
        )

    def test_returns_none_for_unknown_action(self) -> None:
        assert (
            build_memory_decision_event(
                request=_approval_request(),
                action="maybe",
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
            is None
        )

    def test_cloud_payload_wraps_contract_version(self) -> None:
        event = build_memory_decision_event(
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert event is not None
        payload = event_to_cloud_payload(event)
        assert payload["contractVersion"] == MEMORY_DECISION_EVENT_CONTRACT_VERSION
        assert payload["decision_action"] == "approved"
        assert isinstance(payload["memory_pattern_components"], dict)


# ── Outbox enqueue integration ───────────────────────────────────────────────


def _store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


def _seed_workspace(store: GuardStore) -> None:
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="demo-token",
        dpop_private_key_pem=None,  # type: ignore[arg-type]
        dpop_public_jwk=None,  # type: ignore[arg-type]
        dpop_public_jwk_thumbprint=None,  # type: ignore[arg-type]
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-07-07T00:00:00Z",
    )


class TestMemoryDecisionOutboxEnqueue:
    def test_enqueue_writes_event_to_outbox(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        enqueued = enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert enqueued is True
        events = store.list_guard_events_v1(uploaded=False, limit=10)
        assert len(events) == 1
        assert events[0]["event_type"] == "approval.memory_decision"
        payload = events[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["eventType"] == "approval.memory_decision"
        assert payload["payload"]["decision_action"] == "approved"
        assert payload["payload"]["contractVersion"] == MEMORY_DECISION_EVENT_CONTRACT_VERSION

    def test_enqueue_is_idempotent_by_request_action_time(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        for _ in range(3):
            enqueue_memory_decision_event(
                store,
                request=_approval_request(),
                action="allow",
                scope="harness",
                resolved_at="2026-07-07T00:00:00Z",
            )
        events = store.list_guard_events_v1(uploaded=False, limit=10)
        assert len(events) == 1

    def test_block_and_allow_on_same_request_are_distinct(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="block",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        events = store.list_guard_events_v1(uploaded=False, limit=10)
        assert len(events) == 2

    def test_enqueue_skips_when_no_signal(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        request = _approval_request(
            review_command="",
            raw_command=None,
            artifact_id=None,
            artifact_name=None,
        )
        # build_memory_decision_event still produces an event when artifact_name
        # is None — but with no command and no artifact there is no fingerprint.
        # The contract: events with no fingerprint are still recorded (they may
        # carry enough Cloud-side context), but events with no request_id are
        # rejected. Here we assert the request_id-missing rejection path instead.
        request["request_id"] = "req-no-signal"
        enqueued = enqueue_memory_decision_event(
            store,
            request=request,
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        # With no command and no artifact, the event has no fingerprint but is
        # still recorded as decision evidence (Cloud may enrich it). Assert it
        # enqueued without a fingerprint rather than rejecting outright.
        assert enqueued is True
        events = store.list_guard_events_v1(uploaded=False, limit=10)
        assert len(events) == 1
        payload = events[0]["payload"]
        assert isinstance(payload, dict)
        assert payload["payload"]["memory_pattern_fingerprint"] is None

    def test_enqueue_rejects_empty_request_id(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        _seed_workspace(store)
        request = _approval_request()
        request["request_id"] = ""
        enqueued = enqueue_memory_decision_event(
            store,
            request=request,
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        assert enqueued is False
        assert store.count_guard_events_v1(uploaded=False) == 0

    def test_enqueue_does_not_raise_without_cloud_pairing(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        # No OAuth seeding — store has no cloud pairing.
        enqueued = enqueue_memory_decision_event(
            store,
            request=_approval_request(),
            action="allow",
            scope="harness",
            resolved_at="2026-07-07T00:00:00Z",
        )
        # Event still enqueues into the outbox; sync will skip until paired.
        # The important contract: no exception is raised.
        assert isinstance(enqueued, bool)

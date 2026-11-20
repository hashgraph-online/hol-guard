"""Always allow on a changed script's review allows the script's new version."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import approvals, native_policy_snapshot
from codex_plugin_scanner.guard.local_clis import local_cli_reallow as reallow
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import custom_extension_continuity
from codex_plugin_scanner.guard.runtime.extension_allow_hint import (
    CONNECTOR_SETUP_HINT_SCHEMA,
    connector_setup_deep_link,
    validated_connector_setup_hint,
)
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore

_HASH = "a" * 64
_OLD_HASH = "0" * 64
_CLI_ID = "local-cli.approve-merge-sh-0123abcd"
_GROUP = f"connector:{_HASH}:0123456789abcdef"
_STATES = {"root": "allow", "--dry-run": "allow", "--title": "allow", "other": "allow"}


def _hint(surface: str = "cli") -> dict[str, object] | None:
    return validated_connector_setup_hint(
        {
            "schema": CONNECTOR_SETUP_HINT_SCHEMA,
            "identity_hash": _HASH,
            "cli_id": _CLI_ID,
            "surface": surface,
            "display_name": "approve-merge.sh",
            "deep_link": connector_setup_deep_link(_CLI_ID),
            "card_recommendation": {"state": "allowed", "capabilities": []},
            "risk_classes": [],
        }
    )


def _queue(store: GuardStore, request_id: str, *, group_id: str = _GROUP, hint: object = None) -> None:
    store.add_approval_request(
        GuardApprovalRequest(
            request_id=request_id,
            harness="cursor",
            artifact_id="cursor:native-pretool:Shell",
            artifact_name="Shell",
            artifact_hash=f"binding-{request_id}",
            policy_action="review",
            recommended_scope="artifact",
            changed_fields=("native_pre_tool",),
            source_scope="project",
            config_path="/workspace",
            review_command=f"hol-guard approvals approve {request_id}",
            approval_url=f"http://127.0.0.1/requests/{request_id}",
            launch_target="./approve-merge.sh 12 --dry-run",
            queue_group_id=group_id,
            extension_allow_hint=_hint() if hint is None else hint,
        ),
        "2026-11-20T10:00:00+00:00",
    )


def _item(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "cli_id": _CLI_ID,
        "identity_hash": _HASH,
        "name": "approve-merge.sh",
        "kind": "script",
        "example_label": "approve-merge.sh",
        "state": "allowed",
        "stale": True,
        "surface": "cli",
    }
    item.update(overrides)
    return item


class _Writes:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.notified = 0
        self.bulk: list[list[str]] = []


@pytest.fixture
def writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[GuardStore, _Writes]:
    store = GuardStore(tmp_path / "guard")
    _queue(store, "req-1")
    _queue(store, "req-2", group_id=f"connector:{_HASH}:1111111111111111")
    seen = _Writes()

    def record(_store: object, **kwargs: object) -> int:
        seen.calls.append(kwargs)
        return 8

    def notify(_home: object) -> None:
        seen.notified += 1

    def bulk(**kwargs: object) -> dict[str, object]:
        ids = list(kwargs["request_ids"])  # type: ignore[call-overload]
        seen.bulk.append(ids)
        return {"resolved_count": len(ids), "failed": []}

    monkeypatch.setattr(custom_extension_continuity, "record_local_custom_extension_mutation", record)
    monkeypatch.setattr(native_policy_snapshot, "notify_native_policy_mutation", notify)
    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", bulk)
    monkeypatch.setattr(reallow, "listed_public_items", lambda _store: [_item()])
    monkeypatch.setattr(store, "read_local_cli_command_states", lambda _cli_id: dict(_STATES))
    monkeypatch.setattr(store, "read_local_cli_revision", lambda: 7)
    return store, seen


def test_always_allow_moves_the_allow_to_the_new_version_keeping_command_choices(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, seen = writes

    result = reallow.reallow_changed_cli(
        store, request_id="req-1", approval_gate_input=None, now="2026-11-20T10:01:00Z"
    )

    assert result == {
        "status": "allowed",
        "cli_id": _CLI_ID,
        "identity_hash": _HASH,
        "revision": 8,
        "held_allowed_once": 0,
    }
    # The grant update returns before any sibling is resolved. The outer
    # approval wrapper resolves siblings after releasing its origin stripe.
    assert seen.bulk == []
    monkeypatch.setattr(store, "read_local_cli_revision", lambda: 8)
    reallow.finalize_reallow_siblings(
        store,
        request_id="req-1",
        changed_cli=result,
        approval_gate_input=None,
        now="2026-11-20T10:01:00Z",
    )
    assert result["held_allowed_once"] == 1
    (call,) = seen.calls
    identity = call["identity"]
    assert identity.cli_id == _CLI_ID  # type: ignore[attr-defined]
    assert identity.identity_hash == _HASH  # type: ignore[attr-defined]
    assert identity.kind == "script"  # type: ignore[attr-defined]
    assert call["state"] == "allowed"
    assert call["expected_revision"] == 7
    # The writer replaces the choices it is given: the stored ones go back unchanged.
    assert call["command_states"] == _STATES
    assert seen.notified == 2
    # The other call held on this version is allowed once; the decided row is not re-sent.
    assert seen.bulk == [["req-2"]]


@pytest.mark.parametrize(
    "item",
    [
        _item(stale=False),  # Already the allowed version.
        _item(state="blocked"),  # A block stays a decision.
        _item(state="unset", stale=False),  # Never set up: the Protect page sets it up.
        _item(identity_hash=_OLD_HASH),  # The stored version is not the one this review names.
        _item(surface="package-scripts"),
    ],
)
def test_only_a_cli_allowed_for_an_earlier_version_moves(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch, item: dict[str, object]
) -> None:
    store, seen = writes
    monkeypatch.setattr(reallow, "listed_public_items", lambda _store: [item])

    assert reallow.reallow_changed_cli(store, request_id="req-1", approval_gate_input=None, now="t") is None
    assert seen.calls == [] and seen.bulk == []


def test_a_review_that_names_no_changed_script_moves_nothing(writes: tuple[GuardStore, _Writes]) -> None:
    store, seen = writes
    _queue(store, "req-plain", group_id="approval-group:v1:abc", hint={"schema": "guard.extension-allow-hint.v1"})
    # The group id alone is not enough: the row must carry the connector hint.
    _queue(store, "req-no-hint", hint={"schema": "guard.extension-allow-hint.v1"})
    _queue(store, "req-mcp", hint=_hint(surface="mcp"))

    for request_id in ("req-plain", "req-no-hint", "req-mcp", "req-missing"):
        assert reallow.reallow_changed_cli(store, request_id=request_id, approval_gate_input=None, now="t") is None
    assert seen.calls == []



def test_a_concurrent_block_cannot_be_reallowed_from_its_newer_revision(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, seen = writes
    revision = [7]
    monkeypatch.setattr(store, "read_local_cli_revision", lambda: revision[0])

    def snapshot_during_block(_cli_id: str) -> dict[str, str]:
        # Another request blocks the CLI after this request's eligibility read.
        # The write must not use the revision produced by that newer decision.
        revision[0] += 1
        return dict(_STATES)

    monkeypatch.setattr(store, "read_local_cli_command_states", snapshot_during_block)

    def compare_and_write(_store: object, **kwargs: object) -> int:
        seen.calls.append(kwargs)
        if kwargs["expected_revision"] != revision[0]:
            raise ValueError("local_cli_revision_conflict")
        return 9

    monkeypatch.setattr(custom_extension_continuity, "record_local_custom_extension_mutation", compare_and_write)

    result = reallow.reallow_changed_cli(store, request_id="req-1", approval_gate_input=None, now="t")

    assert result == {"status": "failed", "error": "ValueError"}
    assert seen.calls[0]["expected_revision"] == 7
    assert seen.bulk == []


def test_sibling_approval_runs_after_the_origin_stripe_is_released(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch
) -> None:
    import hashlib
    import threading

    store, seen = writes
    request_id = "req-1"
    digest = hashlib.sha256(request_id.encode("utf-8")).digest()
    stripe = approvals._APPROVAL_RESOLUTION_LOCKS[
        int.from_bytes(digest[:2], "big") % len(approvals._APPROVAL_RESOLUTION_LOCKS)
    ]

    def bulk_after_release(**kwargs: object) -> dict[str, object]:
        acquired: list[bool] = []

        def check_from_another_thread() -> None:
            did_acquire = stripe.acquire(timeout=0.3)
            acquired.append(did_acquire)
            if did_acquire:
                stripe.release()

        t = threading.Thread(target=check_from_another_thread)
        t.start()
        t.join(timeout=2)
        assert acquired == [True], "Sibling resolution ran while the origin stripe was held"
        seen.bulk.append(list(kwargs["request_ids"]))  # type: ignore[arg-type]
        return {"resolved_count": 1, "failed": []}

    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", bulk_after_release)
    monkeypatch.setattr(store, "read_local_cli_revision", lambda: 8)

    @approvals._serialize_approval_resolution
    def mock_origin(*, store: GuardStore, request_id: str, now: str) -> dict[str, object]:
        # The production inner function writes the grant under the lock before
        # resolving the origin. This stub exercises only stripe sequencing.
        return {
            "changed_cli": {
                "status": "allowed",
                "cli_id": _CLI_ID,
                "identity_hash": _HASH,
                "revision": 8,
                "held_allowed_once": 0,
            }
        }

    result = mock_origin(store=store, request_id=request_id, now="2026-11-20T10:01:00Z")
    assert result["changed_cli"]["held_allowed_once"] == 1  # type: ignore[index]
    assert seen.bulk == [["req-2"]]


def test_changed_revision_skips_deferred_siblings(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, seen = writes
    changed_cli: dict[str, object] = {
        "status": "allowed",
        "cli_id": _CLI_ID,
        "identity_hash": _HASH,
        "revision": 8,
        "held_allowed_once": 0,
    }
    monkeypatch.setattr(store, "read_local_cli_revision", lambda: 9)
    reallow.finalize_reallow_siblings(
        store,
        request_id="req-1",
        changed_cli=changed_cli,
        approval_gate_input=None,
        now="2026-11-20T10:01:00Z",
    )
    assert changed_cli["held_allowed_once"] == 0
    assert changed_cli["siblings_skipped"] == "local_cli_revision_changed"
    assert seen.bulk == []


def test_a_failed_write_reports_without_raising(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, seen = writes

    def conflict(_store: object, **_kwargs: object) -> int:
        raise ValueError("local_cli_revision_conflict")

    monkeypatch.setattr(custom_extension_continuity, "record_local_custom_extension_mutation", conflict)

    result = reallow.reallow_changed_cli(store, request_id="req-1", approval_gate_input=None, now="t")

    assert result == {"status": "failed", "error": "ValueError"}
    # The mutation fence is lifted again even when the write fails.
    assert seen.notified == 2
    assert seen.bulk == []


def test_held_calls_that_cannot_be_allowed_leave_the_new_version_allowed(
    writes: tuple[GuardStore, _Writes], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _seen = writes

    def gate_required(**_kwargs: object) -> dict[str, object]:
        raise ValueError("bulk_approve_gate_required")

    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", gate_required)

    result = reallow.reallow_changed_cli(store, request_id="req-1", approval_gate_input=None, now="t")

    assert result is not None and result["status"] == "allowed"
    assert result["held_allowed_once"] == 0
    monkeypatch.setattr(store, "read_local_cli_revision", lambda: 8)
    reallow.finalize_reallow_siblings(
        store, request_id="req-1", changed_cli=result, approval_gate_input=None, now="t"
    )
    assert result["held_allowed_once"] == 0


def test_a_real_store_moves_the_allow_and_keeps_the_choices(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "guard")
    old = UnlistedCliIdentity(
        cli_id=_CLI_ID,
        name="approve-merge.sh",
        kind="script",
        identity_hash=_OLD_HASH,
        example_label="approve-merge.sh",
    )
    choices = {"--dry-run": "allow", "--title": "allow"}
    store.record_local_cli_observation(old, seen_at="2026-11-20T09:00:00Z", surface="cli")
    store.replace_local_cli_commands(
        _CLI_ID, tuple(LocalCliCommand(command, command, command, f"{command} safely") for command in choices)
    )
    custom_extension_continuity.record_local_custom_extension_mutation(
        store,
        identity=old,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        command_states=choices,
        now="2026-11-20T09:00:00Z",
    )
    # The script is edited: Guard now sees a new version of the same file.
    store.record_local_cli_observation(
        UnlistedCliIdentity(
            cli_id=_CLI_ID,
            name="approve-merge.sh",
            kind="script",
            identity_hash=_HASH,
            example_label="approve-merge.sh",
        ),
        seen_at="2026-11-20T09:30:00Z",
        surface="cli",
    )
    _queue(store, "req-1")
    monkeypatch.setattr(approvals, "bulk_allow_read_only_once", lambda **_kwargs: {"resolved_count": 0})
    (before,) = [item for item in reallow.listed_public_items(store) if item["cli_id"] == _CLI_ID]
    assert before["state"] == "allowed" and before["stale"] is True

    result = reallow.reallow_changed_cli(
        store, request_id="req-1", approval_gate_input=None, now="2026-11-20T10:01:00Z"
    )

    assert result is not None and result["status"] == "allowed", result
    (after,) = [item for item in reallow.listed_public_items(store) if item["cli_id"] == _CLI_ID]
    assert after["state"] == "allowed" and after["identity_hash"] == _HASH and after.get("stale") is not True
    assert store.read_local_cli_command_states(_CLI_ID) == choices

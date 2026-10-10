"""Native MCP grant client: failure reasons and the unavailable-resident hold."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_cli_trust, local_mcp_grant_decision
from codex_plugin_scanner.guard import native_local_mcp_grant as client
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256
from codex_plugin_scanner.guard.native_local_cli_identity import LocalCliIdentityUnavailableError
from codex_plugin_scanner.guard.native_local_mcp_grant import NativeLocalMcpGrant, NativeLocalMcpGrantFailure
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401
from .test_guard_local_mcp_grants import _artifact, _enroll, _identity


def _reply(monkeypatch: pytest.MonkeyPatch, status: str, code: object, *, prerequisite: bool = True) -> list[str]:
    calls: list[str] = []

    def resident(*, operation: str, request: dict[str, object], **_kwargs: object) -> dict[str, object]:
        calls.append(operation)
        return {
            "schema": "guard-local-mcp-grant-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": status,
            "code": code,
            "payload": None,
        }

    monkeypatch.setattr(client, "_resident_request", resident)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _home: prerequisite)
    return calls


def _ask(tmp_path: Path) -> NativeLocalMcpGrant | NativeLocalMcpGrantFailure:
    return client.native_local_mcp_grant(
        store_path=tmp_path / "guard.db",
        guard_home=tmp_path,
        current_action="allow",
        harness="codex",
        tool_name="read_file",
        server={},
        connection_identity_hash=None,
        tool_authority_hash=None,
        launcher_path=None,
        launcher_home=None,
    )


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("native_local_mcp_grant_schema_outdated", "native_local_mcp_grant_schema_outdated"),
        ("native_local_mcp_grant_store_unavailable", "native_local_mcp_grant_store_unavailable"),
        ("free text from a reply", "native_local_mcp_grant_unavailable"),
        (None, "native_local_mcp_grant_unavailable"),
    ],
)
def test_resident_refusal_reason_reaches_the_caller(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, code: object, expected: str
) -> None:
    _reply(monkeypatch, "error", code)
    assert _ask(tmp_path) == NativeLocalMcpGrantFailure(expected)


def test_lookup_establishes_the_resident_prerequisite(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _reply(monkeypatch, "ok", "ok", prerequisite=False)
    assert _ask(tmp_path) == NativeLocalMcpGrantFailure("native_local_mcp_grant_prerequisite_unavailable")
    assert calls == []


def test_failure_code_is_raised_and_logged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    failure = NativeLocalMcpGrantFailure("native_local_mcp_grant_schema_outdated")
    monkeypatch.setattr(local_mcp_grant_decision, "native_local_mcp_grant", lambda **_kwargs: failure)

    with (
        caplog.at_level(logging.WARNING, logger=local_mcp_grant_decision.__name__),
        pytest.raises(LocalCliIdentityUnavailableError, match="native_local_mcp_grant_schema_outdated"),
    ):
        local_mcp_grant_decision.decide_local_mcp_grant(
            store=store, artifact=_artifact(identity, "read_file"), current_action="allow"
        )
    assert "native_local_mcp_grant_schema_outdated" in caplog.text


def _resident_unavailable(**_kwargs: object) -> None:
    raise LocalCliIdentityUnavailableError("native_local_mcp_grant_unavailable")


def test_unavailable_resident_holds_review_only_grants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    # No block rule exists; the per-tool review state is the only protection.
    _enroll(store, identity, states={"read_file": "review", "write_file": "inherit"})
    monkeypatch.setattr(local_cli_trust, "decide_local_mcp_grant", _resident_unavailable)

    decision = local_cli_trust.apply_local_mcp_extension_decision(store, _artifact(identity, "read_file"), "allow")

    assert decision is not None
    assert decision[0] == "review"


def test_unavailable_resident_holds_a_review_so_approvals_cannot_override_a_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    _enroll(store, identity, states={"read_file": "allow"}, grant_state="blocked")
    monkeypatch.setattr(local_cli_trust, "decide_local_mcp_grant", _resident_unavailable)

    decision = local_cli_trust.apply_local_mcp_extension_decision(store, _artifact(identity, "read_file"), "review")

    # A decisive review keeps temporary approval grants from upgrading it to allow.
    assert decision is not None
    assert decision[:2] == ("review", "local-mcp-extension")


def test_unavailable_resident_without_grants_keeps_baseline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _identity()
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(local_cli_trust, "decide_local_mcp_grant", _resident_unavailable)

    assert local_cli_trust.apply_local_mcp_extension_decision(store, _artifact(identity, "read_file"), "allow") is None
    assert local_cli_trust.apply_local_mcp_extension_decision(store, _artifact(identity, "read_file"), "review") is None


@pytest.mark.parametrize("state", [[], {}, 1, None, "maybe"])
def test_malformed_state_is_an_invalid_payload_not_a_crash(state: object) -> None:
    payload = {"state": state, "cli_id": None, "identity_hash": None}

    assert client._decode_payload(payload) is None


def test_relative_path_entries_are_anchored_to_the_callers_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    absolute = str(tmp_path / "abs")
    joined = os.pathsep.join(["node_modules/.bin", absolute, ""])

    anchored = local_mcp_grant_decision._caller_launcher_path(joined)

    assert anchored == os.pathsep.join([os.path.join(os.getcwd(), "node_modules/.bin"), absolute, ""])
    assert local_mcp_grant_decision._caller_launcher_path(None) is None


def test_unreadable_working_directory_fails_closed_only_when_a_relative_entry_needs_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deleted_cwd() -> str:
        raise FileNotFoundError("cwd removed")

    monkeypatch.setattr(os, "getcwd", deleted_cwd)
    absolute = str(tmp_path / "abs")

    assert local_mcp_grant_decision._caller_launcher_path(absolute) == absolute
    with pytest.raises(LocalCliIdentityUnavailableError):
        local_mcp_grant_decision._caller_launcher_path(os.pathsep.join(["node_modules/.bin", absolute]))

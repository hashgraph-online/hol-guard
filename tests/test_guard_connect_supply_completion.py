"""Real first-sync subwriters must not commit after their connection changes."""

from __future__ import annotations

import io
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_supply_chain
from codex_plugin_scanner.guard.cli import connect_flow
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_connect_completion_authority import credential_args
from tests.test_guard_supply_chain_bundle import _bundle_dict, _generate_key_pair, _sign_bundle_response


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args, **_kwargs):
        raise AssertionError("First-sync authority tests must not open a network socket")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)


def connection(tmp_path: Path):
    store = GuardStore(tmp_path / "guard-home", allow_system_keyring=False)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    key = generate_dpop_key_pair()
    args = credential_args(key, "workspace-alpha")
    committed = store.set_oauth_local_credentials(**args, expected_attempt=store.begin_oauth_connect_attempt())
    assert committed is not None
    context = connect_flow._build_sync_auth_context(
        access_token="synthetic-access", dpop_key_material=key, sync_url="https://hol.org/api/guard/receipts/sync"
    )
    return store, peer, key, args, committed, context


def change_connection(peer, key, args, change: str) -> None:
    if change == "disconnect":
        peer.clear_oauth_local_credentials()
    elif change == "identical":
        peer.set_oauth_local_credentials(**args)
    else:
        peer.set_oauth_local_credentials(**credential_args(key, "newer-team"))


@pytest.mark.parametrize("phase", ["index", "partition", "bundle", "verified"])
@pytest.mark.parametrize("change", ["replacement", "disconnect", "identical"])
def test_signed_bundle_response_cannot_replace_newer_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, change: str
) -> None:
    exercise_bundle(tmp_path, monkeypatch, phase=phase, change=change)


def test_current_signed_bundle_still_commits_its_verified_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exercise_bundle(tmp_path, monkeypatch, phase="unchanged", change="unchanged")


def exercise_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, phase: str, change: str) -> None:
    store, peer, key, args, committed, context = connection(tmp_path)
    private, _ = _generate_key_pair()
    signed = _sign_bundle_response(_bundle_dict(generated_at=datetime.now(timezone.utc)), private_key_pem=private)
    store.set_sync_payload(
        "supply_chain_bundle_keyring",
        {
            "workspace_id": "workspace-alpha",
            "keys": signed["verificationKeys"],
        },
        args["now"],
    )
    states = (
        "supply_chain_bundle_summary",
        "supply_chain_bundle_entitlement",
        "supply_chain_bundle_keyring",
        "supply_chain_bundle_partition_cache",
    )
    marker = {"source": "newer-decision", "workspace_id": "newer-team"}
    calls = []

    def replace():
        change_connection(peer, key, args, change)
        for state in states:
            peer.set_sync_payload(state, marker, args["now"])

    verify = runner.verify_supply_chain_bundle_response

    def verify_then_change(*verify_args, **verify_kwargs):
        result = verify(*verify_args, **verify_kwargs)
        replace()
        return result

    if phase == "verified":
        monkeypatch.setattr(runner, "verify_supply_chain_bundle_response", verify_then_change)

    def reply(request, **_kwargs):
        calls.append(request.full_url)
        assert len(calls) <= 2, "Changed authority must not trigger another request"
        point = "index" if len(calls) == 1 else "partition" if phase == "partition" else "bundle"
        if point == phase:
            replace()
        payload = signed
        if point == "index":
            payload = (
                {
                    "partitions": [{"ecosystem": "npm", "partition": 0, "payloadHash": signed["payloadHash"]}],
                    "bundleVersion": "1747612800000-deadbeef",
                }
                if phase == "partition"
                else {}
            )
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr(runner, "managed_urlopen", reply)
    with hold_sync_auth_handoff(store, context, committed):
        if phase == "unchanged":
            result = runner.sync_supply_chain_bundle(store, auth_context=context)
            assert result["workspace_id"] == "workspace-alpha"
            assert peer.get_sync_payload("supply_chain_bundle_summary") == result
            assert peer.get_cached_supply_chain_bundle("workspace-alpha") is not None
            assert peer.capture_oauth_connection(allow_primary=True) == committed
        else:
            with pytest.raises(RuntimeError, match="connection changed"):
                runner.sync_supply_chain_bundle(store, auth_context=context)
            assert all(peer.get_sync_payload(state) == marker for state in states)
            assert peer.get_cached_supply_chain_bundle("workspace-alpha") is None
    assert len(calls) == (1 if phase == "index" else 2)


@pytest.mark.parametrize("phase", ["enqueue", "poll", "next-poll"])
@pytest.mark.parametrize("change", ["replacement", "disconnect"])
def test_managed_audit_refuses_stale_response_without_summary_or_followup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, change: str
) -> None:
    exercise_audit(tmp_path, monkeypatch, phase=phase, change=change)


def test_current_managed_audit_still_commits_completed_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exercise_audit(tmp_path, monkeypatch, phase="unchanged", change="unchanged")


def exercise_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, phase: str, change: str) -> None:
    store, peer, key, args, committed, context = connection(tmp_path)
    workspace = tmp_path / "synthetic-workspace"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name":"synthetic","dependencies":{"react":"18.2.0"}}')
    store.set_managed_install("codex", True, str(workspace), {}, args["now"])
    marker = {"source": "newer-decision"}
    calls = []

    def replace():
        change_connection(peer, key, args, change)
        peer.set_sync_payload("workspace_audits_sync_summary", marker, args["now"])

    def reply(request, **_kwargs):
        calls.append(request.get_method())
        assert len(calls) <= 2, "Changed authority must not trigger another request"
        if (phase == "enqueue" and len(calls) == 1) or (phase == "poll" and len(calls) == 2):
            replace()
        payload = {
            "jobId": "synthetic-job",
            "status": "queued" if len(calls) == 1 or phase == "next-poll" else "completed",
        }
        return io.BytesIO(json.dumps(payload).encode())

    def wait(_delay):
        assert phase == "next-poll"
        replace()

    monkeypatch.setattr(local_supply_chain, "managed_urlopen", reply)
    monkeypatch.setattr(local_supply_chain.time, "sleep", wait)
    with hold_sync_auth_handoff(store, context, committed):
        if phase == "unchanged":
            result = local_supply_chain.sync_managed_workspace_audits(
                store, auth_context=context, workspace_dir=workspace
            )
            assert result["status"] == "synced"
            assert result["completed_jobs"] == 1
            assert peer.get_sync_payload("workspace_audits_sync_summary") == result
        else:
            with pytest.raises(RuntimeError, match="connection changed"):
                local_supply_chain.sync_managed_workspace_audits(store, auth_context=context, workspace_dir=workspace)
            assert peer.get_sync_payload("workspace_audits_sync_summary") == marker
    assert calls == (["POST"] if phase == "enqueue" else ["POST", "GET"])


def test_empty_audit_cannot_commit_over_replacement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, peer, key, args, committed, context = connection(tmp_path)
    marker = {"source": "newer-decision"}

    def candidates(*_args, **_kwargs):
        change_connection(peer, key, args, "replacement")
        peer.set_sync_payload("workspace_audits_sync_summary", marker, args["now"])
        return []

    monkeypatch.setattr(local_supply_chain, "_managed_workspace_audit_candidates", candidates)
    with hold_sync_auth_handoff(store, context, committed), pytest.raises(RuntimeError, match="connection changed"):
        local_supply_chain.sync_managed_workspace_audits(store, auth_context=context)
    assert peer.get_sync_payload("workspace_audits_sync_summary") == marker

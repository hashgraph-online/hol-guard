"""Initial authorization must not replace a newer local connection decision."""

from __future__ import annotations

import socket
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import TypedDict
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.cli import connect_flow
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial, generate_dpop_key_pair
from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.oauth_connection_authority import connection_epoch_key
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture(autouse=True)
def prohibit_network_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args, **_kwargs):
        raise AssertionError("Connection-authority tests must not open any network socket")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)


class CredentialArgs(TypedDict):
    issuer: str
    client_id: str
    refresh_token: str
    dpop_private_key_pem: str
    dpop_public_jwk: dict[str, str]
    dpop_public_jwk_thumbprint: str
    workspace_id: str
    grant_id: str
    machine_id: str
    now: str


def required_credentials(store: GuardStore) -> dict[str, object]:
    value = store.get_oauth_local_credentials(allow_primary=True)
    assert value is not None
    return value


def credential_args(key: GuardDpopKeyMaterial, workspace: str = "newer-team") -> CredentialArgs:
    return CredentialArgs(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        workspace_id=workspace,
        grant_id="synthetic-grant",
        machine_id="synthetic-machine",
        now="2026-09-19T00:00:00+00:00",
    )


def token_result():
    return connect_flow.GuardOAuthTokenExchangeResult(
        access_token="synthetic-access",
        refresh_token="synthetic-authorized-refresh",
        expires_in=3600,
        scope="guard:runtime.sync guard:offline_access",
        token_type="DPoP",
        grant_id="synthetic-authorized-grant",
        machine_id="synthetic-machine",
        workspace_id="authorized-team",
        supply_chain_entitlement=None,
    )


@pytest.mark.parametrize("surface", ["cli-browser", "cli-device", "daemon-browser"])
@pytest.mark.parametrize("phase", ["callback", "provider"])
@pytest.mark.parametrize("change", ["unchanged", "disconnect", "replacement", "new-attempt", "pending-reset"])
def test_initial_connect_rechecks_authority_before_persisting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    phase: str,
    change: str,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    other = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    finalized = Mock(side_effect=lambda **kwargs: kwargs["payload"])
    monkeypatch.setattr(server, "_finalize_daemon_guard_connect_payload", finalized)
    monkeypatch.setattr(connect_flow, "prepare_guard_cloud_connect_authorization", lambda _store: {})

    def mutate():
        if change == "disconnect":
            # This is the actual CLI disconnect when enrollment has not stored credentials.
            assert (
                connect_flow.run_guard_disconnect_command(store=other, revoke_cloud_grant=False)["status"]
                == "not_connected"
            )
        elif change == "replacement":
            other.set_oauth_local_credentials(**credential_args(key))
        elif change == "new-attempt":
            other.begin_oauth_connect_attempt()
        elif change == "pending-reset":
            other.set_sync_payload(
                connection_epoch_key("oauth_local_credentials"), {"epoch": "a" * 32, "reset": "b" * 32}, "now"
            )

    def callback(_timeout):
        if phase == "callback":
            mutate()
        return SimpleNamespace(code="synthetic-code", state="synthetic-state")

    session = SimpleNamespace(
        wait_for_callback=callback,
        close=Mock(),
        redirect_uri="http://127.0.0.1:61234/oauth/callback",
        pkce_verifier="synthetic-verifier",
        dpop_key_material=key,
        authorize_url="https://hol.org/guard/connect",
    )

    def exchange(**_kwargs):
        if phase == "provider":
            mutate()
        return token_result()

    def request_authorization(*_args):
        if phase == "callback":
            mutate()
        return {
            "device_code": "synthetic-code",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://hol.org/guard/connect",
            "expires_in": 180,
            "interval": 1,
        }

    def invoke():
        if surface == "cli-browser":
            return connect_flow.run_guard_browser_connect_command(
                store=store,
                connect_url="https://hol.org/guard/connect",
                start_browser_session=lambda **_: session,
                open_browser=lambda _: True,
                exchange_authorization_code=exchange,
            )
        if surface == "cli-device":
            monkeypatch.setattr(connect_flow, "exchange_guard_device_code", exchange)
            return connect_flow.run_guard_device_connect_command(
                store=store,
                connect_url="https://hol.org/guard/connect",
                request_device_authorization=request_authorization,
            )
        attempt = store.begin_oauth_connect_attempt()
        monkeypatch.setattr(server, "exchange_guard_authorization_code", exchange)
        return server._complete_browser_oauth_connect(
            store=store,
            session=session,
            connect_url="https://hol.org/guard/connect",
            browser_opened=True,
            attempt=attempt,
            managed_controls_publish=None,
        )

    if change == "unchanged":
        assert invoke()["status"] == "connected"
        assert required_credentials(other)["workspace_id"] == "authorized-team"
        assert finalized.call_count == (1 if surface == "daemon-browser" else 0)
    else:
        with pytest.raises(RuntimeError, match="connection changed during authorization"):
            invoke()
        current = other.get_oauth_local_credentials(allow_primary=True)
        assert (current["workspace_id"] if current else None) == ("newer-team" if change == "replacement" else None)
        if current:
            assert current["refresh_token"] == "synthetic-refresh"
        finalized.assert_not_called()
    if surface == "cli-browser":
        session.close.assert_called_once()


def test_attempt_is_one_use_and_does_not_write_secrets_on_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    attempt = store.begin_oauth_connect_attempt()
    store.set_oauth_local_credentials(**credential_args(key), expected_attempt=attempt)
    snapshot = store.capture_oauth_connection(allow_primary=True)
    write = Mock(side_effect=AssertionError("A rejected attempt must not touch the secret store"))
    monkeypatch.setattr(store._oauth_secret_store, "set_secret", write)
    with pytest.raises(RuntimeError, match="connection changed during authorization"):
        store.set_oauth_local_credentials(**credential_args(key, "stale-team"), expected_attempt=attempt)
    write.assert_not_called()
    assert store.capture_oauth_connection(allow_primary=True) == snapshot


@pytest.mark.parametrize("other_scope", ["store", "source"])
def test_attempt_cannot_cross_guard_home_or_named_source(tmp_path: Path, other_scope: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    other = GuardStore(
        tmp_path / ("another-home" if other_scope == "store" else "guard-home"),
        source="other" if other_scope == "source" else "default",
    )
    attempt = store.begin_oauth_connect_attempt()
    with pytest.raises(RuntimeError, match="different connection"):
        other.set_oauth_local_credentials(**credential_args(generate_dpop_key_pair()), expected_attempt=attempt)
    assert other.get_oauth_local_credentials(allow_primary=True) is None


@pytest.mark.parametrize("authority", [{"epoch": "a" * 32, "reset": "b" * 32}, {"epoch": "invalid"}])
def test_begin_cannot_reopen_pending_or_corrupt_reset(tmp_path: Path, authority: dict[str, str]) -> None:
    store = GuardStore(tmp_path / "guard-home")
    key = connection_epoch_key("oauth_local_credentials")
    store.set_sync_payload(key, authority, "now")
    with pytest.raises(RuntimeError, match="requires recovery"):
        store.begin_oauth_connect_attempt()
    assert store.get_sync_payload(key) == authority


@pytest.mark.parametrize("surface", ["cli-browser", "cli-device", "daemon-browser"])
@pytest.mark.parametrize("change", ["unchanged", "disconnect", "replacement", "new-attempt"])
def test_committed_authorization_cannot_finalize_over_newer_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, surface: str, change: str
) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_connect

    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    marker = {"cursor": 47, "source": "newer-local-decision"}
    captured = {}
    persist_module = server if surface == "daemon-browser" else connect_flow
    persist = persist_module._persist_oauth_local_credentials

    def persist_then_change(**kwargs):
        committed = persist(**kwargs)
        assert required_credentials(peer)["workspace_id"] == "authorized-team"
        if change == "replacement":
            peer.set_oauth_local_credentials(**credential_args(key))
        elif change == "disconnect":
            peer.clear_oauth_local_credentials()
        elif change == "new-attempt":
            peer.begin_oauth_connect_attempt()
        peer.set_sync_payload("receipt_sync_cursor", marker, "now")
        captured["epoch"] = peer.get_sync_payload(connection_epoch_key("oauth_local_credentials"))
        captured["pairing"] = peer.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00")
        return committed

    monkeypatch.setattr(persist_module, "_persist_oauth_local_credentials", persist_then_change)
    monkeypatch.setattr(connect_flow, "prepare_guard_cloud_connect_authorization", lambda _: {})
    monkeypatch.setattr(connect_flow, "exchange_guard_device_code", lambda **_: token_result())
    monkeypatch.setattr(server, "exchange_guard_authorization_code", lambda **_: token_result())
    # Skip external first sync only; the actual finalizer, reset, pairing and credential writes execute.
    monkeypatch.setattr(store, "get_cloud_sync_profile", lambda: None)
    session = SimpleNamespace(
        wait_for_callback=lambda _: SimpleNamespace(code="synthetic-code", state="synthetic-state"),
        close=Mock(),
        redirect_uri="http://127.0.0.1:61234/oauth/callback",
        pkce_verifier="synthetic-verifier",
        dpop_key_material=key,
        authorize_url="https://hol.org/guard/connect",
    )

    def invoke():
        if surface == "daemon-browser":
            return server._complete_browser_oauth_connect(
                store=store,
                session=session,
                connect_url="https://hol.org/guard/connect",
                browser_opened=True,
                attempt=store.begin_oauth_connect_attempt(),
                managed_controls_publish=None,
            )
        if surface == "cli-browser":
            payload = connect_flow.run_guard_browser_connect_command(
                store=store,
                connect_url="https://hol.org/guard/connect",
                start_browser_session=lambda **_: session,
                open_browser=lambda _: True,
                exchange_authorization_code=lambda **_: token_result(),
                include_sync_auth_context=True,
            )
        else:
            payload = connect_flow.run_guard_device_connect_command(
                store=store,
                connect_url="https://hol.org/guard/connect",
                request_device_authorization=lambda *_: {
                    "device_code": "synthetic-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://hol.org/guard/connect",
                    "expires_in": 180,
                    "interval": 1,
                },
                include_sync_auth_context=True,
            )
        return commands_support_connect._finalize_guard_connect_payload(
            store=store, connect_url="https://hol.org/guard/connect", payload=payload, now="2026-09-19T00:00:00+00:00"
        )

    if change == "unchanged":
        result = invoke()
        assert result["status"] == "connected"
        assert result["milestone"] == "first_sync_pending"
        assert not any(key.startswith("_guard_") for key in result)
        assert peer.get_sync_payload("receipt_sync_cursor") is None
        assert peer.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00") != captured["pairing"]
    else:
        with pytest.raises(RuntimeError, match="connection changed during authorization"):
            invoke()
        assert peer.get_sync_payload("receipt_sync_cursor") == marker
        assert peer.get_sync_payload(connection_epoch_key("oauth_local_credentials")) == captured["epoch"]
        assert peer.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00") == captured["pairing"]
        current = peer.get_oauth_local_credentials(allow_primary=True)
        assert (current["workspace_id"] if current else None) == {
            "replacement": "newer-team",
            "disconnect": None,
            "new-attempt": "authorized-team",
        }[change]


@pytest.mark.parametrize("surface", ["cli", "daemon"])
@pytest.mark.parametrize("outcome", ["success", "failure"])
def test_first_sync_result_cannot_update_replacement_pairing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, surface: str, outcome: str
) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_connect
    from codex_plugin_scanner.guard.cli.connect_completion import CONNECT_CONNECTION_KEY
    from codex_plugin_scanner.guard.runtime.sync_auth_handoff import selected_sync_auth_handoff

    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    committed = store.set_oauth_local_credentials(
        **credential_args(key, "authorized-team"), expected_attempt=store.begin_oauth_connect_attempt()
    )
    context = connect_flow._build_sync_auth_context(
        access_token="synthetic-access", dpop_key_material=key, sync_url="https://hol.org/api/guard/receipts/sync"
    )
    captured = {}

    def sync(_store, auth_context=None, **_kwargs):
        bound = selected_sync_auth_handoff(store, auth_context)
        assert bound is not None and bound.credentials()["workspace_id"] == "authorized-team"
        peer.set_oauth_local_credentials(**credential_args(key))
        peer.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-09-19T00:00:01+00:00",
            request_id="newer-pairing",
        )
        captured["pairing"] = peer.get_latest_guard_connect_state(now="2026-09-19T00:00:01+00:00")
        if outcome == "failure":
            raise RuntimeError("Synthetic response loss after replacement")
        return {"synced_at": "2026-09-19T00:00:02+00:00"}

    target = server if surface == "daemon" else commands_support_connect
    monkeypatch.setattr(target, "sync_local_guard_cloud_proof", sync)
    finalizer = (
        server._finalize_daemon_guard_connect_payload
        if surface == "daemon"
        else commands_support_connect._finalize_guard_connect_payload
    )
    with pytest.raises(RuntimeError, match="connection changed during authorization"):
        finalizer(
            store=store,
            connect_url="https://hol.org/guard/connect",
            now="2026-09-19T00:00:00+00:00",
            payload={
                "status": "connected",
                "connect_mode": "browser_oauth",
                CONNECT_CONNECTION_KEY: committed,
                connect_flow.CONNECT_SYNC_AUTH_CONTEXT_KEY: context,
            },
        )
    assert peer.get_latest_guard_connect_state(now="2026-09-19T00:00:01+00:00") == captured["pairing"]
    assert required_credentials(peer)["workspace_id"] == "newer-team"


@pytest.mark.parametrize("phase", ["before-sync", "after-runtime", "after-receipts", "unchanged"])
def test_first_sync_preserves_explicit_authority_and_checks_summary_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    from codex_plugin_scanner.guard.runtime import runner
    from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff, selected_sync_auth_handoff

    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    committed = store.set_oauth_local_credentials(
        **credential_args(key, "authorized-team"), expected_attempt=store.begin_oauth_connect_attempt()
    )
    context = connect_flow._build_sync_auth_context(
        access_token="synthetic-access", dpop_key_material=key, sync_url="https://hol.org/api/guard/receipts/sync"
    )
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-09-19T00:00:00+00:00",
        request_id="authorized-pairing",
    )
    original_pairing = store.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00")
    marker = {"source": "newer-decision"}
    calls = []

    def replace():
        peer.set_oauth_local_credentials(**credential_args(key))
        peer.set_sync_payload("sync_summary", marker, "now")

    def runtime(_store, *, auth_context, **_kwargs):
        calls.append("runtime")
        assert selected_sync_auth_handoff(store, auth_context) == committed
        if phase == "after-runtime":
            replace()
        return {"runtime_session_id": "synthetic-session", "runtime_session_synced_at": "2026-09-19T00:00:02+00:00"}

    def receipts(_store, *, auth_context, **_kwargs):
        calls.append("receipts")
        assert selected_sync_auth_handoff(store, auth_context) == committed
        if phase == "after-receipts":
            replace()
        return {"synced_at": "2026-09-19T00:00:02+00:00", "receipts_stored": 0}

    monkeypatch.setattr(runner, "sync_runtime_session", runtime)
    monkeypatch.setattr(runner, "sync_receipts", receipts)
    monkeypatch.setattr(runner, "_local_guard_runtime_session", lambda **_: {"device_id": "synthetic-device"})
    with hold_sync_auth_handoff(store, context, committed):
        if phase == "before-sync":
            replace()
        if phase == "unchanged":
            assert (
                runner.sync_local_guard_cloud_proof(store, auth_context=context, now="2026-09-19T00:00:00+00:00")[
                    "receipts_stored"
                ]
                == 0
            )
            final_state = store.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00")
            assert final_state is not None and final_state["milestone"] == "first_sync_succeeded"
        else:
            with pytest.raises(RuntimeError, match="connection changed"):
                runner.sync_local_guard_cloud_proof(store, auth_context=context, now="2026-09-19T00:00:00+00:00")
            assert peer.get_sync_payload("sync_summary") == marker
            assert peer.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00") == original_pairing
    assert calls == ([] if phase == "before-sync" else ["runtime", "receipts"])


@pytest.mark.parametrize("surface", ["cli", "daemon"])
@pytest.mark.parametrize("missing", ["connection", "context", "invalid-context"])
def test_oauth_finalization_refuses_missing_private_authority_before_reset(
    tmp_path: Path, surface: str, missing: str
) -> None:
    from codex_plugin_scanner.guard.cli import commands_support_connect
    from codex_plugin_scanner.guard.cli.connect_completion import CONNECT_CONNECTION_KEY

    store = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    committed = store.set_oauth_local_credentials(
        **credential_args(key), expected_attempt=store.begin_oauth_connect_attempt()
    )
    marker = {"cursor": 51}
    store.set_sync_payload("receipt_sync_cursor", marker, "now")
    payload: dict[str, object] = {"status": "connected", "connect_mode": "browser_oauth"}
    if missing != "connection":
        payload[CONNECT_CONNECTION_KEY] = committed
    if missing == "invalid-context":
        payload[connect_flow.CONNECT_SYNC_AUTH_CONTEXT_KEY] = {"access_token": "synthetic-access"}
    finalizer = (
        server._finalize_daemon_guard_connect_payload
        if surface == "daemon"
        else commands_support_connect._finalize_guard_connect_payload
    )
    with pytest.raises(RuntimeError, match=r"authorized (connection|sync context)"):
        finalizer(
            store=store, connect_url="https://hol.org/guard/connect", payload=payload, now="2026-09-19T00:00:00+00:00"
        )
    assert store.capture_oauth_connection(allow_primary=True) == committed
    assert store.get_sync_payload("receipt_sync_cursor") == marker
    assert store.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00") is None


def test_conditional_reset_cannot_adopt_same_value_replacement_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    args = credential_args(generate_dpop_key_pair())
    committed = store.set_oauth_local_credentials(**args, expected_attempt=store.begin_oauth_connect_attempt())
    assert committed is not None
    clear = store.clear_policy_bundle_authority
    captured = {}

    def replace_during_reset(*positional, **kwargs):
        result = clear(*positional, **kwargs)
        peer.set_oauth_local_credentials(**args)
        captured["authority"] = peer.get_sync_payload(connection_epoch_key("oauth_local_credentials"))
        return result

    monkeypatch.setattr(store, "clear_policy_bundle_authority", replace_during_reset)
    with pytest.raises(RuntimeError, match="connection changed during authorization"):
        store.clear_cloud_sync_state_for_reconnect(now="2026-09-19T00:00:00+00:00", expected_connection=committed)
    authority = peer.get_sync_payload(connection_epoch_key("oauth_local_credentials"))
    assert authority == captured["authority"]
    assert isinstance(authority, dict) and authority.get("reset")
    assert peer.capture_oauth_connection(allow_primary=True) is None
    assert peer.get_latest_guard_connect_state(now="2026-09-19T00:00:00+00:00") is None


@pytest.mark.parametrize("response", [200, 404, 429])
@pytest.mark.parametrize("change", ["replacement", "disconnect", "unchanged"])
def test_actual_runtime_session_commit_respects_initial_connection_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: int, change: str
) -> None:
    import urllib.error

    from codex_plugin_scanner.guard.runtime import runner
    from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff

    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    args = credential_args(key, "authorized-team")
    committed = store.set_oauth_local_credentials(**args, expected_attempt=store.begin_oauth_connect_attempt())
    context = connect_flow._build_sync_auth_context(
        access_token="synthetic-access", dpop_key_material=key, sync_url="https://hol.org/api/guard/receipts/sync"
    )
    marker = {"source": "newer-decision", "runtime_device_id": "newer-device"}
    catalog = Mock(return_value={})

    def reply(**kwargs):
        kwargs["validate_request"]()
        if change == "replacement":
            peer.set_oauth_local_credentials(**credential_args(key))
        elif change == "disconnect":
            peer.clear_oauth_local_credentials()
        if change != "unchanged":
            peer.set_sync_payload("runtime_session_summary", marker, args["now"])
        if response != 200:
            raise urllib.error.HTTPError(
                "https://hol.org/api/guard/runtime/sync", response, "controlled", Message(), None
            )
        return {"syncedAt": "2026-09-19T00:00:10+00:00", "items": []}

    monkeypatch.setattr(runner, "_cloud_local_identity_payload", lambda **_: {})
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", reply)
    monkeypatch.setattr(runner, "_sync_extension_catalog_from_runtime_handshake", catalog)
    with hold_sync_auth_handoff(store, context, committed):
        if change == "unchanged":
            result = runner.sync_runtime_session(
                store, session={"harness": "codex", "surface": "cli", "status": "active"}, auth_context=context
            )
            assert peer.get_sync_payload("runtime_session_summary") == result
            assert len(peer.list_guard_events_v1(uploaded=False, limit=10)) == (1 if response == 200 else 0)
        else:
            with pytest.raises(RuntimeError, match="connection changed"):
                runner.sync_runtime_session(
                    store, session={"harness": "codex", "surface": "cli", "status": "active"}, auth_context=context
                )
            assert peer.get_sync_payload("runtime_session_summary") == marker
            assert peer.list_guard_events_v1(uploaded=False, limit=10) == []
            catalog.assert_not_called()


@pytest.mark.parametrize("phase", ["refresh", "revoke"])
@pytest.mark.parametrize("rotation", [True, False])
@pytest.mark.parametrize("change", ["replacement", "new-attempt", "unchanged"])
def test_older_disconnect_completion_preserves_later_connection_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, rotation: bool, change: str
) -> None:
    from dataclasses import replace

    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    store.set_oauth_local_credentials(**credential_args(key, "original-team"))
    captured = {}

    def mutate():
        if change == "replacement":
            peer.set_oauth_local_credentials(**credential_args(key))
        elif change == "new-attempt":
            peer.begin_oauth_connect_attempt()
        captured["connection"] = peer.capture_oauth_connection(allow_primary=True)

    def refresh(**_kwargs):
        if phase == "refresh":
            mutate()
        return replace(token_result(), refresh_token="synthetic-rotated-refresh" if rotation else None)

    def revoke(**_kwargs):
        if phase == "revoke":
            mutate()

    monkeypatch.setattr(connect_flow, "refresh_guard_access_token", refresh)
    monkeypatch.setattr(connect_flow, "revoke_guard_self_oauth_grant", revoke)
    if change == "unchanged":
        assert (
            connect_flow.run_guard_disconnect_command(store=store, revoke_cloud_grant=False)["status"] == "disconnected"
        )
        assert peer.get_oauth_local_credentials(allow_primary=True) is None
    else:
        with pytest.raises(RuntimeError, match="connection changed"):
            connect_flow.run_guard_disconnect_command(store=store, revoke_cloud_grant=False)
        assert peer.capture_oauth_connection(allow_primary=True) == captured["connection"]


def test_old_inactive_grant_response_cannot_clear_replacement_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    store.set_oauth_local_credentials(**credential_args(key, "original-team"))
    captured = {}

    def refresh(**_kwargs):
        peer.set_oauth_local_credentials(**credential_args(key))
        captured["connection"] = peer.capture_oauth_connection(allow_primary=True)
        raise RuntimeError("Grant is missing, expired, or already consumed")

    monkeypatch.setattr(connect_flow, "refresh_guard_access_token", refresh)
    with pytest.raises(RuntimeError, match="connection changed"):
        connect_flow.run_guard_disconnect_command(store=store, revoke_cloud_grant=False)
    assert peer.capture_oauth_connection(allow_primary=True) == captured["connection"]


def test_empty_disconnect_cancels_before_a_waiting_credential_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading

    store = GuardStore(tmp_path / "guard-home")
    peer = GuardStore(tmp_path / "guard-home")
    args = credential_args(generate_dpop_key_pair())
    stale_attempt = peer.begin_oauth_connect_attempt()
    capture = store._capture_oauth_connection_unlocked
    writer_started = threading.Event()
    writer_done = threading.Event()
    failures: list[BaseException] = []

    def write():
        writer_started.set()
        try:
            peer.set_oauth_local_credentials(**args)
        except BaseException as error:
            failures.append(error)
        finally:
            writer_done.set()

    writer = threading.Thread(target=write)

    def capture_with_waiting_writer(**kwargs):
        value = capture(**kwargs)
        assert value is None
        writer.start()
        assert writer_started.wait(2)
        # A writer using the actual second Store cannot enter this cancellation lease.
        assert not writer_done.is_set()
        return value

    monkeypatch.setattr(store, "_capture_oauth_connection_unlocked", capture_with_waiting_writer)
    try:
        result = connect_flow.run_guard_disconnect_command(store=store, revoke_cloud_grant=False)
    finally:
        writer.join(timeout=5)
    assert result["status"] == "not_connected"
    assert writer_done.is_set() and not failures
    assert required_credentials(peer)["workspace_id"] == "newer-team"
    with pytest.raises(RuntimeError, match="connection changed during authorization"):
        peer.set_oauth_local_credentials(**args, expected_attempt=stale_attempt)

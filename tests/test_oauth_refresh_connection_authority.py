"""Actual credential authority fences around OAuth provider boundaries."""

from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.oauth_refresh_connection_support import _error, _mutate, _Response, _token
from tests.oauth_refresh_connection_support import _offline as _offline
from tests.test_oauth_connection_authority import NOW, _inputs, _store


@pytest.mark.parametrize("bound", [False, True])
@pytest.mark.parametrize(
    "mutation",
    [
        "unchanged",
        "unrelated",
        "named-source",
        "workspace",
        "grant",
        "key",
        "endpoint",
        "reset",
        "withdrawal",
        "aba",
        "identical",
    ],
)
def test_provider_response_cannot_replace_changed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: bool, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    before = store.capture_oauth_connection()
    assert before is not None
    observed: list[object] = []

    def transport(_request: object, timeout: float) -> _Response:
        assert timeout == 20
        _mutate(peer, inputs, mutation)
        observed.append(peer.capture_oauth_connection())
        return _Response(inputs)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if mutation in {"unchanged", "unrelated", "named-source"}:
        result = runner._resolve_guard_sync_auth_context(
            store, force_refresh=True, required_connection=before if bound else None
        )
        assert set(result) == {"access_token", "dpop_key_material", "sync_url"}
        after = store.capture_oauth_connection()
        assert after is not None and before.same_authority(after)
        assert after.credentials()["refresh_token"] == "rotated-refresh"
    else:
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(
                store, force_refresh=True, required_connection=before if bound else None
            )
        assert store.capture_oauth_connection() == observed[0]
    assert len(observed) == 1


@pytest.mark.parametrize("mutation", ["unchanged", "withdrawal", "reset", "aba"])
def test_cached_return_has_its_own_authority_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    actual_cached = runner._cached_oauth_access_token

    def cache(credentials: dict[str, object], **kwargs: Any) -> str | None:
        result = actual_cached(credentials, **kwargs)
        assert result is not None
        _mutate(store, inputs, mutation)
        return result

    def no_transport(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Valid cache must not request a token")

    monkeypatch.setattr(runner, "_cached_oauth_access_token", cache)
    monkeypatch.setattr(runner, "managed_urlopen", no_transport)
    if mutation == "unchanged":
        result = runner._resolve_guard_sync_auth_context(store)
        assert set(result) == {"access_token", "dpop_key_material", "sync_url"}
        assert store.capture_oauth_connection() == before
    else:
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(store)


@pytest.mark.parametrize("mutation", ["unchanged", "withdrawal", "reset", "aba"])
def test_nonpersisted_refresh_has_its_own_return_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    inputs["access_token_expires_at"] = "2000-01-01T00:00:00+00:00"
    store.set_oauth_local_credentials(**inputs)
    before = store.capture_oauth_connection()
    writes: list[object] = []
    actual_set = store.set_oauth_local_credentials

    def set_credentials(**kwargs: Any) -> object:
        writes.append(kwargs)
        return actual_set(**kwargs)

    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    observed: list[object] = []

    def transport(_request: object, timeout: float) -> _Response:
        assert timeout == 20
        _mutate(peer, inputs, mutation)
        observed.append(peer.capture_oauth_connection())
        return _Response(inputs, rotate=False)

    monkeypatch.setattr(store, "set_oauth_local_credentials", set_credentials)
    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if mutation == "unchanged":
        result = runner._resolve_guard_sync_auth_context(store)
        assert result["access_token"] == _token(inputs)
        assert store.capture_oauth_connection() == before
    else:
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(store)
        assert store.capture_oauth_connection() == observed[0]
    assert not writes


@pytest.mark.parametrize("bound", [False, True])
@pytest.mark.parametrize("mutation", ["same-rotation", "key", "endpoint", "withdrawal"])
def test_invalid_grant_retry_captures_complete_current_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: bool, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    before = store.capture_oauth_connection()
    assert before is not None
    replacement: dict[str, Any] = {
        **inputs,
        "refresh_token": "replacement-refresh",
        "cloud_user_profile": {"name": "fresh-peer"},
    }
    if mutation == "key":
        replacement.update({k: v for k, v in _inputs().items() if k.startswith("dpop_")})
    if mutation == "endpoint":
        replacement.update(issuer="http://localhost:3041", client_id="replacement-client")
    calls: list[tuple[str, dict[str, list[str]], dict[str, object]]] = []
    sleeps: list[float] = []

    def transport(request: Any, timeout: float) -> _Response:
        assert timeout == 20
        form = urllib.parse.parse_qs(request.data.decode())
        proof = request.get_header("Dpop")
        header = json.loads(base64.urlsafe_b64decode(proof.split(".")[0] + "=="))
        calls.append((request.full_url, form, header))
        if len(calls) == 1:
            if mutation == "withdrawal":
                peer.delete_sync_payload(peer._oauth_local_credentials_state_key)
            else:
                peer.set_oauth_local_credentials(
                    **replacement, expected_connection=before if mutation == "same-rotation" else None
                )
            raise _error(request)
        assert request.full_url == replacement["issuer"] + "/api/guard/oauth/token"
        assert form["client_id"] == [replacement["client_id"]]
        assert form["refresh_token"] == [replacement["refresh_token"]]
        assert header["jwk"] == replacement["dpop_public_jwk"]
        return _Response(replacement)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)
    if mutation == "withdrawal" or (bound and mutation != "same-rotation"):
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(
                store, force_refresh=True, required_connection=before if bound else None
            )
        assert len(calls) == 1
    else:
        result = runner._resolve_guard_sync_auth_context(
            store, force_refresh=True, required_connection=before if bound else None
        )
        assert len(calls) == 2
        assert result["sync_url"] == replacement["issuer"] + "/api/guard/receipts/sync"
        assert result["dpop_key_material"] == runner._oauth_dpop_key_material(replacement)
        persisted = store.get_oauth_local_credentials()
        assert persisted is not None
        assert persisted["cloud_user_profile"] == {"name": "fresh-peer"}
        assert persisted["dpop_private_key_pem"] == replacement["dpop_private_key_pem"]
    assert sleeps == [0.75]


@pytest.mark.parametrize("mutation", ["unchanged", "reset", "withdrawal"])
def test_nonce_retry_validates_authority_before_next_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    calls: list[object] = []

    def transport(request: Any, timeout: float) -> _Response:
        assert timeout == 20
        calls.append(request)
        if len(calls) == 1:
            _mutate(store, inputs, mutation)
            raise _error(request, nonce=True)
        return _Response(inputs)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if mutation == "unchanged":
        assert runner._resolve_guard_sync_auth_context(store, force_refresh=True)["access_token"] == _token(inputs)
        assert len(calls) == 2
    else:
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(store, force_refresh=True)
        assert len(calls) == 1


@pytest.mark.parametrize("boundary", ["before-cas", "after-cas"])
def test_late_commit_and_return_use_the_exact_written_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    store, inputs = _store(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    observed: list[object] = []
    actual_set = store.set_oauth_local_credentials

    def set_credentials(**kwargs: Any) -> object:
        if boundary == "before-cas":
            _mutate(peer, inputs, "workspace")
            observed.append(peer.capture_oauth_connection())
            return actual_set(**kwargs)
        committed = actual_set(**kwargs)
        _mutate(peer, inputs, "workspace")
        observed.append(peer.capture_oauth_connection())
        return committed

    monkeypatch.setattr(store, "set_oauth_local_credentials", set_credentials)
    monkeypatch.setattr(runner, "managed_urlopen", lambda *_args, **_kwargs: _Response(inputs))
    with pytest.raises(RuntimeError, match="connection changed"):
        runner._resolve_guard_sync_auth_context(store, force_refresh=True)
    assert store.capture_oauth_connection() == observed[0]


def test_late_revocation_cannot_clear_a_replacement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store, inputs = _store(tmp_path)
    inputs["access_token_expires_at"] = "2000-01-01T00:00:00+00:00"
    store.set_oauth_local_credentials(**inputs)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    calls: list[object] = []
    observed: list[object] = []

    def transport(request: Any, timeout: float) -> _Response:
        assert timeout == 20
        calls.append(request)
        if len(calls) == 2:
            _mutate(peer, inputs, "workspace")
            observed.append(peer.capture_oauth_connection())
        raise _error(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    assert runner.clear_revoked_guard_oauth_sign_in(store) is False
    assert len(calls) == 2
    assert store.capture_oauth_connection() == observed[0]


@pytest.mark.parametrize("bound", [False, True])
def test_outer_retry_starts_a_fresh_complete_source_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: bool
) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    replacement: dict[str, Any] = {
        **inputs,
        "issuer": "http://localhost:3041",
        "client_id": "replacement-client",
        "refresh_token": "replacement-refresh",
    }
    replacement.update({k: v for k, v in _inputs().items() if k.startswith("dpop_")})
    calls: list[str] = []
    sleeps: list[float] = []

    def transport(request: Any, timeout: float) -> _Response:
        assert timeout == 20
        calls.append(request.full_url)
        if len(calls) < 3:
            if len(calls) == 2:
                store.set_oauth_local_credentials(**replacement)
            raise _error(request)
        assert request.full_url == replacement["issuer"] + "/api/guard/oauth/token"
        assert urllib.parse.parse_qs(request.data.decode())["client_id"] == [replacement["client_id"]]
        return _Response(replacement)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner.time, "sleep", sleeps.append)
    if bound:
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(store, force_refresh=True, required_connection=before)
        assert len(calls) == 2
    else:
        result = runner._resolve_guard_sync_auth_context(store, force_refresh=True)
        assert len(calls) == 3
        assert result["sync_url"] == replacement["issuer"] + "/api/guard/receipts/sync"
        assert result["dpop_key_material"] == runner._oauth_dpop_key_material(replacement)
    assert sleeps == [0.75]


@pytest.mark.parametrize("allow_primary", [False, True])
@pytest.mark.parametrize("authority", ["ready", "pending", "invalid"])
def test_actual_recoverable_secret_respects_authority_and_repair_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, allow_primary: bool, authority: str
) -> None:
    from tests.test_oauth_connection_authority import _corrupt_epoch

    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    assert store.get_recoverable_oauth_local_credentials() == before.credentials()
    if authority == "invalid":
        _corrupt_epoch(store, "{}")
    elif authority == "pending":

        def fail_cleanup(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("controlled reset failure")

        with monkeypatch.context() as context:
            context.setattr(store, "clear_policy_bundle_authority", fail_cleanup)
            with pytest.raises(RuntimeError, match="controlled reset failure"):
                store.clear_cloud_sync_state_for_reconnect(now=NOW)
    # Only the normal reader is unavailable. Recovery still reads the actual encrypted store.
    monkeypatch.setattr(store, "get_oauth_local_credentials", lambda **_kwargs: None)
    calls: list[object] = []

    def transport(_request: object, timeout: float) -> _Response:
        assert timeout == 20
        calls.append(_request)
        return _Response(inputs)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if authority != "ready":
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._resolve_guard_sync_auth_context(
                store, allow_primary_repair=allow_primary, required_connection=before
            )
        assert calls == []
    else:
        result = runner._resolve_guard_sync_auth_context(
            store, allow_primary_repair=allow_primary, required_connection=before
        )
        assert result["access_token"] == (_token(inputs) if allow_primary else inputs["access_token"])
        assert len(calls) == int(allow_primary)
        after = store.capture_oauth_connection(allow_recoverable=True)
        assert after is not None and before.same_authority(after)


@pytest.mark.parametrize("mutation", ["unchanged", "workspace"])
def test_recovered_binding_persistence_compares_original_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    store, inputs = _store(tmp_path)
    incomplete: dict[str, Any] = {
        **inputs,
        "access_token": _token(inputs),
        "grant_id": None,
        "machine_id": None,
        "workspace_id": None,
    }
    store.set_oauth_local_credentials(**incomplete)
    credentials = store.get_oauth_local_credentials()
    assert credentials is not None and credentials.get("workspace_id") is None
    actual_persist = runner._persist_rotated_oauth_refresh_token
    observed: list[object] = []

    def persist(**kwargs: Any):
        _mutate(store, inputs, mutation)
        observed.append(store.capture_oauth_connection())
        return actual_persist(**kwargs)

    monkeypatch.setattr(runner, "_persist_rotated_oauth_refresh_token", persist)
    if mutation == "unchanged":
        assert runner._persist_recovered_oauth_binding(store, credentials)
        current = store.get_oauth_local_credentials()
        assert current is not None and current["workspace_id"] == inputs["workspace_id"]
    else:
        with pytest.raises(RuntimeError, match="connection changed"):
            runner._persist_recovered_oauth_binding(store, credentials)
        assert store.capture_oauth_connection() == observed[0]


def test_public_disconnect_remains_serialized_across_processes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    import sys
    import threading
    from queue import Empty, Queue

    store, inputs = _store(tmp_path)
    children: list[subprocess.Popen[str]] = []
    readers: list[threading.Thread] = []
    child_code = r"""
import socket
import sys
from pathlib import Path
from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.store import GuardStore

def denied(*args, **kwargs):
    raise AssertionError("Unexpected raw network operation")
socket.socket.connect = denied
socket.create_connection = denied
store = GuardStore(Path(sys.argv[1]), allow_system_keyring=False)
original = store_connection_schema._acquire_advisory_file_lock
announced = False

def observed_acquisition(handle):
    global announced
    try:
        return original(handle)
    except BlockingIOError:
        if Path(handle.name).name == "oauth-refresh.lock" and not announced:
            announced = True
            print("blocked", flush=True)
        raise

store_connection_schema._acquire_advisory_file_lock = observed_acquisition
store.clear_oauth_local_credentials()
assert store.get_oauth_local_credentials() is None
print("cleared", flush=True)
"""

    def transport(_request: object, timeout: float) -> _Response:
        assert timeout == 20
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(store.guard_home)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        children.append(child)
        assert child.stdout is not None
        lines: Queue[str] = Queue()

        def read_boundary() -> None:
            assert child.stdout is not None
            lines.put(child.stdout.readline())

        reader = threading.Thread(target=read_boundary, daemon=True)
        readers.append(reader)
        reader.start()
        try:
            line = lines.get(timeout=10)
        except Empty:
            pytest.fail("Disconnect never reached its actual lock boundary")
        reader.join(timeout=10)
        assert not reader.is_alive()
        assert line.strip() == "blocked"
        assert child.poll() is None
        assert store.get_oauth_local_credentials() is not None
        return _Response(inputs)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    try:
        result = runner._resolve_guard_sync_auth_context(store, force_refresh=True)
        assert result["access_token"] == _token(inputs)
        assert len(children) == 1
        output, error = children[0].communicate(timeout=10)
        assert children[0].returncode == 0
        assert output.strip() == "cleared"
        assert error == ""
        assert store.get_oauth_local_credentials() is None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
        for reader in readers:
            reader.join(timeout=10)
            assert not reader.is_alive()
        for child in children:
            child.communicate(timeout=10)


@pytest.mark.parametrize("failure", ["untrusted-endpoint", "malformed-response", "runtime-upgraded"])
def test_existing_trust_and_upgrade_refusals_remain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    calls: list[object] = []

    def transport(request: object, timeout: float) -> _Response:
        calls.append(request)
        assert timeout == 20
        response = _Response(inputs)
        response.payload = {}
        return response

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if failure == "untrusted-endpoint":
        payload = store.get_sync_payload(store._oauth_local_credentials_state_key)
        assert isinstance(payload, dict)
        payload["issuer"] = "https://invalid.example"
        store.set_sync_payload(store._oauth_local_credentials_state_key, payload, NOW)
        expected = runner.GuardSyncEndpointUntrustedError
    elif failure == "runtime-upgraded":
        monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: True)
        expected = runner.GuardSyncNotAvailableError
    else:
        expected = runner.GuardSyncAuthorizationExpiredError
    current = store.capture_oauth_connection()
    with pytest.raises(expected):
        runner._resolve_guard_sync_auth_context(store, force_refresh=True)
    assert store.capture_oauth_connection() == current
    assert len(calls) == int(failure == "malformed-response")


@pytest.mark.parametrize("override", ["memory", "environment"])
def test_bound_resolution_never_substitutes_test_auth_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: str
) -> None:
    store, inputs = _store(tmp_path)
    before = store.capture_oauth_connection()
    assert before is not None
    fake = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "synthetic-override",
        "dpop_key_material": None,
    }
    if override == "memory":
        monkeypatch.setattr(runner, "_test_sync_auth_context_override", fake)
    else:
        monkeypatch.setenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", json.dumps(fake))
    _mutate(store, inputs, "workspace")
    with pytest.raises(RuntimeError, match="connection changed"):
        runner._resolve_guard_sync_auth_context(store, required_connection=before)


def test_refresh_request_representation_hides_source_and_credentials() -> None:
    from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial

    sentinels = (
        "https://synthetic-source.invalid/private-route-marker",
        "synthetic-private-client-marker",
        "synthetic-private-refresh-marker",
        "synthetic-private-key-marker",
        "synthetic-public-key-marker",
        "synthetic-thumbprint-marker",
    )
    key = GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=sentinels[3],
        public_jwk={"kid": sentinels[4]},
        public_jwk_thumbprint=sentinels[5],
    )
    request = runner._OAuthRefreshRequest(sentinels[0], sentinels[1], sentinels[2], key)
    assert (request.token_endpoint, request.client_id, request.refresh_token, request.dpop_key_material) == (
        sentinels[0],
        sentinels[1],
        sentinels[2],
        key,
    )
    for rendered in (repr(request), str(request)):
        assert all(value not in rendered for value in sentinels)

"""Resolved authentication exposes only the authority of its actual successful result."""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.oauth_connection_authority import OAuthConnectionSnapshot
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests import test_oauth_refresh_connection_authority as existing
from tests.test_oauth_connection_authority import _store


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected raw network operation")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: False)
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**vars(time)))
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)


def _assert_result_source(result: dict[str, object], captured: OAuthConnectionSnapshot, store: GuardStore) -> None:
    assert set(result) == {"sync_url", "access_token", "dpop_key_material"}
    assert captured == store.capture_oauth_connection(allow_recoverable=True)
    credentials = captured.credentials()
    assert result["sync_url"] == credentials["issuer"] + "/api/guard/receipts/sync"
    assert result["dpop_key_material"] == runner._oauth_dpop_key_material(credentials)


@pytest.mark.parametrize("source", ["default", "selected"])
@pytest.mark.parametrize("mode", ["cached", "rotated", "nonpersisted", "recovered", "recovered-read-only"])
def test_actual_cached_refreshed_and_recovered_results_handoff_their_selected_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, mode: str
) -> None:
    store, inputs = _store(tmp_path, source=source)
    if mode == "nonpersisted":
        inputs["access_token_expires_at"] = "2000-01-01T00:00:00+00:00"
        store.set_oauth_local_credentials(**inputs)
    before = store.capture_oauth_connection()
    assert before is not None
    if mode.startswith("recovered"):
        monkeypatch.setattr(store, "get_oauth_local_credentials", lambda **_kwargs: None)
    sent: list[object] = []
    observed: list[OAuthConnectionSnapshot] = []

    def transport(request: object, timeout: int) -> existing._Response:
        assert timeout == 20
        sent.append(request)
        return existing._Response(inputs, rotate=mode != "nonpersisted")

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    result = runner._resolve_guard_sync_auth_context(
        store,
        force_refresh=mode == "rotated",
        allow_primary_repair=mode != "recovered-read-only",
        connection_observer=observed.append,
    )
    assert len(observed) == 1
    _assert_result_source(result, observed[0], store)
    assert observed[0].same_authority(before)
    assert len(sent) == int(mode in {"rotated", "nonpersisted", "recovered"})
    assert result["access_token"] == (existing._token(inputs) if sent else inputs["access_token"])
    if mode in {"cached", "nonpersisted", "recovered-read-only"}:
        assert observed[0] == before


@pytest.mark.parametrize("bound", [False, True])
@pytest.mark.parametrize("recovery", ["provider", "outer"])
def test_complete_replacement_recovery_reports_only_the_actual_successful_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bound: bool, recovery: str
) -> None:
    actual = runner._resolve_guard_sync_auth_context
    observed: list[OAuthConnectionSnapshot] = []
    results: list[dict[str, object]] = []

    def resolve(store: GuardStore, **kwargs: Any) -> dict[str, object]:
        result = actual(store, connection_observer=observed.append, **kwargs)
        assert len(observed) == 1
        _assert_result_source(result, observed[0], store)
        results.append(result)
        return result

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolve)
    if recovery == "provider":
        existing.test_invalid_grant_retry_captures_complete_current_source(tmp_path, monkeypatch, bound, "endpoint")
    else:
        existing.test_outer_retry_starts_a_fresh_complete_source_attempt(tmp_path, monkeypatch, bound)
    assert len(observed) == len(results) == int(not bound)
    if not bound:
        assert observed[0].credentials()["issuer"] == "http://localhost:3041"
        assert observed[0].credentials()["client_id"] == "replacement-client"


@pytest.mark.parametrize("mode", ["cached", "nonpersisted"])
@pytest.mark.parametrize("mutation", ["reset", "aba"])
def test_failed_final_authority_fence_does_not_emit_a_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, mutation: str
) -> None:
    actual = runner._resolve_guard_sync_auth_context
    observed: list[OAuthConnectionSnapshot] = []

    def resolve(store: GuardStore, **kwargs: Any) -> dict[str, object]:
        return actual(store, connection_observer=observed.append, **kwargs)

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", resolve)
    if mode == "cached":
        existing.test_cached_return_has_its_own_authority_fence(tmp_path, monkeypatch, mutation)
    else:
        existing.test_nonpersisted_refresh_has_its_own_return_fence(tmp_path, monkeypatch, mutation)
    assert observed == []


@pytest.mark.parametrize("override", ["memory", "environment"])
def test_plain_test_authentication_never_mints_optional_upload_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, override: str
) -> None:
    store, _ = _store(tmp_path)
    context = {
        "sync_url": "https://hol.org/api/guard/receipts/sync",
        "access_token": "synthetic-override",
        "dpop_key_material": None,
    }
    if override == "memory":
        monkeypatch.setattr(runner, "_test_sync_auth_context_override", context)
    else:
        monkeypatch.setenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", json.dumps(context))
    observed: list[OAuthConnectionSnapshot] = []
    assert runner._resolve_guard_sync_auth_context(store, connection_observer=observed.append) == context
    assert observed == []

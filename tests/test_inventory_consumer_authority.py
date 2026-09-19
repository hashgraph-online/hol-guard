"""Real inventory collection, authentication and transport retain one authority."""

from __future__ import annotations

import io
import json
import socket
import time
import urllib.error
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_cli
from codex_plugin_scanner.guard.runtime import runner
from tests.test_aibom_operation_authority import _context
from tests.test_oauth_connection_authority import NOW, _store
from tests.test_oauth_refresh_connection_authority import _Response as OAuthResponse


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected raw network operation")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: False)
    monkeypatch.setattr(runner, "_test_sync_auth_context_override", None)
    monkeypatch.delenv("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON", raising=False)


def _fixture(tmp_path: Path):
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    assert context.workspace_dir is not None
    context.workspace_dir.mkdir(parents=True)
    (context.home_dir / ".codex").mkdir(parents=True)
    (context.home_dir / ".codex/config.toml").write_text('[mcp_servers.generic]\ncommand="node"\nargs=["server.js"]\n')
    return store, inputs, context


class Response(io.BytesIO):
    def __init__(self, request: Any):
        events = json.loads(request.data)["events"]
        super().__init__(json.dumps({"accepted": len(events), "rejected": 0, "statuses": [], "syncedAt": NOW}).encode())


def test_successful_unauthorized_refresh_finishes_actual_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, inputs, context = _fixture(tmp_path)
    calls: list[str] = []

    def transport(request: Any, *, timeout: int):
        if request.full_url.endswith("/oauth/token"):
            calls.append("refresh")
            assert timeout == 20
            return OAuthResponse(inputs)
        calls.append("events")
        assert timeout == 90
        if calls == ["events"]:
            raise urllib.error.HTTPError(request.full_url, 401, "controlled", Message(), io.BytesIO(b"{}"))
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    result = aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
    assert result["synced"] is True
    assert result["accepted"] == result["snapshots"]
    assert calls == ["events", "refresh", "events"]
    assert store.get_sync_payload("aibom_sync_summary") == result


@pytest.mark.parametrize(
    "mutation",
    ["selection", "selection-aba", "source", "source-aba", "disconnect", "installation", "unrelated", "identical"],
)
@pytest.mark.parametrize("phase", ["collection", "response", "commit"])
def test_real_inventory_refuses_stale_results_without_touching_existing_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, phase: str
) -> None:
    from codex_plugin_scanner.guard import aibom_operation_authority as authority
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_aibom_operation_authority import _selected

    store, inputs, context = _fixture(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    selected = _selected(context)
    store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, selected, NOW)
    sentinel = {"synced": False, "sentinel": "prior-state"}
    store.set_sync_payload("aibom_sync_summary", sentinel, NOW)
    store.set_sync_payload("receipt_sync_cursor", {"last_rowid": 17}, NOW)
    requests: list[object] = []
    calls: list[str] = []

    def mutate() -> None:
        calls.append(mutation)
        if mutation in {"selection", "selection-aba"}:
            peer.set_sync_payload(
                authority.INVENTORY_CONTEXT_KEY, {**selected, "workspace_dir": str(tmp_path / "other")}, NOW
            )
            if mutation == "selection-aba":
                peer.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, selected, NOW)
        elif mutation in {"source", "source-aba"}:
            replacement: dict[str, Any] = {**inputs, "workspace_id": "other-workspace"}
            peer.set_oauth_local_credentials(**replacement)
            if mutation == "source-aba":
                peer.set_oauth_local_credentials(**inputs)
        elif mutation == "disconnect":
            peer.clear_oauth_local_credentials()
        elif mutation == "installation":
            peer.rotate_installation_id(NOW)
        elif mutation == "unrelated":
            peer.set_sync_payload("receipt_sync_cursor", {"last_rowid": 18}, NOW)
        else:
            peer.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, dict(selected), NOW)

    collect = aibom_cli.collect_aibom_snapshots
    commit = aibom_cli.commit_aibom_results

    def collection(*args: Any, **kwargs: Any):
        result = collect(*args, **kwargs)
        if phase == "collection":
            mutate()
        return result

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        requests.append(request)
        response = Response(request)
        if phase == "response":
            mutate()
        return response

    def committing(*args: Any, **kwargs: Any):
        if phase == "commit":
            mutate()
        return commit(*args, **kwargs)

    monkeypatch.setattr(aibom_cli, "collect_aibom_snapshots", collection)
    monkeypatch.setattr(aibom_cli, "commit_aibom_results", committing)
    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if mutation in {"unrelated", "identical"}:
        result = aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert result["synced"] is True
        assert store.get_sync_payload("aibom_sync_summary") == result
    else:
        with pytest.raises(RuntimeError, match="context changed"):
            aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert store.get_sync_payload("aibom_sync_summary") == sentinel
    assert calls == [mutation]
    assert len(requests) == (0 if phase == "collection" and mutation not in {"unrelated", "identical"} else 1)
    assert store.get_sync_payload("receipt_sync_cursor") == {"last_rowid": 18 if mutation == "unrelated" else 17}


@pytest.mark.parametrize("outcome", ["empty", "oversized", "success", "missing", "http", "network"])
@pytest.mark.parametrize("change_at_commit", [False, True])
def test_every_direct_summary_uses_conditional_atomic_result_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, change_at_commit: bool
) -> None:
    from codex_plugin_scanner.guard import aibom_operation_authority as authority
    from tests.test_aibom_operation_authority import _selected

    store, _inputs, context = _fixture(tmp_path)
    sentinel = {"sentinel": "unchanged"}
    store.set_sync_payload("aibom_sync_summary", sentinel, NOW)
    store.set_sync_payload("aibom_guard_events_backoff", sentinel, NOW)
    original_commit = aibom_cli.commit_aibom_results
    committed_keys: list[set[str]] = []

    def committing(*args: Any, **kwargs: Any):
        committed_keys.append(set(args[2]))
        if change_at_commit:
            store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(aibom_cli, "commit_aibom_results", committing)
    if outcome == "empty":
        monkeypatch.setattr(aibom_cli, "cloud_syncable_snapshots", lambda _snapshots: ())
    elif outcome == "oversized":
        monkeypatch.setattr(aibom_cli, "_batch_inventory_events", lambda events: ([], events))

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        if outcome == "network":
            raise OSError("controlled network failure")
        if outcome in {"missing", "http"}:
            raise urllib.error.HTTPError(
                request.full_url, 404 if outcome == "missing" else 403, "controlled", Message(), io.BytesIO(b"{}")
            )
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if change_at_commit:
        with pytest.raises(RuntimeError, match="context changed"):
            aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert store.get_sync_payload("aibom_sync_summary") == sentinel
        assert store.get_sync_payload("aibom_guard_events_backoff") == sentinel
    elif outcome in {"http", "network"}:
        with pytest.raises(RuntimeError, match=r"HTTP error|network error"):
            aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        summary = store.get_sync_payload("aibom_sync_summary")
        assert isinstance(summary, dict) and summary["synced"] is False
    else:
        result = aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert result["synced"] is (outcome in {"empty", "success"})
        assert store.get_sync_payload("aibom_sync_summary") == result
    assert committed_keys == [
        {"aibom_sync_summary", "aibom_guard_events_backoff"} if outcome == "missing" else {"aibom_sync_summary"}
    ]


def test_automatic_freshness_is_exact_context_and_legacy_state_is_not_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _inputs, context = _fixture(tmp_path)
    store.set_sync_payload("aibom_sync_summary", {"synced": True, "synced_at": NOW, "snapshots": 1}, NOW)
    requests: list[object] = []

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        requests.append(request)
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    args: dict[str, Any] = dict(generated_at=NOW, home_dir=context.home_dir, workspace_dir=context.workspace_dir)
    assert aibom_cli.sync_aibom_snapshots_if_due(store, **args)["synced"] is True
    assert len(requests) == 1
    assert aibom_cli.sync_aibom_snapshots_if_due(store, **args)["reason"] == "recently_synced"
    assert len(requests) == 1
    assert (
        aibom_cli.sync_aibom_snapshots_if_due(store, **dict(args, workspace_dir=tmp_path / "other"))["synced"] is True
    )
    assert len(requests) == 2
    assert aibom_cli.sync_aibom_snapshots_if_due(store, **args)["synced"] is True
    assert len(requests) == 3
    assert aibom_cli.sync_aibom_snapshots_if_due(store, force=True, **args)["synced"] is True
    assert len(requests) == 4


def test_caller_auth_dictionary_cannot_replace_captured_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _inputs, context = _fixture(tmp_path)
    requests: list[Any] = []

    def transport(request: Any, *, timeout: int):
        requests.append(request)
        assert request.full_url == "https://hol.org/api/v1/guard/events"
        assert request.get_header("Authorization") == "Bearer synthetic-access"
        assert request.get_header("Dpop")
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    result = aibom_cli.sync_aibom_snapshots(
        store,
        context,
        generated_at=NOW,
        auth_context={
            "sync_url": "https://other.invalid/private",
            "access_token": "stale-token",
            "dpop_key_material": None,
        },
    )
    assert result["synced"] is True
    assert len(requests) == 1


@pytest.mark.parametrize("mutation", ["unchanged", "selection", "source"])
def test_actual_refresh_response_cannot_switch_inventory_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    from codex_plugin_scanner.guard import aibom_operation_authority as authority
    from tests.test_aibom_operation_authority import _selected

    store, inputs, context = _fixture(tmp_path)
    calls: list[str] = []

    def transport(request: Any, *, timeout: int):
        if request.full_url.endswith("/oauth/token"):
            calls.append("refresh")
            assert timeout == 20
            if mutation == "selection":
                store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
            elif mutation == "source":
                replacement: dict[str, Any] = {**inputs, "workspace_id": "other"}
                store.set_oauth_local_credentials(**replacement)
            return OAuthResponse(inputs)
        calls.append("events")
        assert timeout == 90
        if calls == ["events"]:
            raise urllib.error.HTTPError(request.full_url, 401, "controlled", Message(), io.BytesIO(b"{}"))
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    if mutation == "unchanged":
        assert aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)["synced"] is True
        assert calls == ["events", "refresh", "events"]
    else:
        with pytest.raises(RuntimeError, match=r"context changed|connection changed"):
            aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert calls == ["events", "refresh"]
        assert store.get_sync_payload("aibom_sync_summary") is None


@pytest.mark.parametrize("mutation", ["unchanged", "selection", "source", "installation"])
@pytest.mark.parametrize("phase", ["content-response", "content-retry"])
def test_actual_primary_content_transport_revalidates_full_inventory_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, phase: str
) -> None:
    from codex_plugin_scanner.guard import aibom_operation_authority as authority
    from tests.test_aibom_operation_authority import _selected

    store, inputs, context = _fixture(tmp_path)
    assert context.workspace_dir is not None
    (context.workspace_dir / "AGENTS.md").write_text("# Synthetic workspace instructions\n")
    calls: list[str] = []
    successful_items: list[tuple[str, str]] = []

    def mutate() -> None:
        if mutation == "selection":
            store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
        elif mutation == "source":
            replacement: dict[str, Any] = {**inputs, "workspace_id": "other"}
            store.set_oauth_local_credentials(**replacement)
        elif mutation == "installation":
            store.rotate_installation_id(NOW)

    def transport(request: Any, *, timeout: int):
        if request.full_url.endswith("/content-upload"):
            calls.append("content")
            assert timeout == 60
            assert "/synthetic-workspace/" in request.full_url
            items = json.loads(request.data)["items"]
            assert items
            if calls.count("content") == 1:
                mutate()
                if phase == "content-retry":
                    headers = Message()
                    headers["Retry-After"] = "1"
                    raise urllib.error.HTTPError(request.full_url, 429, "controlled", headers, io.BytesIO(b"{}"))
            successful_items.extend((item["snapshotId"], item["itemId"]) for item in items)
            return io.BytesIO(json.dumps({"storedCount": len(items), "hashOnlyCount": 0, "failedCount": 0}).encode())
        calls.append("events")
        assert timeout == 90
        return Response(request)

    waits: list[int] = []
    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    if mutation == "unchanged":
        result = aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert result["synced"] is True
        content = result["content_upload"]
        assert isinstance(content, dict)
        assert content["stored"] == content["eligible"] == len(successful_items) > 0
        assert len(set(successful_items)) == len(successful_items)
        assert result["accepted"] == result["snapshots"]
        assert calls[0] == "events"
        assert calls.count("content") == len(successful_items) + int(phase == "content-retry")
        assert waits == ([1] if phase == "content-retry" else [])
    else:
        with pytest.raises(RuntimeError, match="context changed"):
            aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert calls == ["events", "content"]
        assert waits == []
        assert store.get_sync_payload("aibom_sync_summary") is None


@pytest.mark.parametrize("retry", ["nonce", "invalid-grant"])
@pytest.mark.parametrize("mutation", [False, True])
def test_actual_oauth_retry_attempts_keep_the_local_inventory_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry: str, mutation: bool
) -> None:
    from codex_plugin_scanner.guard import aibom_operation_authority as authority
    from tests.test_aibom_operation_authority import _selected
    from tests.test_oauth_refresh_connection_authority import _error as oauth_error

    store, inputs, context = _fixture(tmp_path)
    expired: dict[str, Any] = {**inputs, "access_token_expires_at": "2000-01-01T00:00:00Z"}
    store.set_oauth_local_credentials(**expired)
    calls: list[str] = []
    waits: list[float] = []

    def transport(request: Any, *, timeout: int):
        if request.full_url.endswith("/oauth/token"):
            calls.append("refresh")
            assert timeout == 20
            if calls == ["refresh"]:
                if mutation:
                    store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)
                raise oauth_error(request, nonce=retry == "nonce")
            return OAuthResponse(inputs)
        calls.append("events")
        assert timeout == 90
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    if mutation:
        with pytest.raises(RuntimeError, match="context changed"):
            aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)
        assert calls == ["refresh"]
        assert waits == []
        assert store.get_sync_payload("aibom_sync_summary") is None
    else:
        assert aibom_cli.sync_aibom_snapshots(store, context, generated_at=NOW)["synced"] is True
        assert calls == ["refresh", "refresh", "events"]
        assert waits == ([0.75] if retry == "invalid-grant" else [])


@pytest.mark.parametrize("automatic", [False, True])
def test_named_source_inventory_never_borrows_default_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, automatic: bool
) -> None:
    from codex_plugin_scanner.guard.store import GuardStore

    store, inputs, context = _fixture(tmp_path)
    named = GuardStore(store.guard_home, source="named", allow_system_keyring=False)
    selected: dict[str, Any] = {**inputs, "workspace_id": "named-workspace", "access_token": "named-access"}
    named.set_oauth_local_credentials(**selected)
    requests: list[object] = []

    def transport(request: Any, *, timeout: int):
        assert timeout == 90
        requests.append(request)
        assert request.get_header("Authorization") == "Bearer named-access"
        events = json.loads(request.data)["events"]
        assert all(event["workspaceId"] == "named-workspace" for event in events)
        return Response(request)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    result = (
        aibom_cli.sync_aibom_snapshots_if_due(
            named, generated_at=NOW, home_dir=context.home_dir, workspace_dir=context.workspace_dir
        )
        if automatic
        else aibom_cli.sync_aibom_snapshots(named, context, generated_at=NOW)
    )
    assert result["synced"] is True
    assert len(requests) == 1
    default_credentials = store.get_oauth_local_credentials()
    assert default_credentials is not None
    assert default_credentials["workspace_id"] == "synthetic-workspace"

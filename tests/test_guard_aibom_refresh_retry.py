"""Drive inventory acknowledgments through the actual shared HTTP retry client."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import aibom_cli
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore

STAMP = "2026-09-17T00:00:00Z"
URL = "https://fixture.invalid/api/v1/guard/events"


@pytest.mark.parametrize("retry_outcome", ["accepted", "unauthorized", "missing_endpoint", "network_error"])
def test_inventory_auth_refresh_preserves_acknowledgment_and_failure_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retry_outcome: str
) -> None:
    home, workspace = tmp_path / "home", tmp_path / "workspace"
    workspace.mkdir()
    skill = home / ".hermes" / "skills" / "local" / "fixture" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: fixture\n---\nLocal evidence.\n", encoding="utf-8")
    context = HarnessContext(home, workspace, tmp_path / "guard")
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: "fixture-workspace")
    monkeypatch.setattr(aibom_cli, "detect_all", lambda current: (HermesHarnessAdapter().detect(current),))
    monkeypatch.setenv("GUARD_AIBOM_TRUST_ATTESTATION_V2", "0")
    requests: list[urllib.request.Request] = []
    refreshes: list[bool] = []

    def refresh(_store: GuardStore, *, force_refresh: bool) -> dict[str, object]:
        refreshes.append(force_refresh)
        return {"sync_url": URL, "access_token": "fixture-refreshed-token"}

    def transport(request: urllib.request.Request, *, timeout: int) -> io.BytesIO:
        assert timeout == (60 if request.full_url.endswith("/content-upload") else 90)
        requests.append(request)
        if request.full_url.endswith("/content-upload"):
            assert isinstance(request.data, bytes)
            body = json.loads(request.data)
            return io.BytesIO(
                json.dumps({"storedCount": len(body["items"]), "hashOnlyCount": 0, "failedCount": 0}).encode()
            )
        assert request.full_url == URL
        event_requests = [item for item in requests if item.full_url == URL]
        if len(event_requests) == 1:
            raise urllib.error.HTTPError(URL, 401, "expired fixture credential", Message(), io.BytesIO(b"{}"))
        assert len(event_requests) == 2, "credential refresh must be bounded to one attempt"
        if retry_outcome == "network_error":
            raise OSError("fixture transport failure")
        if retry_outcome in {"unauthorized", "missing_endpoint"}:
            code = 401 if retry_outcome == "unauthorized" else 404
            raise urllib.error.HTTPError(URL, code, "fixture retry failed", Message(), io.BytesIO(b"{}"))
        return io.BytesIO(b'{"accepted":1,"rejected":0}')

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", refresh)
    monkeypatch.setattr(runner, "managed_urlopen", transport)

    def synchronize() -> dict[str, object]:
        return aibom_cli.sync_aibom_snapshots(
            store,
            context,
            generated_at=STAMP,
            options=aibom_cli.AibomCliOptions(),
            auth_context={"sync_url": URL, "access_token": "fixture-expired-token"},
        )

    if retry_outcome in {"unauthorized", "network_error"}:
        expected = "HTTP error" if retry_outcome == "unauthorized" else "network error"
        with pytest.raises(RuntimeError, match=expected):
            synchronize()
        summary = store.get_sync_payload("aibom_sync_summary")
        assert isinstance(summary, dict) and summary["synced"] is False
        assert expected in str(summary["error"])
    else:
        summary = synchronize()
        assert summary["synced"] is (retry_outcome == "accepted")
        if retry_outcome == "accepted":
            assert summary["accepted"] == 1
            assert summary["content_upload_complete"] is True
            assert len(requests) == 3
        else:
            assert summary["reason"] == "guard_events_endpoint_unavailable"
            backoff = store.get_sync_payload(aibom_cli._AIBOM_GUARD_EVENTS_BACKOFF_KEY)
            assert isinstance(backoff, dict) and backoff["sync_reason"] == "guard_events_endpoint_unavailable"
    assert refreshes == [True]
    assert requests[0].data == requests[1].data
    assert requests[0].get_header("Authorization") == "Bearer fixture-expired-token"
    assert requests[1].get_header("Authorization") == "Bearer fixture-refreshed-token"
    if retry_outcome != "accepted":
        assert len(requests) == 2, "unaccepted inventories must not upload primary content"

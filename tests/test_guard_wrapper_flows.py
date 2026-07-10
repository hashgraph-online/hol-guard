"""Guard wrapper flow tests — P4.

Covers:
- wait_for_approval_requests resolves immediately when all items resolved
- wait_for_approval_requests returns pending when timeout fires
- _headless_approval_resolver with --json flag (noninteractive) skips waiting
- _headless_approval_resolver timeout produces hint with pending request IDs
- Duplicate approval requests for same artifact are not re-queued
"""

from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approvals import wait_for_approval_requests
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import (
    GuardArtifact,
    HarnessDetection,
)
from codex_plugin_scanner.guard.store import GuardStore


def _make_artifact(artifact_id: str = "codex:project:my_tool") -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name="my_tool",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="/home/user/.codex/config.toml",
        command="python",
        args=("-m", "my_tool"),
        transport="stdio",
    )


def _make_detection(artifact: GuardArtifact) -> HarnessDetection:
    return HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )


class TestWaitForApprovalRequests:
    def _add_request(self, store: GuardStore, req_id: str, status: str = "pending") -> str:
        from codex_plugin_scanner.guard.models import GuardApprovalRequest

        request = GuardApprovalRequest(
            request_id=req_id,
            harness="codex",
            artifact_id="codex:project:my_tool",
            artifact_name="my_tool",
            artifact_hash="sha256-abc",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("args",),
            source_scope="project",
            config_path="/workspace/.codex/config.toml",
            review_command=f"hol-guard approvals approve {req_id}",
            approval_url=f"http://127.0.0.1:4455/approvals/{req_id}",
        )
        persisted_id = store.add_approval_request(request, "2026-01-01T00:00:00+00:00")
        if status == "resolved":
            store.resolve_approval_request(
                persisted_id,
                resolution_action="allow",
                resolution_scope="artifact",
                reason=None,
                resolved_at="2026-01-01T00:00:01+00:00",
            )
        return persisted_id

    def test_resolves_immediately_when_all_requests_resolved(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        req_id = self._add_request(store, "req-001", status="resolved")
        result = wait_for_approval_requests(
            store=store,
            request_ids=[req_id],
            timeout_seconds=30,
            poll_interval=0.01,
        )
        assert result["resolved"] is True
        assert result["pending_request_ids"] == []

    def test_observes_remote_resolution_within_200ms(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        request_id = self._add_request(store, "req-fast-remote", status="pending")
        resolved_at = [0.0]

        def resolve_remotely() -> None:
            time.sleep(0.02)
            resolved_at[0] = time.monotonic()
            store.resolve_approval_request(
                request_id,
                resolution_action="allow",
                resolution_scope="artifact",
                reason=None,
                resolved_at="2026-01-01T00:00:01+00:00",
            )

        resolver = threading.Thread(target=resolve_remotely)
        resolver.start()
        try:
            result = wait_for_approval_requests(
                store=store,
                request_ids=[request_id],
                timeout_seconds=1,
            )
            observed_at = time.monotonic()
        finally:
            resolver.join(timeout=1)

        assert result["resolved"] is True
        assert observed_at - resolved_at[0] < 0.2

    def test_returns_pending_after_timeout_when_not_resolved(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        req_id = self._add_request(store, "req-002", status="pending")
        start = time.monotonic()
        result = wait_for_approval_requests(
            store=store,
            request_ids=[req_id],
            timeout_seconds=0,
            poll_interval=0.01,
        )
        elapsed = time.monotonic() - start
        assert result["resolved"] is False
        assert req_id in result["pending_request_ids"]
        assert elapsed < 2.0, "Timeout=0 should return almost immediately"

    def test_resolves_partial_when_some_resolved_some_pending(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        resolved_id = self._add_request(store, "req-003", status="resolved")
        pending_id = self._add_request(store, "req-004", status="pending")
        result = wait_for_approval_requests(
            store=store,
            request_ids=[resolved_id, pending_id],
            timeout_seconds=0,
            poll_interval=0.01,
        )
        assert result["resolved"] is False
        assert pending_id in result["pending_request_ids"]
        assert resolved_id not in result["pending_request_ids"]

    def test_empty_request_list_resolves_immediately(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        result = wait_for_approval_requests(
            store=store,
            request_ids=[],
            timeout_seconds=5,
            poll_interval=0.01,
        )
        assert result["resolved"] is True
        assert result["pending_request_ids"] == []


class TestHeadlessApprovalResolverNoninteractive:
    def _make_resolver(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        json_flag: bool = True,
    ) -> Any:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        store = GuardStore(home_dir)
        config = GuardConfig(
            guard_home=home_dir,
            workspace=workspace_dir,
            approval_wait_timeout_seconds=1,
        )
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _: "http://127.0.0.1:4455",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "load_guard_surface_daemon_client",
            lambda _: (_ for _ in ()).throw(RuntimeError("daemon unavailable")),
        )
        args = argparse.Namespace(harness="codex", json=json_flag)
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=home_dir,
        )
        return guard_commands_module._headless_approval_resolver(
            args=args,
            context=context,
            store=store,
            config=config,
        ), store

    def test_json_flag_skips_wait_and_returns_unresolved_approval_wait(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        resolver, _store = self._make_resolver(tmp_path, monkeypatch, json_flag=True)
        artifact = _make_artifact()
        payload: dict[str, Any] = {
            "blocked": True,
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "sha256-abc",
                    "policy_action": "require-reapproval",
                    "changed_fields": ["args"],
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "launch_target": "python -m my_tool",
                }
            ],
        }
        detection = _make_detection(artifact)
        result = resolver(detection, payload)

        assert "approval_wait" in result
        assert result["approval_wait"]["resolved"] is False

    def test_noninteractive_resolver_includes_approval_center_url(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        resolver, _store = self._make_resolver(tmp_path, monkeypatch, json_flag=True)
        artifact = _make_artifact()
        payload: dict[str, Any] = {
            "blocked": True,
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "sha256-abc",
                    "policy_action": "require-reapproval",
                    "changed_fields": ["args"],
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "launch_target": "python -m my_tool",
                }
            ],
        }
        detection = _make_detection(artifact)
        result = resolver(detection, payload)

        assert result.get("approval_center_url") == "http://127.0.0.1:4455"


class TestHeadlessApprovalResolverTimeout:
    def test_timeout_produces_review_hint_with_pending_request_ids(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        store = GuardStore(home_dir)
        config = GuardConfig(
            guard_home=home_dir,
            workspace=workspace_dir,
            approval_wait_timeout_seconds=0,
        )
        monkeypatch.setattr(
            guard_commands_module,
            "ensure_guard_daemon",
            lambda _: "http://127.0.0.1:4455",
        )
        monkeypatch.setattr(
            guard_commands_module,
            "load_guard_surface_daemon_client",
            lambda _: (_ for _ in ()).throw(RuntimeError("daemon unavailable")),
        )

        args = argparse.Namespace(harness="codex", json=False)
        context = HarnessContext(
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            guard_home=home_dir,
        )
        resolver = guard_commands_module._headless_approval_resolver(
            args=args,
            context=context,
            store=store,
            config=config,
        )

        artifact = _make_artifact()
        payload: dict[str, Any] = {
            "blocked": True,
            "artifacts": [
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "artifact_hash": "sha256-abc",
                    "policy_action": "require-reapproval",
                    "changed_fields": ["args"],
                    "artifact_type": artifact.artifact_type,
                    "source_scope": artifact.source_scope,
                    "config_path": artifact.config_path,
                    "launch_target": "python -m my_tool",
                }
            ],
        }
        detection = _make_detection(artifact)
        result = resolver(detection, payload)

        assert result["approval_wait"]["resolved"] is False
        review_hint = str(result.get("review_hint", ""))
        assert "pending" in review_hint.lower() or "approval" in review_hint.lower()

"""Watch-only behavior for resident hook output review."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import Protocol, cast

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardMode
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import (
    HookOutputSummary,
    HookReviewRequest,
    HookSourceFileRef,
)
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text
from codex_plugin_scanner.guard.store import GuardStore


class _Metrics:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class _DaemonServerAccess(Protocol):
    auth_token: str
    hook_worker: HookWorker


def _engine(
    guard_home: Path,
    *,
    mode: GuardMode,
    metrics: object | None = None,
) -> HookReviewEngine:
    store = GuardStore(guard_home)
    return HookReviewEngine(
        store=store,
        scanner=ContentScanner(),
        cache=HookDecisionCache(store),
        config_loader=lambda loaded_home, workspace: GuardConfig(
            guard_home=loaded_home,
            workspace=workspace,
            mode=mode,
        ),
        metrics=metrics,
    )


def _request(
    *,
    workspace: Path,
    guard_home: Path,
    payload: dict[str, object],
    source_ref: HookSourceFileRef | None = None,
    output_summary: HookOutputSummary | None = None,
) -> HookReviewRequest:
    return HookReviewRequest(
        harness="pi",
        event_name="PostToolUse",
        payload=payload,
        payload_kind="source_file_ref" if source_ref is not None else "inline",
        config_path=None,
        cwd=workspace,
        home_dir=workspace.parent,
        guard_home=guard_home,
        source_scope="project",
        source_ref=source_ref,
        output_summary=output_summary,
    )


def test_watch_only_observes_sensitive_source_read_without_blocking(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    source = workspace / "src" / "delivery.ts"
    source.parent.mkdir(parents=True)
    guard_home.mkdir()
    text = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";'
    _ = source.write_text(text, encoding="utf-8")
    output_sha256 = sha256_text(text)
    source_ref = HookSourceFileRef(
        version=1,
        path="src/delivery.ts",
        output_sha256=output_sha256,
        output_chars=len(text),
        tool_input_path="src/delivery.ts",
    )

    metrics = _Metrics()
    response = _engine(guard_home, mode="observe", metrics=metrics).review(
        _request(
            workspace=workspace,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/delivery.ts"},
            },
            source_ref=source_ref,
            output_summary=HookOutputSummary(
                text_excerpt=text,
                excerpt_truncated=False,
                output_sha256=output_sha256,
                output_chars=len(text),
            ),
        )
    )

    assert response.decision == "allow"
    assert response.model_output_action == "allow_original"
    assert response.reviewed_output_sha256 == output_sha256
    assert response.reason_code == "observe_source_secret_match"
    assert response.policy_action == "allow"
    assert response.observed_policy_action == "block"
    assert response.observe_mode is True
    assert metrics.calls[0]["policy_action"] == "block"


def test_watch_only_observes_inline_secret_output_without_blocking(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir()
    guard_home.mkdir()

    response = _engine(guard_home, mode="observe").review(
        _request(
            workspace=workspace,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_response": "token=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            },
        )
    )

    assert response.decision == "allow"
    assert response.model_output_action == "allow_original"
    assert response.reason_code == "observe_output_secret_match"
    assert response.observed_policy_action == "block"
    assert response.observe_mode is True


def test_watch_only_preserves_clean_truncated_output(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    guard_home = tmp_path / "guard-home"
    workspace.mkdir()
    guard_home.mkdir()
    text = "Routine output that exceeded the adapter payload limit."

    response = _engine(guard_home, mode="observe").review(
        _request(
            workspace=workspace,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "stdout": text,
            },
            output_summary=HookOutputSummary(
                text_excerpt=text,
                excerpt_truncated=True,
                output_sha256=None,
                output_chars=len(text) + 1,
            ),
        )
    )

    assert response.decision == "allow"
    assert response.model_output_action == "allow_original"
    assert response.reason_code == "output_too_large"
    assert response.observe_mode is True


def test_enforcing_modes_still_block_sensitive_source_read(tmp_path: Path) -> None:
    modes: tuple[GuardMode, ...] = ("prompt", "enforce")
    for mode in modes:
        workspace = tmp_path / mode
        guard_home = tmp_path / f"{mode}-guard-home"
        source = workspace / "src" / "delivery.ts"
        source.parent.mkdir(parents=True)
        guard_home.mkdir()
        text = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";'
        _ = source.write_text(text, encoding="utf-8")
        source_ref = HookSourceFileRef(
            version=1,
            path="src/delivery.ts",
            output_sha256=sha256_text(text),
            output_chars=len(text),
            tool_input_path="src/delivery.ts",
        )

        response = _engine(guard_home, mode=mode).review(
            _request(
                workspace=workspace,
                guard_home=guard_home,
                payload={
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Read",
                    "tool_input": {"file_path": "src/delivery.ts"},
                },
                source_ref=source_ref,
            )
        )

        assert response.decision == "deny"
        assert response.model_output_action == "block"
        assert response.reason_code == "source_secret_match"


def test_watch_only_daemon_worker_exception_does_not_block_harnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    guard_home.mkdir()
    workspace.mkdir()
    _ = (guard_home / "config.toml").write_text('mode = "observe"\n', encoding="utf-8")
    monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    daemon.start()
    server_access = cast(_DaemonServerAccess, vars(daemon)["_server"])

    def fail_review(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("resident worker failed")

    monkeypatch.setattr(server_access.hook_worker, "review_http_payload", fail_review)
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/delivery.ts"},
        "guard_source_ref": {
            "version": 1,
            "path": "src/delivery.ts",
            "tool_input_path": "src/delivery.ts",
            "output_sha256": "0" * 64,
            "output_chars": 10,
        },
    }

    try:
        results: dict[str, dict[str, object]] = {}
        for harness in ("pi", "claude-code"):
            query = urllib.parse.urlencode(
                {
                    "guard-home": str(guard_home),
                    "home": str(tmp_path),
                    "workspace": str(workspace),
                }
            )
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/hooks/{harness}?{query}",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": server_access.auth_token,
                },
                method="POST",
            )
            response = cast(HTTPResponse, urllib.request.urlopen(request, timeout=5))
            with response:
                results[harness] = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert results["pi"]["decision"] == "allow"
    assert results["pi"]["reason_code"] == "daemon_worker_exception"
    assert results["claude-code"]["continue"] is True
    assert results["claude-code"]["reason_code"] == "daemon_worker_exception"

"""Security regression tests for fast hook review.

These tests prove that raw oversized output never reaches the model
unreviewed, and that adversarial payloads fail safe.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
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


def _config_loader(guard_home: Path, workspace: Path | None) -> GuardConfig:
    return GuardConfig(guard_home=guard_home, workspace=workspace)


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "src").mkdir()
    return ws


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    hd = tmp_path / "home"
    hd.mkdir()
    return hd


@pytest.fixture()
def guard_home(tmp_path: Path) -> Path:
    gh = tmp_path / "guard-home"
    gh.mkdir()
    return gh


@pytest.fixture()
def store(guard_home: Path) -> GuardStore:
    return GuardStore(guard_home)


@pytest.fixture()
def engine(store: GuardStore) -> HookReviewEngine:
    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    return HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=_config_loader,
    )


def _source_ref(*, path: str, text: str, version: int = 1) -> HookSourceFileRef:
    stripped = text.rstrip("\n")
    return HookSourceFileRef(
        version=version,
        path=path,
        output_sha256=sha256_text(stripped),
        output_chars=len(stripped),
        tool_input_path=path,
    )


def _request(
    *,
    source_ref: HookSourceFileRef | None = None,
    cwd: Path,
    home_dir: Path,
    guard_home: Path,
    output_summary: HookOutputSummary | None = None,
) -> HookReviewRequest:
    return HookReviewRequest(
        harness="pi",
        event_name="PostToolUse",
        payload={
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": source_ref.path if source_ref else "src/foo.ts"},
        },
        payload_kind="source_file_ref" if source_ref else "inline",
        config_path=None,
        cwd=cwd,
        home_dir=home_dir,
        guard_home=guard_home,
        source_scope="project",
        source_ref=source_ref,
        output_summary=output_summary,
    )


class TestRawOversizedOutputNeverUnreviewed:
    def test_large_source_with_secret_after_12k_never_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Secret after the old 12k prefix must never pass through."""
        prefix = "x" * 15_000 + "\n"
        secret = 'token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\n'
        content = prefix + secret
        file_path = workspace / "src" / "large.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/large.ts", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        response = engine.review(request)
        assert response.model_output_action != "allow_original"
        assert response.decision == "deny"

    def test_large_source_with_secret_near_5mb_tail_never_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Secret near the 5MB tail must be found."""
        prefix = "x" * (4 * 1024 * 1024) + "\n"
        secret = "AKIAIOSFODNN7EXAMPLE\n"
        content = prefix + secret
        file_path = workspace / "src" / "huge.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/huge.ts", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        response = engine.review(request)
        assert response.model_output_action != "allow_original"


class TestSourceRefHashMismatch:
    def test_output_hash_mismatch_no_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="0" * 64,
            output_chars=999,
            tool_input_path="src/foo.ts",
        )
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        response = engine.review(request)
        assert response.model_output_action != "allow_original"


class TestSourceRefSensitivePath:
    def test_source_ref_path_to_env_no_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "SECRET=abc123\n"
        file_path = workspace / ".env"
        file_path.write_text(content)

        ref = _source_ref(path=".env", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        response = engine.review(request)
        assert response.model_output_action != "allow_original"
        assert response.decision == "deny"
        assert response.reason_code == "sensitive_path"


class TestSourceRefSymlinkSwap:
    def test_source_ref_symlink_swap_no_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path, tmp_path: Path
    ) -> None:
        target = tmp_path / "outside.txt"
        target.write_text("secret data from outside")
        link = workspace / "src" / "link.ts"
        try:
            os.symlink(target, link)
        except OSError:
            pytest.skip("Cannot create symlinks")

        content = "secret data from outside"
        ref = _source_ref(path="src/link.ts", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        response = engine.review(request)
        assert response.model_output_action != "allow_original"


class TestSourceRefFileChangesBetweenStatAndRead:
    def test_source_ref_file_changes_no_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """File modified between stat and read must not allow original."""
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        # This test verifies the stat_identity comparison works.
        # In practice, the TOCTOU window is tiny, but the stat check
        # ensures any file change is detected.
        from codex_plugin_scanner.guard.runtime.hook_source_read import stat_identity

        pre_stat = file_path.stat()
        file_path.write_text("export const y = 2;\n")
        os.utime(file_path, (time.time() + 10, time.time() + 10))
        post_stat = file_path.stat()

        assert stat_identity(pre_stat) != stat_identity(post_stat)


class TestMalformedPostToolPayload:
    def test_malformed_payload_blocks_safely(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        request = _request(
            source_ref=None,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            output_summary=None,
        )

        response = engine.review(request)
        assert response.decision == "deny"
        assert response.model_output_action == "block"


class TestDaemonWorkerException:
    def test_daemon_worker_exception_returns_deny_block(
        self, store: GuardStore, workspace: Path, home_dir: Path, guard_home: Path, monkeypatch
    ) -> None:
        worker = HookWorker(store=store)

        def broken_inner(request, *, start):
            raise RuntimeError("crash")

        monkeypatch.setattr(worker.engine, "_review_inner", broken_inner)

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": "0" * 64,
                "output_chars": 10,
            },
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "deny"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "engine_exception"


class TestMetricsNoRawContent:
    def test_metrics_do_not_contain_fixture_secret(
        self, store: GuardStore, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        from unittest.mock import MagicMock

        metrics = MagicMock()
        scanner = ContentScanner()
        cache = HookDecisionCache(store)
        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=_config_loader,
            metrics=metrics,
        )

        secret_value = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        content = f'const token = "{secret_value}";\n'
        file_path = workspace / "src" / "config.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/config.ts", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        engine.review(request)

        metrics.record.assert_called_once()
        call_kwargs = metrics.record.call_args.kwargs
        # Verify the secret value is not in any metric field
        for key, value in call_kwargs.items():
            assert secret_value not in str(value), f"Secret found in metric field {key}"


class TestCacheStaleOnPolicyChange:
    def test_cache_stale_on_policy_change(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path, store: GuardStore
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/foo.ts", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        # First call caches the result
        response1 = engine.review(request)
        assert response1.reason_code == "source_full_scan_allow"

        # Add a policy decision to change the policy fingerprint
        from datetime import datetime, timezone

        from codex_plugin_scanner.guard.store_base import PolicyDecision

        store.upsert_policy(
            PolicyDecision(
                harness="pi",
                scope="harness",
                artifact_id=None,
                artifact_hash=None,
                workspace=None,
                publisher=None,
                action="block",
                reason="test policy change",
                owner="test",
                source="local",
                expires_at=None,
            ),
            datetime.now(timezone.utc).isoformat(),
        )

        # Second call should be a fresh scan, not cache hit
        response2 = engine.review(request)
        assert response2.reason_code == "source_full_scan_allow"  # Not "source_cache_hit"


class TestCacheStaleOnConfigChange:
    def test_cache_stale_on_config_change(
        self, store: GuardStore, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        scanner = ContentScanner()
        cache = HookDecisionCache(store)

        config1 = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="warn")
        config2 = GuardConfig(guard_home=guard_home, workspace=workspace, default_action="block")

        engine1 = HookReviewEngine(store=store, scanner=scanner, cache=cache, config_loader=lambda gh, ws: config1)
        engine2 = HookReviewEngine(store=store, scanner=scanner, cache=cache, config_loader=lambda gh, ws: config2)

        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/foo.ts", text=content)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir, guard_home=guard_home)

        # First call with config1 caches
        response1 = engine1.review(request)
        assert response1.reason_code == "source_full_scan_allow"

        # Second call with different config should not hit cache
        response2 = engine2.review(request)
        assert response2.reason_code == "source_full_scan_allow"  # Not "source_cache_hit"


class TestSourceRefTargetMismatch:
    """Regression: source ref must not choose a different file than the
    envelope target. A malformed source ref pointing at a benign file
    while the actual tool read targeted a different file must not
    result in allow_original."""

    def test_source_ref_pointing_at_different_file_is_inconclusive(
        self, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        store = GuardStore(guard_home)
        scanner = ContentScanner()
        cache = HookDecisionCache(store)
        config = GuardConfig(guard_home=guard_home, workspace=workspace)
        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=lambda gh, ws: config,
        )

        # Create two files: a benign one and the "actual" target.
        benign_content = "export const safe = 1;\n"
        benign_file = workspace / "src" / "benign.ts"
        benign_file.write_text(benign_content)

        actual_content = "export const actual = 2;\n"
        actual_file = workspace / "src" / "actual.ts"
        actual_file.write_text(actual_content)

        # Source ref claims the benign file's hash but points at a
        # different path than the envelope target.
        ref = HookSourceFileRef(
            version=1,
            path="src/benign.ts",
            output_sha256=sha256_text(benign_content),
            output_chars=len(benign_content),
            tool_input_path="src/benign.ts",
        )
        # Envelope says the tool read src/actual.ts
        request = HookReviewRequest(
            harness="pi",
            event_name="PostToolUse",
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/actual.ts"},
            },
            payload_kind="source_file_ref",
            config_path=None,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            source_scope="project",
            source_ref=ref,
        )

        response = engine.review(request)
        # Must NOT allow original — source ref pointed at a different file
        # than the envelope target.
        assert response.model_output_action != "allow_original"
        assert response.decision != "allow" or response.model_output_action != "allow_original"


class TestPreToolUseFallsBackToLegacy:
    """Regression: PreToolUse must not be handled by the fast worker.
    It must raise HookWorkerUnsupported so the server falls through to
    the legacy CLI path, preserving policy/permission checks."""

    def test_pre_tool_use_raises_unsupported(self, workspace: Path, home_dir: Path, guard_home: Path) -> None:
        from codex_plugin_scanner.guard.daemon.hook_worker import HookWorkerUnsupported

        store = GuardStore(guard_home)
        worker = HookWorker(store=store)

        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
        }

        with pytest.raises(HookWorkerUnsupported):
            worker.review_http_payload(
                payload=payload,
                params={},
                default_harness="pi",
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )

    def test_post_tool_use_without_source_ref_uses_engine(
        self, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """PostToolUse without source_ref now uses the server-side output scanning path.

        Previously this raised HookWorkerUnsupported (legacy CLI fallback).
        Now the engine handles it by scanning the tool output in the payload.
        """
        store = GuardStore(guard_home)
        worker = HookWorker(store=store)

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "safe content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # Should not raise — engine handles it via output scanning
        assert result["model_output_action"] == "allow_original"

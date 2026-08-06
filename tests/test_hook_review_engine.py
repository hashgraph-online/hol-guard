"""Tests for the hook review engine."""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookFailSafe, HookReviewEngine
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
    (ws / "docs").mkdir()
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
def scanner() -> ContentScanner:
    return ContentScanner()


@pytest.fixture()
def cache(store: GuardStore) -> HookDecisionCache:
    return HookDecisionCache(store)


@pytest.fixture()
def engine(store: GuardStore, scanner: ContentScanner, cache: HookDecisionCache) -> HookReviewEngine:
    return HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=_config_loader,
    )


def _source_ref(*, path: str = "src/foo.ts", text: str = "export const x = 1;\n") -> HookSourceFileRef:
    stripped = text.rstrip("\n")
    return HookSourceFileRef(
        version=1,
        path=path,
        output_sha256=sha256_text(stripped),
        output_chars=len(stripped),
        tool_input_path=path,
    )


def _request(
    *,
    source_ref: HookSourceFileRef | None = None,
    event_name: str = "PostToolUse",
    payload: dict[str, object] | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
    output_summary: HookOutputSummary | None = None,
    tool_input_path: str | None = None,
) -> HookReviewRequest:
    if payload is None and source_ref is not None:
        payload = {
            "hook_event_name": event_name,
            "tool_name": "Read",
            "tool_input": {"file_path": tool_input_path or source_ref.path},
        }
    return HookReviewRequest(
        harness="pi",
        event_name=event_name,
        payload=payload or {},
        payload_kind="source_file_ref" if source_ref else "inline",
        config_path=None,
        cwd=cwd or Path("/workspace"),
        home_dir=home_dir or Path("/home"),
        guard_home=guard_home or Path("/guard"),
        source_scope="project",
        source_ref=source_ref,
        output_summary=output_summary,
    )


def test_inline_scan_honors_outer_daemon_deadline(
    engine: HookReviewEngine,
    scanner: ContentScanner,
    workspace: Path,
    home_dir: Path,
    guard_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_deadlines: list[float | None] = []
    original_scan_text = scanner.scan_text

    def capture_deadline(
        text: str,
        *,
        local_content: bool,
        source_context: bool,
        max_bytes: int,
        deadline_monotonic: float | None,
    ):
        observed_deadlines.append(deadline_monotonic)
        return original_scan_text(
            text,
            local_content=local_content,
            source_context=source_context,
            max_bytes=max_bytes,
            deadline_monotonic=deadline_monotonic,
        )

    monkeypatch.setattr(scanner, "scan_text", capture_deadline)
    outer_deadline = time.monotonic() + 1
    base_request = _request(
        payload={"hook_event_name": "PostToolUse", "tool_response": "routine output"},
        cwd=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
    )
    request = replace(base_request, deadline_monotonic=outer_deadline)
    response = engine.review(request)

    assert response.decision == "allow"
    assert observed_deadlines
    assert all(deadline is not None and deadline <= outer_deadline for deadline in observed_deadlines)


class TestSafeSourceRefAllowOriginal:
    def test_safe_source_ref_returns_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/foo.ts", text=content)
        request = _request(
            source_ref=ref,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

        response = engine.review(request)
        assert response.decision == "allow"
        assert response.model_output_action == "allow_original"
        assert response.reviewed_output_sha256 is not None
        assert response.notice == "none"
        assert response.reason_code == "source_full_scan_allow"


class TestSourceRefMismatch:
    def test_source_ref_mismatch_returns_excerpt_or_deny_not_allow_original(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        # Claim a wrong hash
        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="0" * 64,
            output_chars=999,
            tool_input_path="src/foo.ts",
        )
        request = _request(
            source_ref=ref,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            output_summary=HookOutputSummary(
                text_excerpt="export const x = 1;",
                excerpt_truncated=False,
                output_sha256=None,
                output_chars=None,
            ),
        )

        response = engine.review(request)
        assert response.model_output_action != "allow_original"

    @pytest.mark.parametrize("path", ["skill://routine-workflow", "/external/docs/release.md"])
    def test_unverifiable_read_scans_available_pi_stdout(
        self,
        engine: HookReviewEngine,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
        path: str,
    ) -> None:
        text = "Routine local instructions with no sensitive values."
        request = _request(
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"path": path},
                "stdout": text,
            },
            output_summary=HookOutputSummary(
                text_excerpt="",
                excerpt_truncated=False,
                output_sha256=sha256_text(text),
                output_chars=len(text),
            ),
        )

        response = engine.review(request)

        assert response.decision == "allow"
        assert response.model_output_action == "allow_original"
        assert response.reason_code == "output_scan_allow"

    def test_inconclusive_source_ref_still_blocks_secret_in_pi_stdout(
        self,
        engine: HookReviewEngine,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        text = "token=ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        path = "skill://private-instructions"
        request = _request(
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"path": path},
                "stdout": text,
            },
            output_summary=HookOutputSummary(
                text_excerpt="",
                excerpt_truncated=False,
                output_sha256=sha256_text(text),
                output_chars=len(text),
            ),
        )

        response = engine.review(request)

        assert response.decision == "deny"
        assert response.model_output_action == "block"
        assert response.reason_code == "output_secret_match"

    def test_inconclusive_truncated_source_ref_never_allows_original(
        self,
        engine: HookReviewEngine,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        text = "Reviewed safe excerpt"
        path = "skill://large-instructions"
        request = _request(
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"path": path},
                "stdout": text,
            },
            output_summary=HookOutputSummary(
                text_excerpt=text,
                excerpt_truncated=True,
                output_sha256=None,
                output_chars=len(text) + 1,
            ),
        )

        response = engine.review(request)

        assert response.decision == "allow"
        assert response.model_output_action == "replace_with_reviewed_excerpt"
        assert response.reviewed_excerpt == text


class TestSecretSourceFile:
    def test_secret_source_file_returns_deny_block(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\n'
        file_path = workspace / "src" / "config.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = HookSourceFileRef(
            version=1,
            path="src/config.ts",
            output_sha256=sha256_text(stripped),
            output_chars=len(stripped),
            tool_input_path="src/config.ts",
        )
        request = _request(
            source_ref=ref,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

        response = engine.review(request)
        assert response.decision == "deny"
        assert response.model_output_action == "block"
        assert response.reason_code == "source_secret_match"


class TestSensitivePath:
    def test_env_path_returns_deny_block(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "SECRET=abc123\n"
        file_path = workspace / ".env"
        file_path.write_text(content)

        ref = _source_ref(path=".env", text=content)
        request = _request(
            source_ref=ref,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

        response = engine.review(request)
        assert response.decision == "deny"
        assert response.model_output_action == "block"
        assert response.reason_code == "sensitive_path"


class TestNonPostToolEvents:
    def test_pre_tool_use_returns_not_applicable(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        request = _request(
            event_name="PreToolUse",
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            payload={"hook_event_name": "PreToolUse", "tool_name": "Read"},
        )

        response = engine.review(request)
        assert response.model_output_action == "not_applicable"
        assert response.decision == "allow"


class TestEngineException:
    def test_engine_exception_returns_deny_block(
        self,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        def broken_config_loader(guard_home: Path, workspace: Path | None) -> GuardConfig:
            raise RuntimeError("config loading failed")

        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=broken_config_loader,
        )

        request = _request(
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

        response = engine.review(request)
        assert response.decision == "deny"
        assert response.model_output_action == "block"
        assert response.reason_code == "engine_exception"

    def test_engine_exception_records_sanitized_failure(
        self,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        metrics = MagicMock()

        def broken_config_loader(_guard_home: Path, _workspace: Path | None) -> GuardConfig:
            raise RuntimeError("sensitive details")

        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=broken_config_loader,
            metrics=metrics,
        )

        engine.review(_request(cwd=workspace, home_dir=home_dir, guard_home=guard_home))

        metrics.record_failure.assert_called_once_with(stage="engine", exception_type="RuntimeError")
        assert "sensitive details" not in str(metrics.mock_calls)


class TestScannerBudgetExhaustion:
    def test_scanner_budget_exhaustion_returns_excerpt_or_deny(
        self, engine: HookReviewEngine, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        # Create a large file that will exhaust the scanner budget
        content = "x" * (5 * 1024 * 1024 + 1) + "\n"
        file_path = workspace / "src" / "large.ts"
        file_path.write_text(content)

        # This should be inconclusive due to file size limit
        stripped = content.rstrip("\n")
        ref = HookSourceFileRef(
            version=1,
            path="src/large.ts",
            output_sha256=sha256_text(stripped),
            output_chars=len(stripped),
            tool_input_path="src/large.ts",
        )
        request = _request(
            source_ref=ref,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            output_summary=HookOutputSummary(
                text_excerpt=content[:12000],
                excerpt_truncated=True,
                output_sha256=sha256_text(stripped),
                output_chars=len(stripped),
            ),
        )

        response = engine.review(request)
        # File too large -> inconclusive -> falls to standard path
        # Standard path scans excerpt, which is safe, but can't prove full
        assert response.model_output_action != "allow_original"

    def test_scanner_receives_its_budget_after_slow_config_load(
        self,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        def slow_config_loader(guard_home: Path, workspace: Path | None) -> GuardConfig:
            time.sleep(0.8)
            return _config_loader(guard_home, workspace)

        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=slow_config_loader,
        )
        request = _request(
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_output": "routine documentation",
            },
        )

        response = engine.review(request)

        assert response.decision == "allow"
        assert response.reason_code == "output_scan_allow"

    def test_source_scanner_receives_its_budget_after_slow_config_load(
        self,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        content = "Routine local documentation.\n"
        source_path = workspace / "docs" / "routine.md"
        source_path.write_text(content)

        def slow_config_loader(guard_home: Path, workspace: Path | None) -> GuardConfig:
            time.sleep(0.3)
            return _config_loader(guard_home, workspace)

        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=slow_config_loader,
        )
        response = engine.review(
            _request(
                source_ref=_source_ref(path="docs/routine.md", text=content),
                cwd=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
            )
        )

        assert response.decision == "allow"
        assert response.reason_code == "source_full_scan_allow"


class TestMetricsExcludesRawContent:
    def test_metrics_payload_excludes_raw_content(
        self,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        workspace: Path,
        home_dir: Path,
        guard_home: Path,
    ) -> None:
        metrics = MagicMock()
        engine = HookReviewEngine(
            store=store,
            scanner=scanner,
            cache=cache,
            config_loader=_config_loader,
            metrics=metrics,
        )

        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        ref = _source_ref(path="src/foo.ts", text=content)
        request = _request(
            source_ref=ref,
            cwd=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )

        engine.review(request)

        # Verify metrics.record was called
        metrics.record.assert_called_once()
        call_kwargs = metrics.record.call_args.kwargs
        assert call_kwargs["decision"] == "allow"
        assert call_kwargs["reason_code"] == "source_full_scan_allow"
        assert call_kwargs["model_output_action"] == "allow_original"
        # Verify no raw content fields
        for key in call_kwargs:
            assert "raw" not in key.lower()
            assert "content" not in key.lower() or key == "output_size"
            assert "secret" not in key.lower()
            assert "prompt" not in key.lower()


class TestHookFailSafe:
    def test_fail_safe_with_excerpt_returns_allow_excerpt(self) -> None:
        error = HookFailSafe(
            "test_reason",
            "test reason",
            excerpt="safe excerpt",
        )
        response = error.to_response()
        assert response.decision == "allow"
        assert response.model_output_action == "replace_with_reviewed_excerpt"
        assert response.reviewed_excerpt == "safe excerpt"
        assert response.notice == "excerpt"

    def test_fail_safe_without_excerpt_returns_deny_block(self) -> None:
        error = HookFailSafe("test_reason", "test reason")
        response = error.to_response()
        assert response.decision == "deny"
        assert response.model_output_action == "block"
        assert response.notice == "warning"

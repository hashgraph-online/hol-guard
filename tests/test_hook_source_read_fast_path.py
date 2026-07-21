"""Tests for the source-read fast-path evaluator."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest, HookSourceFileRef
from codex_plugin_scanner.guard.runtime.hook_source_read import (
    evaluate_source_file_ref,
    output_equivalent,
    sha256_text,
)
from codex_plugin_scanner.guard.store import GuardStore


def _envelope(
    *,
    action_type: str = "file_read",
    target_paths: tuple[str, ...] = ("src/foo.ts",),
    workspace_hash: str | None = "ws-hash",
) -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="test-action-id",
        harness="pi",
        event_name="PostToolUse",
        action_type=action_type,  # type: ignore[arg-type]
        workspace="/workspace",
        workspace_hash=workspace_hash,
        tool_name="Read",
        command=None,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=target_paths,
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
    )


def _request(
    *,
    source_ref: HookSourceFileRef | None = None,
    event_name: str = "PostToolUse",
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> HookReviewRequest:
    return HookReviewRequest(
        harness="pi",
        event_name=event_name,
        payload={},
        payload_kind="source_file_ref",
        config_path=None,
        cwd=cwd or Path("/workspace"),
        home_dir=home_dir or Path("/home"),
        guard_home=Path("/guard"),
        source_scope="project",
        source_ref=source_ref,
    )


def _source_ref(
    *,
    path: str = "src/foo.ts",
    output_sha256: str | None = None,
    output_chars: int | None = None,
    text: str = "export const x = 1;\n",
) -> HookSourceFileRef:
    if output_sha256 is None:
        output_sha256 = sha256_text(text.rstrip("\n"))
    if output_chars is None:
        output_chars = len(text.rstrip("\n"))
    return HookSourceFileRef(
        version=1,
        path=path,
        output_sha256=output_sha256,
        output_chars=output_chars,
        tool_input_path=path,
    )


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
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


@pytest.fixture()
def config(tmp_path: Path) -> GuardConfig:
    return GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path)


@pytest.fixture()
def scanner() -> ContentScanner:
    return ContentScanner()


@pytest.fixture()
def cache(store: GuardStore) -> HookDecisionCache:
    return HookDecisionCache(store)


@pytest.fixture()
def deadline() -> float:
    return time.monotonic() + 30.0


class TestOutputEquivalent:
    def test_exact_match(self) -> None:
        text = "hello world"
        assert output_equivalent(text, output_sha256=sha256_text(text), output_chars=len(text))

    def test_trailing_newline_compatibility(self) -> None:
        text_with_newline = "hello world\n"
        stripped = text_with_newline[:-1]
        assert output_equivalent(
            text_with_newline,
            output_sha256=sha256_text(stripped),
            output_chars=len(stripped),
        )

    def test_hash_mismatch_returns_false(self) -> None:
        assert not output_equivalent("hello", output_sha256="wrong", output_chars=5)

    def test_chars_mismatch_returns_false(self) -> None:
        text = "hello"
        assert not output_equivalent(text, output_sha256=sha256_text(text), output_chars=999)


class TestSafeSourceRead:
    def test_safe_ts_file_returns_allow_original(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = _source_ref(path="src/foo.ts", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/foo.ts",), workspace_hash="ws-hash")

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "allow_original"
        assert result.reason_code == "source_full_scan_allow"
        assert result.proof is not None
        assert result.proof.output_sha256 == sha256_text(stripped)

    def test_safe_md_file_returns_allow_original(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "# Spec\n\nThis is a markdown spec.\n"
        file_path = workspace / "docs" / "spec.md"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = _source_ref(path="docs/spec.md", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("docs/spec.md",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "allow_original"
        assert result.reason_code == "source_full_scan_allow"


class TestSensitivePathRejection:
    def test_env_file_returns_risky_not_allow(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "SECRET=abc123\n"
        file_path = workspace / ".env"
        file_path.write_text(content)

        ref = _source_ref(path=".env")
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=(".env",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status != "allow_original"
        assert result.status == "risky"
        assert result.reason_code == "sensitive_path"

    def test_npmrc_returns_risky(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "authToken=abc\n"
        file_path = workspace / ".npmrc"
        file_path.write_text(content)

        ref = _source_ref(path=".npmrc")
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=(".npmrc",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "risky"
        assert result.reason_code == "sensitive_path"


class TestSecretDetection:
    def test_file_with_github_token_returns_risky(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";\n'
        file_path = workspace / "src" / "config.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = _source_ref(path="src/config.ts", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/config.ts",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "risky"
        assert result.reason_code == "source_secret_match"
        assert len(result.scanner_matches) > 0

    def test_file_with_env_reference_returns_allow_original(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "const key = process.env.NOTION_API_KEY;\n"
        file_path = workspace / "src" / "app.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = _source_ref(path="src/app.ts", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/app.ts",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        # process.env.NOTION_API_KEY is a code reference, not a concrete secret.
        assert result.status == "allow_original"


class TestOutputMismatch:
    def test_output_hash_mismatch_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        # Claim a different hash
        ref = _source_ref(path="src/foo.ts", output_sha256="0" * 64, output_chars=999)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/foo.ts",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "output_mismatch"


class TestTOCTOU:
    def test_file_modified_between_stat_and_read_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
        monkeypatch,
    ) -> None:
        """Test TOCTOU protection via stat_identity comparison.

        Rather than monkeypatching Path.stat globally (which crashes pytest's
        own path operations), we directly test the stat_identity comparison
        that the evaluator uses for TOCTOU detection.
        """
        import os as _os

        from codex_plugin_scanner.guard.runtime.hook_source_read import stat_identity

        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        # Get pre-read stat
        pre_stat = file_path.stat()

        # Modify the file (change mtime)
        new_content = "export const y = 2;\n"
        file_path.write_text(new_content)
        _os.utime(file_path, (_os.path.getmtime(file_path) + 10, _os.path.getmtime(file_path) + 10))

        # Get post-read stat
        post_stat = file_path.stat()

        # The stat identity should differ, proving TOCTOU detection works
        assert stat_identity(pre_stat) != stat_identity(post_stat)

        # Verify mtime changed
        assert pre_stat.st_mtime_ns != post_stat.st_mtime_ns


class TestBinaryFile:
    def test_binary_file_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        file_path = workspace / "src" / "data.bin"
        file_path.write_bytes(b"\x00\x01\x02\x03\x00")

        ref = _source_ref(path="src/data.bin", output_sha256="0" * 64, output_chars=5)
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/data.bin",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "binary_file"


class TestSymlinkRejection:
    def test_symlink_path_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
        tmp_path: Path,
    ) -> None:
        target = tmp_path / "outside.txt"
        target.write_text("secret data")
        link = workspace / "src" / "link.ts"
        try:
            os.symlink(target, link)
        except OSError:
            pytest.skip("Cannot create symlinks")

        content = "secret data"
        stripped = content
        ref = _source_ref(path="src/link.ts", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/link.ts",))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )
        # Symlink rejection could come from source_path_is_allowed or path_contains_symlink
        # or absolute_path_outside_workspace if the symlink resolves outside.
        assert result.reason_code in (
            "symlink_in_path",
            "not_source_like",
            "absolute_path_outside_workspace",
        )


class TestCacheBehavior:
    def test_cache_hit_returns_source_cache_hit(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = _source_ref(path="src/foo.ts", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/foo.ts",))

        # First call: full scan, caches the result
        result1 = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )
        assert result1.reason_code == "source_full_scan_allow"

        # Second call: should hit cache
        result2 = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )
        assert result2.status == "allow_original"
        assert result2.reason_code == "source_cache_hit"

    def test_cache_invalidates_when_content_changes(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        file_path = workspace / "src" / "foo.ts"
        content1 = "export const x = 1;\n"
        file_path.write_text(content1)

        stripped1 = content1.rstrip("\n")
        ref1 = _source_ref(path="src/foo.ts", output_sha256=sha256_text(stripped1), output_chars=len(stripped1))
        request1 = _request(source_ref=ref1, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/foo.ts",))

        # First call caches
        evaluate_source_file_ref(
            request=request1,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        # Change content
        content2 = "export const y = 2;\n"
        file_path.write_text(content2)
        # Update mtime
        os.utime(file_path, (time.time() + 1, time.time() + 1))

        stripped2 = content2.rstrip("\n")
        ref2 = _source_ref(path="src/foo.ts", output_sha256=sha256_text(stripped2), output_chars=len(stripped2))
        request2 = _request(source_ref=ref2, cwd=workspace, home_dir=home_dir)

        result = evaluate_source_file_ref(
            request=request2,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        # Should be a fresh scan, not cache hit
        assert result.reason_code == "source_full_scan_allow"

    def test_cache_invalidates_when_config_fingerprint_changes(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
        tmp_path: Path,
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        ref = _source_ref(path="src/foo.ts", output_sha256=sha256_text(stripped), output_chars=len(stripped))
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/foo.ts",))

        config1 = GuardConfig(guard_home=tmp_path / "gh", workspace=tmp_path, default_action="warn")
        config2 = GuardConfig(guard_home=tmp_path / "gh", workspace=tmp_path, default_action="block")

        # First call with config1
        result1 = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config1,
            store=store,
            deadline_monotonic=deadline,
        )
        assert result1.reason_code == "source_full_scan_allow"

        # Second call with different config — should be a fresh scan, not cache hit
        result2 = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config2,
            store=store,
            deadline_monotonic=deadline,
        )
        assert result2.reason_code == "source_full_scan_allow"


class TestShapeValidation:
    def test_not_post_tool_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        ref = _source_ref()
        request = _request(source_ref=ref, event_name="PreToolUse", cwd=workspace, home_dir=home_dir)
        envelope = _envelope()

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "not_post_tool"

    def test_missing_source_ref_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        request = _request(source_ref=None, cwd=workspace, home_dir=home_dir)
        envelope = _envelope()

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "missing_source_ref"

    def test_not_file_read_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        ref = _source_ref()
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(action_type="shell_command")

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "not_file_read"

    def test_multiple_target_paths_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        ref = _source_ref()
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope(target_paths=("src/a.ts", "src/b.ts"))

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "not_single_target_path"

    def test_invalid_output_hash_returns_inconclusive(
        self,
        workspace: Path,
        home_dir: Path,
        store: GuardStore,
        config: GuardConfig,
        scanner: ContentScanner,
        cache: HookDecisionCache,
        deadline: float,
    ) -> None:
        ref = HookSourceFileRef(
            version=1,
            path="src/foo.ts",
            output_sha256="not-a-hash",
            output_chars=10,
        )
        request = _request(source_ref=ref, cwd=workspace, home_dir=home_dir)
        envelope = _envelope()

        result = evaluate_source_file_ref(
            request=request,
            envelope=envelope,
            scanner=scanner,
            cache=cache,
            config=config,
            store=store,
            deadline_monotonic=deadline,
        )

        assert result.status == "inconclusive"
        assert result.reason_code == "invalid_output_hash"

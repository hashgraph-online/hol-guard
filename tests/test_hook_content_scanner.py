"""Tests for the deterministic streaming content scanner."""

from __future__ import annotations

import time

import pytest

from codex_plugin_scanner.guard.runtime.hook_content_scanner import (
    HOOK_CONTENT_SCANNER_VERSION,
    ContentScanner,
    should_unsuppress_local_sample_secrets,
    should_unsuppress_local_sample_secrets_for_paths,
)
from codex_plugin_scanner.guard.runtime.secret_sensitivity import secret_content_rule_version


@pytest.fixture()
def scanner() -> ContentScanner:
    return ContentScanner()


class TestScannerVersion:
    def test_version_includes_wrapper_and_rule_hash(self, scanner: ContentScanner) -> None:
        expected_prefix = f"{HOOK_CONTENT_SCANNER_VERSION}:"
        assert scanner.version.startswith(expected_prefix)
        rule_hash = scanner.version[len(expected_prefix) :]
        assert len(rule_hash) == 64
        assert all(c in "0123456789abcdef" for c in rule_hash)

    def test_version_matches_rule_version(self, scanner: ContentScanner) -> None:
        rule_hash = scanner.version.split(":", 1)[1]
        assert rule_hash == secret_content_rule_version()


class TestDetectSecrets:
    def test_detect_github_token_single_chunk(self, scanner: ContentScanner) -> None:
        text = "export TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = scanner.scan_text(text, local_content=False, source_context=False)
        assert result.reason_code in ("secret_match_early_exit", "matches")
        assert any(m.classifier == "github-token" for m in result.matches)
        assert result.budget_exhausted is False

    def test_detect_openai_key_in_later_chunk(self, scanner: ContentScanner) -> None:
        chunks = ["hello world\n", "some code\n", "sk-proj-abcdefghijklmnopqrstuvwxyz1234"]
        result = scanner.scan_chunks(chunks, local_content=False, source_context=False)
        assert any(m.classifier == "openai-api-key" for m in result.matches)
        assert result.chunks_scanned == 3

    def test_detect_token_split_across_chunk_boundary(self, scanner: ContentScanner) -> None:
        # Split a GitHub token across two chunks at a point where the
        # rolling context window should catch it.
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        mid = len(token) // 2
        chunks = [f"export TOKEN={token[:mid]}", f"{token[mid:]}\n"]
        result = scanner.scan_chunks(chunks, local_content=False, source_context=False)
        assert any(m.classifier == "github-token" for m in result.matches)

    def test_no_secrets_returns_clean(self, scanner: ContentScanner) -> None:
        text = "const x = 42;\nfunction foo() { return x; }\n"
        result = scanner.scan_text(text, local_content=False, source_context=False)
        assert result.reason_code == "clean"
        assert result.matches == ()
        assert result.budget_exhausted is False

    def test_early_exit_on_critical_pem_key(self, scanner: ContentScanner) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
        result = scanner.scan_text(text, local_content=False, source_context=False)
        assert result.reason_code == "secret_match_early_exit"
        assert any(m.sensitivity == "critical" for m in result.matches)

    def test_local_content_unsuppresses_sample_assignments(self, scanner: ContentScanner) -> None:
        # A credential assignment that looks like a sample should be
        # suppressed when suppress_samples=True but found when local_content
        # triggers the unsuppressed retry.
        text = 'api_key = "test-example-value-here"'
        result = scanner.scan_text(text, local_content=True, source_context=False)
        assert any(m.classifier == "credential-assignment" for m in result.matches)

    def test_no_local_content_suppresses_sample_assignments(self, scanner: ContentScanner) -> None:
        text = 'api_key = "test-example-value-here"'
        result = scanner.scan_text(text, local_content=False, source_context=False)
        # Should not detect because it looks like a sample.
        assert all(m.classifier != "credential-assignment" for m in result.matches)


class TestScanContext:
    @pytest.mark.parametrize(
        "path",
        [
            "docs/security-review.md",
            "tests/test_guard_hook_worker.py",
            "fixtures/security/addendum.txt",
            "examples/policy.mdx",
        ],
    )
    def test_docs_and_fixtures_suppress_sample_assignment_retry(self, path: str) -> None:
        assert should_unsuppress_local_sample_secrets(path) is False

    @pytest.mark.parametrize("path", ["src/config.ts", "app/settings.py", None])
    def test_source_paths_keep_local_sample_assignment_retry(self, path: str | None) -> None:
        assert should_unsuppress_local_sample_secrets(path) is True

    def test_absolute_paths_are_relativized_to_workspace(self) -> None:
        cwd = "/Users/john/docs/project"
        assert should_unsuppress_local_sample_secrets("/Users/john/docs/project/src/config.py", cwd=cwd) is True
        assert should_unsuppress_local_sample_secrets("/Users/john/docs/project/docs/review.md", cwd=cwd) is False

    def test_absolute_paths_outside_workspace_ignore_parent_segments(self) -> None:
        assert should_unsuppress_local_sample_secrets("/Users/john/docs/project/src/config.py") is True

    def test_mixed_targets_keep_sample_assignment_retry(self) -> None:
        paths = ("docs/security-review.md", "src/config.py")
        assert should_unsuppress_local_sample_secrets_for_paths(paths, cwd="/repo") is True

    def test_all_docs_targets_suppress_sample_assignment_retry(self) -> None:
        paths = ("docs/security-review.md", "tests/test_guard_hook_worker.py")
        assert should_unsuppress_local_sample_secrets_for_paths(paths, cwd="/repo") is False


class TestBudgetExhaustion:
    def test_max_bytes_exhaustion_returns_budget_exhausted(self, scanner: ContentScanner) -> None:
        text = "x" * 100_000
        result = scanner.scan_text(text, local_content=False, source_context=False, max_bytes=1000)
        assert result.budget_exhausted is True
        assert result.reason_code == "max_bytes_exceeded"

    def test_deadline_exhaustion_returns_budget_exhausted(self, scanner: ContentScanner) -> None:
        # Set deadline in the past.
        deadline = time.monotonic() - 1.0
        result = scanner.scan_text(
            "some text",
            local_content=False,
            source_context=False,
            deadline_monotonic=deadline,
        )
        assert result.budget_exhausted is True
        assert result.reason_code == "deadline_exceeded"

    def test_max_bytes_zero_returns_immediately(self, scanner: ContentScanner) -> None:
        result = scanner.scan_text("hello", local_content=False, source_context=False, max_bytes=0)
        assert result.budget_exhausted is True
        assert result.reason_code == "max_bytes_exceeded"
        assert result.bytes_scanned == 0

    def test_bytes_scanned_tracks_utf8(self, scanner: ContentScanner) -> None:
        text = "héllo wörld"  # Multi-byte UTF-8
        result = scanner.scan_text(text, local_content=False, source_context=False)
        assert result.bytes_scanned == len(text.encode("utf-8"))


class TestNoSecretSamplesInResult:
    def test_result_never_contains_secret_sample_text(self, scanner: ContentScanner) -> None:
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        text = f"export TOKEN={token}\nmore text here"
        result = scanner.scan_text(text, local_content=False, source_context=False)
        # The match objects should only have classifier/family/sensitivity/reason.
        for match in result.matches:
            assert not any(
                getattr(match, attr) and token in str(getattr(match, attr))
                for attr in ("classifier", "family", "sensitivity", "reason")
            )

    def test_reason_field_is_generic(self, scanner: ContentScanner) -> None:
        text = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = scanner.scan_text(text, local_content=False, source_context=False)
        for match in result.matches:
            assert "Guard found" in match.reason or match.reason
            # The reason should be the generic pattern description, not the token.
            assert "ghp_" not in match.reason


class TestNonStringChunks:
    def test_non_string_chunks_are_skipped(self, scanner: ContentScanner) -> None:
        chunks: list[object] = ["hello", 123, None, "world"]
        result = scanner.scan_chunks(chunks, local_content=False, source_context=False)  # type: ignore[arg-type]
        assert result.chunks_scanned == 2  # Only the two str chunks
        assert result.reason_code == "clean"

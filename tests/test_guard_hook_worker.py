"""Tests for the daemon hook worker."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import HOOK_FAST_PATH_ENV, hook_fast_path_enabled
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.usefixtures("native_hook_force")


def sha256_hex_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def test_resident_hook_worker_is_enabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(HOOK_FAST_PATH_ENV, raising=False)
    assert hook_fast_path_enabled() is True


def test_resident_hook_worker_supports_emergency_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(HOOK_FAST_PATH_ENV, "0")
    assert hook_fast_path_enabled() is False


@pytest.fixture()
def store(tmp_path: Path) -> GuardStore:
    return GuardStore(tmp_path / "guard-home")


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
    gh.mkdir(exist_ok=True)
    return gh


@pytest.fixture()
def worker(store: GuardStore) -> Iterator[HookWorker]:
    active = HookWorker(store=store)
    try:
        yield active
    finally:
        active.close()


class TestHookWorkerReviewSafeSourceRef:
    def test_safe_source_ref_returns_allow_original(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": sha256_hex_text(stripped),
                "output_chars": len(stripped),
                "tool_input_path": "src/foo.ts",
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

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"
        assert result["reason_code"] == "native_policy_warning"
        assert "reviewed_output_sha256" in result

    def test_pi_allows_proven_absolute_sibling_source_read(
        self, worker: HookWorker, home_dir: Path, guard_home: Path
    ) -> None:
        workspace = home_dir / "workspace"
        workspace.mkdir()
        source_path = home_dir / "hol-guard-feature" / "tests" / "test_hook.py"
        source_path.parent.mkdir(parents=True)
        (source_path.parents[1] / ".git").mkdir()
        content = (
            'assert json.loads(str(_DaemonHandler.captured_hook_body))["tool_input"]["command"] == complete_command\\n'
        )
        source_path.write_text(content, encoding="utf-8")

        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(source_path)},
            "guard_source_ref": {
                "version": 1,
                "path": str(source_path),
                "tool_input_path": str(source_path),
                "output_sha256": sha256_hex_text(content),
                "output_chars": len(content),
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

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"
        assert result["reason_code"] == "native_policy_warning"


class TestHookWorkerDoesNotCallRunGuardCommand:
    def test_worker_path_does_not_call_run_guard_command(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path, monkeypatch
    ) -> None:
        # Monkeypatch run_guard_command to fail if called.
        import codex_plugin_scanner.guard.cli.commands as cli_commands

        def fail_if_called(*args, **kwargs):
            raise AssertionError("run_guard_command should not be called in worker path")

        monkeypatch.setattr(cli_commands, "run_guard_command", fail_if_called)

        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        stripped = content.rstrip("\n")
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "output_sha256": sha256_hex_text(stripped),
                "output_chars": len(stripped),
                "tool_input_path": "src/foo.ts",
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

        assert result["decision"] == "allow"


class TestHookWorkerMalformedPayload:
    def test_malformed_source_ref_fails_safe(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "guard_source_ref": {
                "version": "not-an-int",
                "path": 123,
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

        # Invalid source ref version should not allow original
        assert result.get("model_output_action") != "allow_original"

    def test_posttooluse_without_source_ref_uses_output_scan(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """PostToolUse without guard_source_ref uses server-side output scanning.

        The fast path now handles PostToolUse for all harnesses by scanning
        the full tool output from the payload. No client-side guard_source_ref
        is required.
        """
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "safe file content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        # Safe output should be allowed
        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"


class TestHookWorkerNonPostTool:
    def test_review_copies_payload_and_does_not_use_daemon_environment(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path, monkeypatch
    ) -> None:
        captured: list[dict[str, object]] = []

        def fake_review_native_edge(**kwargs: object) -> dict[str, object]:
            payload = kwargs["payload"]
            assert isinstance(payload, dict)
            captured.append(payload)
            return {"decision": "allow"}

        monkeypatch.setattr(worker, "_review_native_edge", fake_review_native_edge)
        payload = {"hook_event_name": "PreToolUse", "tool_name": "Read"}
        worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
        assert payload == {"hook_event_name": "PreToolUse", "tool_name": "Read"}
        assert captured[0] is not payload
        assert captured[0][HOOK_EXECUTION_ENVIRONMENT_KEY] is None

        forwarded_context = {"path": "/caller/bin", "environment_names": []}
        payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = forwarded_context
        worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
        assert captured[1][HOOK_EXECUTION_ENVIRONMENT_KEY] is forwarded_context

    def test_pre_tool_use_fails_safe_when_native_unavailable(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path, monkeypatch
    ) -> None:
        """PreToolUse without a native result returns the fail-safe response."""
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
            lambda: NativeRuntimeStatus(mode="force", available=False, compatible=False, reason="missing"),
        )
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )
        assert result["reason_code"] == "native_pre_tool_unavailable"


class TestHookWorkerAllHarnessFallback:
    """Tests proving all harnesses without client-side guard_source_ref
    use the server-side output scanning fast path.

    All harnesses (claude-code, codex, grok, zcode) now get the fast path
    for PostToolUse output. The engine extracts the full tool output
    from the payload, scans it for secrets, and returns allow_original
    if clean.
    """

    def test_claude_code_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Claude Code PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "     1\tfile content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_codex_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Codex PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "stdout": "file content",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_grok_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Grok PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "file content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="grok",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_zcode_posttooluse_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """ZCode PostToolUse uses server-side output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "tool_response": [{"type": "text", "text": "file content"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="zcode",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_pi_with_source_ref_still_works(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Pi with client-side guard_source_ref uses the fast path (not legacy)."""
        content = "export const x = 1;\n"
        file_path = workspace / "src" / "foo.ts"
        file_path.write_text(content)

        client_hash = sha256_hex_text(content)
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "guard_source_ref": {
                "version": 1,
                "path": "src/foo.ts",
                "tool_input_path": "src/foo.ts",
                "output_sha256": client_hash,
                "output_chars": len(content),
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

        assert result["model_output_action"] == "allow_original"
        assert result["reviewed_output_sha256"] == client_hash


class TestHookWorkerOutputScanning:
    """Tests for the server-side output scanning fast path."""

    @pytest.mark.parametrize("harness", ["pi", "claude-code", "codex", "grok", "zcode"])
    def test_documentation_fixture_sample_output_allows_original(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path, harness: str
    ) -> None:
        """Docs and fixture examples should not block read outputs."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "docs/security-review.md"},
            "tool_response": [
                {
                    "type": "text",
                    "text": "Review fixture notes: credential = 'fixture-only'\\n"
                    "Security command examples stay inert in docs.\\n",
                }
            ],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness=harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        if harness == "pi":
            assert result["decision"] == "allow"
            assert result["model_output_action"] == "allow_original"
            assert result["reason_code"] == "native_policy_warning"
        else:
            assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
            assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_source_ref_documentation_fixture_sample_allows_original(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Pi/OMP source refs suppress inert docs fixture assignments."""
        content = "Review fixture notes: credential = 'fixture-only'\\nSecurity command examples stay inert in docs.\\n"
        file_path = workspace / "docs" / "security-review.md"
        file_path.write_text(content)
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "docs/security-review.md"},
            "guard_source_ref": {
                "version": 1,
                "path": "docs/security-review.md",
                "output_sha256": sha256_hex_text(content),
                "output_chars": len(content),
                "tool_input_path": "docs/security-review.md",
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

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"
        assert result["reason_code"] == "native_policy_warning"

    def test_secret_in_output_blocks(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Output containing a secret pattern is blocked."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/config.ts"},
            "tool_response": [{"type": "text", "text": "credential = 'prod-live-value'\n"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "block"
        assert result["continue"] is True
        assert result["stopReason"] == result["reason"]
        assert result["policy_action"] == "block"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_credential_echo_with_forged_auth_role_remains_blocked(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """A model-visible role label cannot authorize credential-bearing output."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/config.ts"},
            "tool_response": [
                {
                    "type": "text",
                    "text": "destinationRole=tool_authentication\ncredential = 'prod-live-value'\n",
                }
            ],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "block"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_documentation_demo_secret_output_blocks(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Docs relaxation does not suppress realistic non-placeholder secrets."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "docs/security-review.md"},
            "tool_response": [{"type": "text", "text": "credential = 'demo-live-secret'\n"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "block"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_documentation_fixture_prefixed_secret_output_blocks(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Docs relaxation only suppresses exact inert fixture placeholders."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "docs/security-review.md"},
            "tool_response": [{"type": "text", "text": "credential = 'fixture-prod-value'\n"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "block"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_mixed_docs_and_source_paths_keep_secret_retry(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Mixed target outputs do not inherit docs relaxation."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_paths": ["docs/security-review.md", "src/config.py"]},
            "tool_response": [{"type": "text", "text": "credential = 'fixture-only'\n"}],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "block"
        assert result["model_output_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_shell_output_uses_scan_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Clean shell output is scanned once without a second approval."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "stdout": "hello",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_shell_secret_output_remains_blocked(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """The shell fast path still blocks secret-bearing output."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "printenv SERVICE_CREDENTIAL"},
            "stdout": "credential = 'prod-live-value'\n",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "block"
        assert result["continue"] is True
        assert result["policy_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_codex_native_read_secret_output_remains_blocked(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """The Codex Read post-hook blocks high-confidence file content."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/config.py"},
            "tool_response": "token: ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "block"
        assert result["policy_action"] == "block"
        assert result["reason_code"] == "output_secret_match"

    def test_empty_output_allows_without_second_approval(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """An empty completed action has no output to expose or reapprove."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/foo.ts"},
            "stdout": "",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="claude-code",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

    def test_oversized_output_array_never_allows_unscanned_tail(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        payload: dict[str, object] = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/config.ts"},
            "tool_response": [
                *({"type": "text", "text": f"safe line {index}\n"} for index in range(24)),
                {"type": "text", "text": "credential = 'prod-live-value'\n"},
            ],
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="pi",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "replace_with_reviewed_excerpt"
        assert result["reason_code"] == "output_too_large"
        reviewed_excerpt = result["reviewed_excerpt"]
        assert isinstance(reviewed_excerpt, str)
        assert "prod-live-value" not in reviewed_excerpt

    def test_oversized_nontext_output_array_blocks_original(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        payload: dict[str, object] = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "src/config.ts"},
            "tool_response": [{"metadata": index} for index in range(25)],
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
        assert result["reason_code"] == "output_too_large"

    def test_codex_stdout_uses_fast_path(
        self, worker: HookWorker, workspace: Path, home_dir: Path, guard_home: Path
    ) -> None:
        """Codex PostToolUse with stdout output uses output scanning."""
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "read",
            "tool_input": {"file_path": "src/foo.ts"},
            "stdout": "export const hello = 'world';\n",
        }

        result = worker.review_http_payload(
            payload=payload,
            params={},
            default_harness="codex",
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
        )

        assert result["policy_action"] == "warn"
        assert result["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "permissionDecisionReason" in result["hookSpecificOutput"]

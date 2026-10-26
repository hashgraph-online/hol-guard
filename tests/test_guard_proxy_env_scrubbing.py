"""Tests that Guard-internal tokens are scrubbed from subprocess environments.

The proxy launches user-configured MCP server commands, which are an
attacker-controlled surface.  Guard-internal tokens (e.g. HERMES_GUARD_TOKEN)
must never leak into those subprocesses.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from codex_plugin_scanner.guard.proxy._env import _GUARD_TOKEN_ENV_VARS, _build_scrubbed_env


class TestBuildScrubbedEnv:
    """Unit tests for _build_scrubbed_env."""

    def test_hermes_guard_token_is_removed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HERMES_GUARD_TOKEN", "secret-oauth-token-12345")
        env = _build_scrubbed_env()
        assert "HERMES_GUARD_TOKEN" not in env

    def test_only_runtime_basics_are_inherited_implicitly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HERMES_GUARD_TOKEN", "secret")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        monkeypatch.setenv("HOME", "/opt/guard-test/home")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret")
        monkeypatch.setenv("UNRELATED_PROJECT_TOKEN", "ambient-project-secret")
        env = _build_scrubbed_env()
        assert env["PATH"] == "/usr/bin:/bin"
        assert env["HOME"] == "/opt/guard-test/home"
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "UNRELATED_PROJECT_TOKEN" not in env

    def test_extra_env_is_merged(self) -> None:
        env = _build_scrubbed_env({"MCP_SERVER_PORT": "8080", "MCP_API_TOKEN": "explicit-grant"})
        assert env["MCP_SERVER_PORT"] == "8080"
        assert env["MCP_API_TOKEN"] == "explicit-grant"

    def test_extra_env_cannot_reinject_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tokens in extra are also scrubbed — defense-in-depth against re-injection."""
        monkeypatch.setenv("HERMES_GUARD_TOKEN", "secret")
        env = _build_scrubbed_env({"HERMES_GUARD_TOKEN": "still-secret"})
        assert "HERMES_GUARD_TOKEN" not in env, "Caller-provided extra env must not re-inject scrubbed tokens"

    def test_extra_env_cannot_reinject_token_with_different_case(self) -> None:
        env = _build_scrubbed_env({"hermes_guard_token": "windows-case-insensitive-secret"})

        assert "hermes_guard_token" not in env

    def test_no_extra_returns_clean_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HERMES_GUARD_TOKEN", "secret")
        env = _build_scrubbed_env()
        assert isinstance(env, dict)
        assert "HERMES_GUARD_TOKEN" not in env

    def test_guard_token_env_vars_constant_contents(self) -> None:
        assert _GUARD_TOKEN_ENV_VARS == ("HERMES_GUARD_TOKEN",)


class TestStdioProxyScrubbing:
    """Integration test: StdioGuardProxy._start_process uses scrubbed env."""

    def test_stdio_proxy_scrubs_hermes_guard_token(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Verify that _start_process strips HERMES_GUARD_TOKEN from the child env."""
        from codex_plugin_scanner.guard.proxy.stdio import StdioGuardProxy

        monkeypatch.setenv("HERMES_GUARD_TOKEN", "leak-me-please")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        captured_env: dict[str, str] = {}

        class FakePopen:
            def __init__(self, *args: object, **kwargs: object) -> None:
                captured_env.update(kwargs.get("env", {}))
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.returncode = 0
                self.pid = 2147483647

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def terminate(self) -> None:
                pass

        # The Popen fake also intercepts the native digest client's spawn;
        # stub the env-hash seam — scrubbing, not hashing, is under test.
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.proxy.stdio.build_configured_environment_hash",
            lambda *_args, **_kwargs: "0" * 64,
        )
        with mock.patch("codex_plugin_scanner.guard.proxy.stdio.subprocess.Popen", FakePopen):
            proxy = StdioGuardProxy(
                command=["echo", "hello"],
                cwd=tmp_path,
            )
            proxy._start_process()

        assert "HERMES_GUARD_TOKEN" not in captured_env, "HERMES_GUARD_TOKEN leaked into stdio proxy subprocess env"
        assert captured_env.get("PATH") == "/usr/bin:/bin"


class TestRuntimeMcpProxyScrubbing:
    """Integration test: RuntimeMcpGuardProxy._start_process uses scrubbed env."""

    def test_runtime_mcp_proxy_scrubs_hermes_guard_token(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Verify that _start_process strips HERMES_GUARD_TOKEN from the child env."""
        from codex_plugin_scanner.guard.adapters.base import HarnessContext
        from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy

        monkeypatch.setenv("HERMES_GUARD_TOKEN", "leak-me-please")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")

        captured_env: dict[str, str] = {}

        def fake_open_native(argv: object, **kwargs: object) -> dict[str, object]:
            extra_env = kwargs.get("extra_env")
            if isinstance(extra_env, dict):
                captured_env.update({str(k): str(v) for k, v in extra_env.items()})
            return {"status": "opened", "session_id": "test-session"}

        context = HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path,
            guard_home=tmp_path,
        )

        # `_start_process` provisions the native resident verifier key from the
        # store's integrity secret material, so a bare mock raises
        # `native_policy_snapshot_integrity_key_unavailable`.
        from codex_plugin_scanner.guard.store import GuardStore

        store = GuardStore(tmp_path)
        config = type("MockConfig", (), {})()

        # RTM-023 moved child spawn to `mcp_stdio_session_open_native`; the
        # scrubbed env is passed via `extra_env`. Stub the native opener and the
        # hash seam so the proxy resolves to a deterministic session.
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.proxy.runtime_mcp.build_configured_environment_hash",
            lambda *_args, **_kwargs: "0" * 64,
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.proxy.runtime_mcp.mcp_stdio_session_open_native",
            fake_open_native,
        )
        proxy = RuntimeMcpGuardProxy(
            harness="codex",
            server_name="test",
            command=["echo", "hello"],
            context=context,
            store=store,
            config=config,
            source_scope="project",
            config_path=str(tmp_path / ".mcp.json"),
        )
        proxy._start_process()

        assert "HERMES_GUARD_TOKEN" not in captured_env, (
            "HERMES_GUARD_TOKEN leaked into runtime_mcp proxy subprocess env"
        )
        assert captured_env.get("PATH") == "/usr/bin:/bin"

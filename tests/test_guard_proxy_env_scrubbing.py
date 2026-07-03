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

    def test_non_token_vars_are_preserved(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HERMES_GUARD_TOKEN", "secret")
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        monkeypatch.setenv("HOME", "/tmp/test")
        env = _build_scrubbed_env()
        assert env["PATH"] == "/usr/bin:/bin"
        assert env["HOME"] == "/tmp/test"

    def test_extra_env_is_merged(self) -> None:
        env = _build_scrubbed_env({"MCP_SERVER_PORT": "8080"})
        assert env["MCP_SERVER_PORT"] == "8080"

    def test_extra_env_cannot_reinject_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Tokens in extra are also scrubbed — defense-in-depth against re-injection."""
        monkeypatch.setenv("HERMES_GUARD_TOKEN", "secret")
        env = _build_scrubbed_env({"HERMES_GUARD_TOKEN": "still-secret"})
        assert "HERMES_GUARD_TOKEN" not in env, "Caller-provided extra env must not re-inject scrubbed tokens"

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
                self.returncode = 0

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def terminate(self) -> None:
                pass

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

        class FakePopen:
            def __init__(self, *args: object, **kwargs: object) -> None:
                captured_env.update(kwargs.get("env", {}))
                self.stdin = None
                self.stdout = None
                self.returncode = 0

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float | None = None) -> int:
                return 0

            def terminate(self) -> None:
                pass

        context = HarnessContext(
            home_dir=tmp_path,
            workspace_dir=tmp_path,
            guard_home=tmp_path,
        )

        # Build minimal mocks for required constructor args
        store = type("MockStore", (), {"get_managed_install": lambda self, h: None})()
        config = type("MockConfig", (), {})()

        with mock.patch("codex_plugin_scanner.guard.proxy.runtime_mcp.subprocess.Popen", FakePopen):
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

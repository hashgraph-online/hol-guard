"""Runtime regression tests: headless approval resolver skips browser for hook."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessContext,
    HarnessDetection,
    argparse,
    artifact_hash,
    guard_commands_module,
    io,
    json,
    load_guard_config,
    sys,
)
from tests.guard_runtime_test_support import (
    _FlushTrackingOutput,
    _LineOnlyInput,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_headless_approval_resolver_skips_browser_for_hook_first_harnesses(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    store = GuardStore(home_dir)
    config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=1)
    artifact = GuardArtifact(
        artifact_id="copilot:project:workspace-tools",
        name="workspace-tools",
        harness="copilot",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace_dir / ".vscode" / "mcp.json"),
        command="python",
        args=("-m", "http.server", "9100"),
        transport="stdio",
    )
    detection = HarnessDetection(
        harness="copilot",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    payload = {
        "blocked": True,
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "artifact_hash": artifact_hash(artifact),
                "policy_action": "require-reapproval",
                "changed_fields": ["args"],
                "artifact_type": artifact.artifact_type,
                "source_scope": artifact.source_scope,
                "config_path": artifact.config_path,
                "launch_target": "python -m http.server 9100",
            }
        ],
    }
    opened_urls: list[str] = []
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    class FailingDaemonClient:
        def start_session(self, **_kwargs):
            raise RuntimeError("Guard daemon request failed: timed out")

    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: FailingDaemonClient(),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_support_hook_payload.open_browser_url",
        lambda url: opened_urls.append(url) or True,
    )

    blocked_resolver = guard_commands_module._headless_approval_resolver(
        args=argparse.Namespace(harness="copilot"),
        context=HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store=store,
        config=config,
    )
    result = blocked_resolver(detection, payload)

    assert opened_urls == []
    assert result["approval_center_url"] == "http://127.0.0.1:4455"
    assert result["approval_delivery"]["destination"] == "harness"
    assert result["approval_delivery"]["prompt_channel"] == "hook"
    assert result["approval_wait"]["resolved"] is False


def test_headless_approval_resolver_treats_managed_hermes_as_native_or_center(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    store = GuardStore(home_dir)
    config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=1)
    artifact = GuardArtifact(
        artifact_id="hermes:global:github",
        name="github",
        harness="hermes",
        artifact_type="mcp_server",
        source_scope="global",
        config_path=str(home_dir / ".hermes" / "config.yaml"),
        command="npx",
        args=("-y", "@modelcontextprotocol/server-github"),
        transport="stdio",
    )
    detection = HarnessDetection(
        harness="hermes",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    payload = {
        "blocked": True,
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "artifact_hash": artifact_hash(artifact),
                "policy_action": "require-reapproval",
                "changed_fields": ["args"],
                "artifact_type": artifact.artifact_type,
                "source_scope": artifact.source_scope,
                "config_path": artifact.config_path,
                "launch_target": "npx -y @modelcontextprotocol/server-github",
            }
        ],
    }
    store.set_managed_install(
        "hermes",
        True,
        str(workspace_dir),
        {"capabilities": {"same_channel": True}},
        "2026-04-15T00:00:00+00:00",
    )
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )

    blocked_resolver = guard_commands_module._headless_approval_resolver(
        args=argparse.Namespace(harness="hermes"),
        context=HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store=store,
        config=config,
    )
    result = blocked_resolver(detection, payload)

    assert result["approval_delivery"]["destination"] == "harness"
    assert result["approval_delivery"]["prompt_channel"] == "native"
    assert result["approval_wait"]["resolved"] is False


def test_hermes_mcp_proxy_streams_stdio_messages_without_waiting_for_eof(tmp_path, monkeypatch, capsys):
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "hermes",
        True,
        str(workspace),
        {
            "servers": {
                "yaml:demo": {
                    "transport": "stdio",
                    "command": "python",
                    "args": ["-m", "demo"],
                }
            }
        },
        "2026-04-15T00:00:00+00:00",
    )
    captured_messages: list[dict[str, object]] = []

    class _FakeProxy:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def run_stream(self, *, input_stream, output_stream, error_stream) -> int:
            for line in input_stream:
                payload = json.loads(line)
                captured_messages.append(payload)
                output_stream.write(json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}}) + "\n")
                output_stream.flush()
            return 0

    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(guard_commands_module, "StdioGuardProxy", _FakeProxy)
    monkeypatch.setattr(sys, "stdin", _LineOnlyInput(['{"jsonrpc":"2.0","id":7,"method":"tools/list"}\n']))

    rc = guard_commands_module._run_hermes_mcp_proxy(
        args=argparse.Namespace(server="yaml:demo"),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=guard_home),
        store=store,
        config=load_guard_config(guard_home),
    )
    output = capsys.readouterr()

    assert rc == 0
    assert captured_messages == [{"jsonrpc": "2.0", "id": 7, "method": "tools/list"}]
    assert '"id": 7' in output.out


def test_hermes_mcp_proxy_passes_manifest_env_to_stdio_proxy(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = GuardStore(guard_home)
    store.set_managed_install(
        "hermes",
        True,
        str(workspace),
        {
            "servers": {
                "yaml:demo": {
                    "transport": "stdio",
                    "command": "python",
                    "args": ["-m", "demo"],
                    "env": {"GITHUB_TOKEN": "ghp_test_token"},
                }
            }
        },
        "2026-04-15T00:00:00+00:00",
    )
    captured_init: list[dict[str, object]] = []

    class _FakeProxy:
        def __init__(self, **kwargs) -> None:
            captured_init.append(kwargs)

        def run_stream(self, *, input_stream, output_stream, error_stream) -> int:
            return 0

    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(guard_commands_module, "StdioGuardProxy", _FakeProxy)
    monkeypatch.setattr(sys, "stdin", _LineOnlyInput([]))

    rc = guard_commands_module._run_hermes_mcp_proxy(
        args=argparse.Namespace(server="yaml:demo"),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=workspace, guard_home=guard_home),
        store=store,
        config=load_guard_config(guard_home),
    )

    assert rc == 0
    assert captured_init[0]["env"] == {"GITHUB_TOKEN": "ghp_test_token"}


def test_hermes_mcp_proxy_rejects_invalid_json(tmp_path, monkeypatch, capsys):
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_managed_install(
        "hermes",
        True,
        None,
        {
            "servers": {
                "yaml:demo": {
                    "transport": "http",
                    "url": "https://mcp.example.com/v1/mcp",
                }
            }
        },
        "2026-04-15T00:00:00+00:00",
    )
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO("{not-json}\n"))

    rc = guard_commands_module._run_hermes_mcp_proxy(
        args=argparse.Namespace(server="yaml:demo"),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=guard_home),
        store=store,
        config=load_guard_config(guard_home),
    )
    output = capsys.readouterr()

    assert rc == 2
    assert "invalid JSON" in output.err


def test_hermes_mcp_proxy_forwards_remote_headers_and_flushes_stdout(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_managed_install(
        "hermes",
        True,
        None,
        {
            "servers": {
                "yaml:demo": {
                    "transport": "http",
                    "url": "https://mcp.example.com/v1/mcp",
                    "headers": {"Authorization": "Bearer test-token"},
                }
            }
        },
        "2026-04-15T00:00:00+00:00",
    )
    captured_headers: list[dict[str, str]] = []
    output_stream = _FlushTrackingOutput()

    class _FakeRemoteProxy:
        def __init__(self, *, base_url: str, allow_insecure_localhost: bool = False) -> None:
            self.base_url = base_url
            self.allow_insecure_localhost = allow_insecure_localhost

        def forward(
            self,
            path: str,
            payload: dict[str, object],
            headers: dict[str, str] | None = None,
            expect_response: bool = True,
        ) -> dict[str, object]:
            captured_headers.append(headers or {})
            assert expect_response is True
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}}

    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(guard_commands_module, "RemoteGuardProxy", _FakeRemoteProxy)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"jsonrpc":"2.0","id":9,"method":"tools/list"}\n'))
    monkeypatch.setattr(sys, "stdout", output_stream)

    rc = guard_commands_module._run_hermes_mcp_proxy(
        args=argparse.Namespace(server="yaml:demo"),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=guard_home),
        store=store,
        config=load_guard_config(guard_home),
    )

    assert rc == 0
    assert captured_headers == [{"Authorization": "Bearer test-token"}]
    assert '"id":9' in output_stream.getvalue()
    assert output_stream.flush_count >= 1


def test_hermes_mcp_proxy_skips_http_notification_responses(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_managed_install(
        "hermes",
        True,
        None,
        {
            "servers": {
                "yaml:demo": {
                    "transport": "http",
                    "url": "https://mcp.example.com/v1/mcp",
                }
            }
        },
        "2026-04-15T00:00:00+00:00",
    )
    captured_expect_response: list[bool] = []
    output_stream = _FlushTrackingOutput()

    class _FakeRemoteProxy:
        def __init__(self, *, base_url: str, allow_insecure_localhost: bool = False) -> None:
            self.base_url = base_url
            self.allow_insecure_localhost = allow_insecure_localhost

        def forward(
            self,
            path: str,
            payload: dict[str, object],
            headers: dict[str, str] | None = None,
            expect_response: bool = True,
        ) -> dict[str, object] | None:
            captured_expect_response.append(expect_response)
            return None

    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(guard_commands_module, "RemoteGuardProxy", _FakeRemoteProxy)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO('{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'),
    )
    monkeypatch.setattr(sys, "stdout", output_stream)

    rc = guard_commands_module._run_hermes_mcp_proxy(
        args=argparse.Namespace(server="yaml:demo"),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=guard_home),
        store=store,
        config=load_guard_config(guard_home),
    )

    assert rc == 0
    assert captured_expect_response == [False]
    assert output_stream.getvalue() == ""


def test_hermes_mcp_proxy_http_transport_does_not_require_guard_daemon(tmp_path, monkeypatch):
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.set_managed_install(
        "hermes",
        True,
        None,
        {
            "servers": {
                "yaml:demo": {
                    "transport": "http",
                    "url": "https://mcp.example.com/v1/mcp",
                }
            }
        },
        "2026-04-15T00:00:00+00:00",
    )
    output_stream = _FlushTrackingOutput()

    class _FakeRemoteProxy:
        def __init__(self, *, base_url: str, allow_insecure_localhost: bool = False) -> None:
            self.base_url = base_url
            self.allow_insecure_localhost = allow_insecure_localhost

        def forward(
            self,
            path: str,
            payload: dict[str, object],
            headers: dict[str, str] | None = None,
            expect_response: bool = True,
        ) -> dict[str, object]:
            return {"jsonrpc": "2.0", "id": payload["id"], "result": {"ok": True}}

    def _raise_daemon_error(_guard_home):
        raise RuntimeError("daemon unavailable")

    monkeypatch.setattr(guard_commands_module, "schedule_guard_daemon_ensure", _raise_daemon_error)
    monkeypatch.setattr(guard_commands_module, "RemoteGuardProxy", _FakeRemoteProxy)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"jsonrpc":"2.0","id":9,"method":"tools/list"}\n'))
    monkeypatch.setattr(sys, "stdout", output_stream)

    rc = guard_commands_module._run_hermes_mcp_proxy(
        args=argparse.Namespace(server="yaml:demo"),
        context=HarnessContext(home_dir=tmp_path, workspace_dir=None, guard_home=guard_home),
        store=store,
        config=load_guard_config(guard_home),
    )

    assert rc == 0
    assert '"id":9' in output_stream.getvalue()

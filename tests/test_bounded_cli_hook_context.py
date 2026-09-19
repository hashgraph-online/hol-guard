"""Configured project context survives the real bridge and receiver boundary."""

from __future__ import annotations

import io
import json
import time
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge as bridge
from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.daemon.config_read_scope import HookConfigReadScope
from scripts.native_slo_registered_surfaces import read_registered_surfaces
from scripts.native_slo_workloads import build_cases


class _BeforeNetwork(BaseException):
    pass


def _handler(context):
    handler = object.__new__(server._GuardDaemonHandler)
    handler.server = SimpleNamespace(
        home_dir=context.home_dir,
        store=SimpleNamespace(guard_home=context.guard_home),
        hook_config_scope=HookConfigReadScope.for_guard_home(context.guard_home),
        request_deadline=lambda _request, timeout: time.monotonic() + timeout,
    )
    handler.request = object()
    return handler


def _context(tmp_path):
    # Query delimiters, quoting and Unicode remain path data, never new fields.
    home = tmp_path / "home 'quoted' &?雪"
    workspace, guard_home = home / "workspace #?雪", home / ".hol-guard"
    workspace.mkdir(parents=True)
    guard_home.mkdir(mode=0o700)
    return HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=guard_home)


def test_actual_global_and_project_commands_preserve_only_configured_context(tmp_path, monkeypatch):
    context = _context(tmp_path)
    CopilotHarnessAdapter().install(context)
    registrations = read_registered_surfaces(context, "copilot")
    case = next(
        item
        for item in build_cases(context.workspace_dir, system="Linux")
        if item.case_id == "copilot/preToolUse/benign/small"
    )
    assert "cwd" not in case.payload
    raw = json.dumps(case.payload, separators=(",", ":"), ensure_ascii=True)
    endpoint = "http://127.0.0.1:4871/v1/hooks/copilot"
    (context.guard_home / "daemon-state.json").write_text(json.dumps({"host": "127.0.0.1", "port": 4871}))
    (context.guard_home / "daemon-state.json").chmod(0o600)
    (context.guard_home / "daemon-auth-token").write_text("synthetic")
    (context.guard_home / "daemon-auth-token").chmod(0o600)
    observed = []

    class Opener:
        def open(self, request, *, timeout):
            observed.append((request, timeout))
            raise _BeforeNetwork

    monkeypatch.setattr(daemon, "_build_loopback_opener", Opener)

    def unexpected_fallback(*_args, **_kwargs):
        raise AssertionError("registration witness must stop before network I/O")

    monkeypatch.setattr(bridge, "run_isolated_hook_process", unexpected_fallback)
    handler = _handler(context)
    admitted = []

    def capture(_handler, _server, payload, params, harness, workspace, _deadline):
        admitted.append({"payload": payload, "params": params, "harness": harness, "workspace": workspace})
        return False

    monkeypatch.setattr(server, "_native_mode_requires_rust", lambda: True)
    monkeypatch.setattr(server, "prepare_native_hook_policy", capture)
    for registration in registrations:
        if registration.event != "preToolUse":
            continue
        configuration = json.loads(registration.argv[-1])
        with pytest.raises(_BeforeNetwork):
            bridge.run_bounded_cli_hook(configuration, input_text=raw)
        request, timeout = observed[-1]
        parsed = urlparse(request.full_url)
        assert request.full_url.split("?", 1)[0] == endpoint
        assert request.data == raw.encode()
        assert request.get_header("X-guard-token") == "synthetic"
        assert request.get_method() == "POST" and timeout == 5.0
        expected = {"guard-home": [str(context.guard_home)], "home": [str(context.home_dir)]}
        if registration.scope == "project":
            expected["workspace"] = [str(context.workspace_dir)]
        assert parse_qs(parsed.query) == expected
        assert registration.cwd == context.guard_home
        handler._handle_runtime_hook(dict(case.payload), parsed.query, default_harness="copilot")
        received = admitted[-1]
        assert received["workspace"] == (str(context.workspace_dir) if registration.scope == "project" else None)
        assert received["params"] == expected and received["harness"] == "copilot"
        assert received["payload"] == {key: value for key, value in case.payload.items() if key != "guard_remaining_ms"}
    assert len(observed) == len(admitted) == 2


@pytest.mark.parametrize(
    "invalid",
    [
        "relative_home",
        "relative_workspace",
        "duplicate_home",
        "duplicate_workspace",
        "unknown",
        "missing",
        "guard_home",
        "harness",
    ],
)
def test_unrecognized_nonfrozen_context_keeps_exact_cli_fallback(tmp_path, monkeypatch, invalid):
    context = _context(tmp_path)
    arguments = ["guard", "hook", "--guard-home", str(context.guard_home), "--harness", "copilot"]
    if invalid == "relative_home":
        arguments += ["--home", "relative"]
    elif invalid == "relative_workspace":
        arguments += ["--workspace", "relative"]
    elif invalid == "duplicate_home":
        arguments += ["--home", str(context.home_dir), "--home", str(context.home_dir)]
    elif invalid == "duplicate_workspace":
        arguments += ["--workspace", str(context.workspace_dir), "--workspace", str(context.workspace_dir)]
    elif invalid == "unknown":
        arguments += ["--working-directory", str(context.workspace_dir)]
    elif invalid == "missing":
        arguments += ["--home"]
    elif invalid == "guard_home":
        arguments[3] = str(context.home_dir / "peer-guard-home")
    else:
        arguments[5] = "grok"

    def forbidden_endpoint(*_args):
        raise AssertionError("unrecognized command context must not read daemon state or authenticate")

    observed = []

    def fallback(command, *, input_text, cwd, environment, timeout_seconds):
        observed.append((command, input_text, cwd, timeout_seconds))
        return BoundedHookProcessResult(0, '{"permissionDecision":"allow"}', False, False)

    monkeypatch.setattr(daemon, "_daemon_hook_endpoint", forbidden_endpoint)
    monkeypatch.setattr(bridge, "run_isolated_hook_process", fallback)
    config = {
        "python_executable": "python",
        "package_root": str(tmp_path),
        "guard_home": str(context.guard_home),
        "cli_args": arguments,
        "harness": "copilot",
        "timeout_seconds": 3,
    }
    with redirect_stdout(io.StringIO()):
        assert bridge.run_bounded_cli_hook(config, input_text='{"unchanged":"body"}') == 0
    assert len(observed) == 1
    command, body, cwd, timeout = observed[0]
    assert tuple(command[-len(arguments) - 1 :]) == (*arguments, "--json")
    assert body == '{"unchanged":"body"}' and cwd == context.guard_home and timeout == 3


@pytest.mark.parametrize("invalid", ["home", "workspace", "guard-home"])
def test_forwarded_metadata_keeps_receiver_path_rejection(tmp_path, monkeypatch, invalid):
    context = _context(tmp_path)
    handler = _handler(context)
    query = {
        "home": str(context.home_dir),
        "guard-home": str(context.guard_home),
        "workspace": str(context.workspace_dir),
    }
    if invalid == "home":
        query[invalid] = str(tmp_path / "peer-home")
    elif invalid == "guard-home":
        query[invalid] = str(tmp_path / "peer-guard-home")
    else:
        # An owned temporary peer workspace can legitimately be admitted by
        # the existing policy; use a path outside that exception and all roots.
        query[invalid] = str(Path(tmp_path.anchor) / "guard-unadmitted-workspace")
    rejections, admitted = [], []

    def capture(_handler, _server, _payload, _params, _harness, workspace, _deadline):
        admitted.append(workspace)
        return False

    monkeypatch.setattr(server, "_native_mode_requires_rust", lambda: True)
    monkeypatch.setattr(server, "prepare_native_hook_policy", capture)
    monkeypatch.setattr(handler, "_record_hook_path_rejection", lambda **fields: rejections.append(fields))
    handler._handle_runtime_hook({}, urlencode(query), default_harness="copilot")
    assert len(rejections) == 1 and rejections[0]["parameter"] == invalid
    assert rejections[0]["reason"] == ("unexpected_guard_home" if invalid == "guard-home" else "unexpected_root")
    assert admitted == [None]


def test_forwarded_context_keeps_loopback_and_authentication_checks(tmp_path):
    guard_home = tmp_path / "guard-home"
    arguments = ["guard", "hook", "--guard-home", str(guard_home), "--harness", "copilot", "--workspace", str(tmp_path)]
    loads = []

    def authentication(_home):
        loads.append("authentication")
        return "synthetic"

    assert (
        daemon.try_daemon_hook(
            guard_home=guard_home,
            harness="copilot",
            input_text="{}",
            timeout_seconds=3,
            cli_args=arguments,
            _endpoint_loader=lambda *_args: "https://example.invalid/v1/hooks/copilot",
            _token_loader=authentication,
        )
        is None
    )
    assert loads == []
    assert (
        daemon.try_daemon_hook(
            guard_home=guard_home,
            harness="copilot",
            input_text="{}",
            timeout_seconds=3,
            cli_args=arguments,
            _endpoint_loader=lambda *_args: "http://127.0.0.1:4871/v1/hooks/copilot",
            _token_loader=lambda _home: None,
        )
        is None
    )

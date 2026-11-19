from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import bounded_cli_hook_bridge, native_caller
from codex_plugin_scanner.guard.codex_hook_launch_runtime import isolated_hook_environment
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.native_harness_client import ask

from .bounded_cli_hook_test_support import config as _config
from .bounded_cli_hook_test_support import json_object as _json_object
from .bounded_cli_hook_test_support import run_hook as _run_hook
from .desktop_proxy_test_support import launch_script
from .native_bounded_runtime import durable_copy, use_bounded_runtime


def _native_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test when Python, not the runtime, writes the answer."""

    def python_answer(_harness: str) -> int:
        raise AssertionError("the native runtime must answer this hook")

    monkeypatch.setattr(bounded_cli_hook_bridge, "_refuse", python_answer)


def _signed_bundle_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    bundle = tmp_path / "HOL Guard.app"
    macos = bundle / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    proxy = macos / "HOL Guard"
    core = macos / "hol-guard"
    for path in (proxy, core):
        path.write_text("binary", encoding="utf-8")
        path.chmod(0o755)
    return bundle, proxy, core


def _frozen_guard(monkeypatch: pytest.MonkeyPatch, executable: str) -> None:
    """Make this process a frozen Guard whose CLI is ``executable``."""

    monkeypatch.setattr("sys.frozen", True, raising=False)
    monkeypatch.setattr("sys.executable", executable)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.stable_guard_cli.prune_safe_cli_executable", lambda executable: executable
    )
    # The caller stamp reports a frozen Guard only when its executable exists;
    # ``executable`` names a launcher this host does not have.
    from codex_plugin_scanner.guard import native_harness_client as harness_client

    stamped = harness_client.caller_identity
    monkeypatch.setattr(harness_client, "caller_identity", lambda: {**stamped(), "frozen": True, "attest_facts": None})


def _hook_argv(tmp_path: Path, harness: str) -> tuple[str, ...]:
    """The bounded hook argv the native kind names for ``harness`` in this process."""

    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    return tuple(str(part) for part in ask("hook_spec", context, harness=harness)["hook_argv"])


def test_desktop_hook_environment_forwards_only_the_proxy_selectors(tmp_path: Path) -> None:
    # The native kind verifies the proxy; the signed launch it renders is covered by its Rust tests.
    forwarded = isolated_hook_environment(
        {
            "PATH": "/usr/bin",
            "HOME": str(tmp_path),
            "HOL_GUARD_DESKTOP": "1",
            "HOL_GUARD_DESKTOP_HOOK_PROXY": str(tmp_path / "HOL Guard"),
            "HOL_GUARD_DESKTOP_RUNTIME_OWNER": str(tmp_path / "untrusted-runtime-owner"),
        }
    )
    assert forwarded == {
        "PATH": "/usr/bin",
        "HOME": str(tmp_path),
        "HOL_GUARD_DESKTOP": "1",
        "HOL_GUARD_DESKTOP_HOOK_PROXY": str(tmp_path / "HOL Guard"),
    }


def test_frozen_hook_without_a_proxy_or_runtime_asks_for_repair(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _frozen_guard(monkeypatch, "/app/hol-guard")
    monkeypatch.setattr(native_caller, "_native_runtime", lambda: None)
    with pytest.raises(RuntimeError, match="hol-guard repair"):
        _hook_argv(tmp_path, "grok")


@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_frozen_bounded_hook_runs_the_durable_native_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    runtime = tmp_path / "bundle" / "hol-guard-runtime"
    digest = use_bounded_runtime(monkeypatch, runtime)
    _frozen_guard(monkeypatch, "/app/hol-guard")

    command = _hook_argv(tmp_path, harness)

    durable = durable_copy(tmp_path / "guard-home", runtime, digest)
    assert command[:2] == (str(durable), bounded_cli_hook_bridge.NATIVE_BOUNDED_HOOK_COMMAND)
    assert len(command) == 3
    config = json.loads(command[2])
    assert config["python_executable"] == "/app/hol-guard"
    assert config["frozen_launcher"] is True
    # The runtime derives the frozen Guard's recovery from the launcher itself.
    assert "start_command" not in config


def test_desktop_proxy_keeps_core_for_an_unsigned_writable_or_cross_bundle_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The kind's team and layout checks are unit tested in Rust; here the real kind
    # answers for fixtures no Apple team signed.
    _bundle, proxy, core = _signed_bundle_fixture(tmp_path)
    _other_bundle, other_proxy, _other_core = _signed_bundle_fixture(tmp_path / "other")
    use_bounded_runtime(monkeypatch, tmp_path / "bundle" / "hol-guard-runtime")
    _frozen_guard(monkeypatch, str(core))
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    def keeps_core() -> None:
        command = _hook_argv(tmp_path, "grok")
        assert command[0] != "/bin/sh"
        assert command[1] == bounded_cli_hook_bridge.NATIVE_BOUNDED_HOOK_COMMAND

    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    keeps_core()
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(other_proxy))
    keeps_core()
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    proxy.chmod(0o777)
    keeps_core()


def test_linux_never_uses_caller_controlled_appimage_as_proxy_provenance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    proxy = tmp_path / "HOL-Guard.AppImage"
    proxy.write_text("proxy", encoding="utf-8")
    proxy.chmod(0o755)
    core = tmp_path / "hol-guard"
    core.write_text("core", encoding="utf-8")
    core.chmod(0o755)
    use_bounded_runtime(monkeypatch, tmp_path / "bundle" / "hol-guard-runtime")
    _frozen_guard(monkeypatch, str(core))
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    monkeypatch.setenv("APPIMAGE", str(proxy))

    command = _hook_argv(tmp_path, "grok")

    assert command[0] != "/bin/sh"
    assert str(proxy) not in command


def test_macos_launcher_reverifies_normal_paths_and_falls_back_by_status() -> None:
    launcher, _name = launch_script()
    assert "/dev/fd" not in launcher
    assert "HOL_GUARD_DESKTOP_E2E_ALLOW_ADHOC_SIGNATURE" not in launcher
    assert 'verify_team "$bundle"' in launcher
    assert 'verify_team "$proxy"' in launcher
    assert 'verify_team "$fallback"' in launcher
    assert '"$proxy" __guard-hook-proxy "$config"' in launcher
    assert 'if [ "$status" -eq 125 ]' in launcher
    assert '|| [ "$status" -eq 126 ]' in launcher
    assert '|| [ "$status" -eq 127 ]' in launcher
    assert 'exec "$fallback" __guard-bounded-hook "$config"' in launcher


def _frozen_config(tmp_path: Path, variant: str) -> dict[str, object]:
    harness = variant if variant in {"hermes", "openclaw"} else "grok"
    config = _config(tmp_path, harness=harness)
    config["frozen_launcher"] = variant != "forged-mode"
    if variant == "noncanonical-home":
        cast(list[str], config["cli_args"])[3] = str(tmp_path / "unused" / ".." / "guard-home")
    if harness != "grok":
        config["cli_args"] = [*cast(list[str], config["cli_args"]), "--json"]
    if variant in {"forged-mode", "forged-args"}:
        config["python_executable"] = "/bin/sh"
    if variant == "forged-args":
        config["cli_args"] = ["-c", "echo bypassed"]
    return config


@pytest.mark.parametrize("frozen", [True, False])
@pytest.mark.parametrize("variant", ["grok", "noncanonical-home", "hermes", "openclaw", "forged-mode", "forged-args"])
def test_a_frozen_config_without_a_daemon_answer_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
    tmp_path: Path,
    native_hook_force: Path,
    variant: str,
    frozen: bool,
) -> None:
    del native_hook_force
    _native_answers(monkeypatch)
    config = _frozen_config(tmp_path, variant)
    # The runtime never runs a config's argv, so a forged one changes nothing.
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "executable", str(tmp_path / "missing" / "hol-guard"))
    returncode = _run_hook(monkeypatch, config, json.dumps({"hook_event_name": "PreToolUse"}))

    expected = ("block", 2) if variant == "hermes" else ("deny", 0)
    assert (_json_object(capfd.readouterr().out)["decision"], returncode) == expected

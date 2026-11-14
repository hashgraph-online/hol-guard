from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge
from codex_plugin_scanner.guard.codex_hook_launch_runtime import isolated_hook_environment

from .bounded_cli_hook_test_support import config as _config
from .bounded_cli_hook_test_support import json_object as _json_object
from .bounded_cli_hook_test_support import run_hook as _run_hook
from .desktop_proxy_test_support import launch_script, sign_every_path


def _native_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test when Python, not the runtime, writes the answer."""

    def python_answer(**_kwargs: object) -> int:
        raise AssertionError("the native runtime must answer this hook")

    monkeypatch.setattr(bounded_cli_hook_bridge, "_emit_failure", python_answer)


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


def test_frozen_hook_command_prefers_runtime_verified_signed_macos_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle, proxy, core = _signed_bundle_fixture(tmp_path)
    forwarded = isolated_hook_environment(
        {
            "PATH": "/usr/bin",
            "HOME": str(tmp_path),
            "HOL_GUARD_DESKTOP": "1",
            "HOL_GUARD_DESKTOP_HOOK_PROXY": str(proxy),
            "HOL_GUARD_DESKTOP_RUNTIME_OWNER": str(tmp_path / "untrusted-runtime-owner"),
        }
    )
    assert forwarded == {
        "PATH": "/usr/bin",
        "HOME": str(tmp_path),
        "HOL_GUARD_DESKTOP": "1",
        "HOL_GUARD_DESKTOP_HOOK_PROXY": str(proxy),
    }
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", forwarded["HOL_GUARD_DESKTOP"])
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", forwarded["HOL_GUARD_DESKTOP_HOOK_PROXY"])
    requests = sign_every_path(monkeypatch)

    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable=str(core),
        package_root=tmp_path,
        guard_home=tmp_path / "guard-home",
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )

    assert command[:4] == ("/bin/sh", "-c", *launch_script())
    assert command[4:7] == (str(proxy), "TEAMID", str(bundle))
    assert [(request["desktop"], request["proxy"], request["core"]) for request in requests] == [
        ("1", str(proxy), str(core))
    ]
    config = json.loads(command[7])
    assert config == {
        "python_executable": str(core),
        "package_root": str(tmp_path.resolve()),
        "guard_home": str((tmp_path / "guard-home").resolve()),
        "cli_args": [
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ],
        "harness": "grok",
        "timeout_seconds": 25,
        "frozen_launcher": True,
    }
    assert command[8] == str(core)
    assert command[9] == "0"


def test_untrusted_native_proxy_falls_back_to_internal_frozen_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy_command",
        lambda executable, config: None,
    )
    monkeypatch.setattr(bounded_cli_hook_bridge, "isolated_cursor_hook_python", lambda: None)
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable="/app/hol-guard",
        package_root=tmp_path,
        guard_home=tmp_path / "guard-home",
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )

    assert command[:2] == ("/app/hol-guard", "__guard-bounded-hook")


@pytest.mark.parametrize("harness", ["hermes", "openclaw"])
def test_frozen_bounded_hook_runs_the_durable_native_bridge(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    runtime = tmp_path / "guard-home" / "native-runtime" / ("a" * 64) / "hol-guard-runtime"
    requested: list[tuple[str, Path | None]] = []

    def durable(name: str, *, guard_home: Path | None = None) -> Path:
        requested.append((name, guard_home))
        return runtime

    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge, "prune_safe_cli_executable", lambda executable: executable)
    monkeypatch.setattr(bounded_cli_hook_bridge, "_trusted_desktop_hook_proxy_command", lambda executable, config: None)
    monkeypatch.setattr(bounded_cli_hook_bridge, "native_bridge_executable", durable)
    guard_home = tmp_path / "guard-home"
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable="/app/hol-guard",
        package_root=tmp_path,
        guard_home=guard_home,
        cli_args=("guard", "hook", "--guard-home", str(guard_home), "--harness", harness),
        harness=harness,
        timeout_seconds=25,
    )

    assert requested == [(harness, guard_home)]
    assert command[:4] == (
        str(runtime),
        bounded_cli_hook_bridge.NATIVE_BOUNDED_HOOK_COMMAND,
        "/app/hol-guard",
        "__guard-bounded-hook",
    )
    config = json.loads(command[4])
    assert config["frozen_launcher"] is True
    # The runtime derives the frozen Guard's recovery from the launcher itself.
    assert "start_command" not in config


def test_frozen_bounded_hook_prefers_isolated_stdlib_client(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "_trusted_desktop_hook_proxy_command",
        lambda executable, config: None,
    )
    monkeypatch.setattr(bounded_cli_hook_bridge, "isolated_cursor_hook_python", lambda: "/usr/bin/python3")
    runtime = tmp_path / "hol-guard-runtime"
    monkeypatch.setattr(bounded_cli_hook_bridge, "native_bridge_executable", lambda *_args, **_kwargs: runtime)
    guard_home = tmp_path / "guard-home"
    command = bounded_cli_hook_bridge.bounded_cli_hook_command(
        python_executable="/app/hol-guard",
        package_root=tmp_path,
        guard_home=guard_home,
        cli_args=(
            "guard",
            "hook",
            "--guard-home",
            str(guard_home),
            "--harness",
            "grok",
        ),
        harness="grok",
        timeout_seconds=25,
    )

    script = bounded_cli_hook_bridge.bounded_hook_script_path(guard_home, "grok")
    assert script is not None
    assert command[:5] == (str(runtime), "bounded-hook-bridge", "/usr/bin/python3", "-I", str(script.resolve()))
    assert json.loads(command[5])["guard_home"] == str(guard_home.resolve())
    source = script.read_text(encoding="utf-8")
    assert 'HARNESS = "grok"' in source
    assert "TIMEOUT_SECONDS = 25" in source
    assert "daemon --serve" not in source
    assert "__guard-bounded-hook" not in source


def test_desktop_proxy_keeps_core_for_an_unsigned_writable_or_cross_bundle_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # The kind's team and layout checks are unit tested in Rust; here the real kind
    # answers for fixtures no Apple team signed.
    _bundle, proxy, core = _signed_bundle_fixture(tmp_path)
    _other_bundle, other_proxy, _other_core = _signed_bundle_fixture(tmp_path / "other")
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "darwin")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")

    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(other_proxy))
    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    proxy.chmod(0o777)
    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None


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
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "frozen", True, raising=False)
    monkeypatch.setattr(bounded_cli_hook_bridge.sys, "platform", "linux")
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_DESKTOP_HOOK_PROXY", str(proxy))
    monkeypatch.setenv("APPIMAGE", str(proxy))

    assert bounded_cli_hook_bridge._trusted_desktop_hook_proxy_command(str(core), "{}") is None


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

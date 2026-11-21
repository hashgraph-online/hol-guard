"""A native MCP relay session whose daemon is down stays native.

The relay decides how the session runs before it reads any stdin byte or
starts the MCP server. A lane that is only not ready yet keeps the session in
the relay, which starts one detached daemon ensure; the Python proxy is never
launched for it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from tests.support.bounded_subprocess import run_bounded

_STDIN = b""
_FAKE_PROXY = """import json, os, sys
# Run as a module, the fake reports the interpreter arguments the relay passed.
argv = sys.orig_argv[1:] if __spec__ is not None else sys.argv[1:]
record = {{"argv": argv, "env": dict(os.environ), "stdin": sys.stdin.buffer.read().hex()}}
name = "ensure" if "daemon" in argv else "proxy"
with open(os.path.join({log!r}, name + ".json"), "w", encoding="utf-8") as handle:
    json.dump(record, handle)
"""


def _runtime() -> Path:
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary or not Path(binary).is_file():
        pytest.skip("HOL_GUARD_NATIVE_BINARY does not name a compiled runtime")
    return Path(binary).resolve()


def _fake_python(root: Path, source: str) -> tuple[Path, dict[str, str]]:
    """The interpreter the proxy argv names, and the environment that fakes the proxy.

    On Windows the relay starts the daemon ensure detached, where a ``.cmd``
    launcher never runs, so the real interpreter imports a fake
    ``codex_plugin_scanner.cli`` from ``PYTHONPATH`` instead.
    """

    if os.name == "nt":
        package = root / "fake-proxy" / "codex_plugin_scanner"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "cli.py").write_text(source, encoding="utf-8")
        return Path(sys.executable), {"PYTHONPATH": str(package.parent)}
    launcher = root / "python"
    launcher.write_text(f"#!{sys.executable}\n" + source, encoding="utf-8")
    launcher.chmod(0o700)
    return launcher, {}


def _environment(home: Path) -> dict[str, str]:
    env = {"HOME": str(home), "HOL_GUARD_TEST_MARK": "kept"}
    if os.name == "nt":
        keep = ("PATH", "PATHEXT", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP")
        env.update({key: os.environ[key] for key in keep if key in os.environ})
        env["USERPROFILE"] = str(home)
        return env
    # LC_ALL keeps the fake interpreter from coercing its own locale variables.
    env.update(PATH="/usr/bin:/bin", LC_ALL="C.UTF-8")
    return env


def _wait_for(path: Path, seconds: float = 10.0) -> dict[str, object]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        time.sleep(0.05)
    raise AssertionError(f"{path.name} was never written")


def test_a_down_daemon_keeps_the_session_native_and_starts_one_ensure(tmp_path: Path) -> None:
    runtime = _runtime()
    log, guard_home, workspace = tmp_path / "log", tmp_path / "guard-home", tmp_path / "workspace"
    for directory in (log, guard_home, workspace):
        directory.mkdir(mode=0o700)
    fake, fake_env = _fake_python(tmp_path, _FAKE_PROXY.format(log=str(log)))
    proxy_args = [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "codex-mcp-proxy",
        "--guard-home",
        str(guard_home),
        "--home",
        str(tmp_path),
        "--workspace",
        str(workspace),
        "--server-name",
        "canary",
        "--config-path",
        str(workspace / ".codex" / "config.toml"),
        "--command",
        # An interpreter reading an empty stdin exits at once, like cat.
        sys.executable if os.name == "nt" else "/bin/cat",
    ]
    env = {**_environment(tmp_path), **fake_env}
    completed = run_bounded(
        [str(runtime), "mcp-relay", str(fake), *proxy_args],
        input=_STDIN,
        env=env,
        cwd=workspace,
        timeout=60,
    )
    stderr = completed.stderr.decode("utf-8", errors="replace")
    assert "hol-guard mcp-relay: lane not ready: mcp_relay_daemon_unreachable" in stderr
    assert "python proxy" not in stderr
    # The host closed at once, so the relay shut its MCP server down cleanly.
    assert completed.returncode == 0, stderr
    # The daemon is down, so one detached ensure ran without the host's input.
    ensure = _wait_for(log / "ensure.json")
    assert ensure["argv"] == [
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "daemon",
        "ensure",
        "--guard-home",
        str(guard_home),
        "--home",
        str(tmp_path),
    ]
    assert ensure["stdin"] == ""
    assert not (log / "proxy.json").exists()

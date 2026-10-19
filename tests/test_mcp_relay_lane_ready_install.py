"""A fresh install's MCP relay session starts on a ready lane, before and after a policy write.

The installer, the daemon and the resident run as a host would start them, in
a temporary home. The lane is ready only once the daemon publishes the
exact-action state, which on a fresh home needs the policy-integrity row the
publisher refreshes; a policy write advances that state, and the daemon has to
republish the generation the write signed. A server no session reported a
catalog of starts native and reports the catalog it relays; its later
sessions start on the ready lane.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TypeVar, cast

import pytest

from tests.support.bounded_subprocess import run_bounded

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

_LANE_READY = "hol-guard mcp-relay: lane ready: "
_HAND_OFF = "hol-guard mcp-relay: python proxy: "
_NOT_READY = "hol-guard mcp-relay: lane not ready: "
_SERVER_UNKNOWN = _NOT_READY + "mcp_relay_session_server_unknown"
_SERVER = """
import json
import sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message.get("method") == "tools/list":
        schema = {"type": "object", "properties": {"path": {"type": "string"}}}
        result = {"tools": [{"name": "read_note", "inputSchema": schema}]}
    else:
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "canary", "version": "1"}}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
"""
_LIST_TOOLS = "".join(
    json.dumps(message) + "\n"
    for message in (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
).encode("utf-8")
_ACK = Path("native-runtime") / "direct-lane" / "ack.json"
_WAIT_SECONDS = 60.0
T = TypeVar("T")
_WRITE_POLICY = """
import sys
from pathlib import Path
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
GuardStore(Path(sys.argv[1]), prime_policy_integrity=False).upsert_policy(
    PolicyDecision(harness="codex", scope="artifact", action="allow", artifact_id="codex:project:relay-e2e",
                   artifact_hash="sha256:relay-e2e", reason="reviewed", source="local"),
    "2026-06-14T00:00:00Z",
)
"""


# Lifecycle commands consult the OS account's own Guard home (not $HOME) for
# the approval gate and lifecycle locks. Pin both to the temporary home so the
# CLI never reads or locks the developer's real install. The daemon it starts
# still resolves the OS account, so run this on a disposable CI runner or in a
# container rather than on a workstation with Guard installed.
_CLI = """
import sys
from pathlib import Path
from codex_plugin_scanner.guard.adapters import codex_lifecycle_lock
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
home = Path(sys.argv[1])
commands_lifecycle_gate.trusted_user_home = lambda: home
codex_lifecycle_lock._account_home = lambda: home
from codex_plugin_scanner.cli import main
sys.exit(main(sys.argv[2:]))
"""


def _runtime() -> str:
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary or not Path(binary).is_file():
        pytest.skip("HOL_GUARD_NATIVE_BINARY does not name a compiled runtime")
    return str(Path(binary).resolve())


class _Install:
    def __init__(self, root: Path, runtime: str) -> None:
        self.home, self.guard_home, self.workspace = root / "home", root / "guard-home", root / "workspace"
        for directory in (self.home, self.guard_home, self.workspace / ".codex"):
            directory.mkdir(parents=True, mode=0o700)
        server = root / "canary_server.py"
        server.write_text(_SERVER, encoding="utf-8")
        (self.workspace / ".codex" / "config.toml").write_text(
            f"[mcp_servers.canary]\ncommand = {json.dumps(sys.executable)}\nargs = [{json.dumps(str(server))}]\n",
            encoding="utf-8",
        )
        # A source checkout names its source compiler; the daemon asks it
        # whether this installation carries a release bundle.
        keep = {"PATH", "LANG", "LC_ALL", "TMPDIR", "PYTHONPATH", "HOL_GUARD_NATIVE_SOURCE_COMPILER"}
        if os.name == "nt":
            keep |= {"PATHEXT", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP"}
        self.env = {key: value for key, value in os.environ.items() if key in keep}
        if os.name == "nt":
            self.env.update(
                USERPROFILE=str(self.home),
                APPDATA=str(self.home / "AppData" / "Roaming"),
                LOCALAPPDATA=str(self.home / "AppData" / "Local"),
            )
        self.env.update(
            HOME=str(self.home),
            XDG_CONFIG_HOME=str(self.home / ".config"),
            XDG_STATE_HOME=str(self.home / ".local" / "state"),
            XDG_DATA_HOME=str(self.home / ".local" / "share"),
            HOL_GUARD_NATIVE_BINARY=runtime,
            HOL_GUARD_NATIVE="force",
            # A guard home under pytest's temporary root idles out in five
            # seconds; keep the daemon publishing for the whole test.
            GUARD_DAEMON_IDLE_TIMEOUT_SECONDS="300",
        )

    def guard(self, *args: str, extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        places = ("--home", str(self.home), "--guard-home", str(self.guard_home))
        return run_bounded(
            [sys.executable, "-c", _CLI, str(self.home), "guard", *args, *places],
            env={**self.env, **(extra or {})},
            cwd=self.workspace,
            timeout=180,
            text=True,
        )

    def _relay(self) -> tuple[list[str], dict[str, str]]:
        with (self.home / ".codex" / "config.toml").open("rb") as handle:
            entry = tomllib.load(handle)["mcp_servers"]["canary"]
        argv = [str(entry["command"]), *map(str, entry["args"])]
        assert argv[1:2] == ["mcp-relay"], argv
        return argv, {**self.env, **{str(k): str(v) for k, v in dict(entry.get("env", {})).items()}}

    def relay_start(self) -> str:
        """The start line of one relay session that reads no input."""

        argv, env = self._relay()
        completed = run_bounded(
            argv,
            env=env,
            cwd=self.workspace,
            stdin=subprocess.DEVNULL,
            timeout=60,
        )
        return _start_line(completed.stderr.decode("utf-8", errors="replace"))

    def relay_list_tools(self) -> str:
        """The start line of one relay session that lists the server's tools."""

        argv, env = self._relay()
        with subprocess.Popen(
            argv,
            env=env,
            cwd=self.workspace,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as session:
            assert session.stdin is not None and session.stdout is not None
            session.stdin.write(_LIST_TOOLS)
            session.stdin.flush()
            # Hold the session open until the host has the catalog.
            for line in session.stdout:
                if json.loads(line).get("id") == 2:
                    break
            try:
                _, stderr = session.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                session.kill()
                raise
        return _start_line(stderr.decode("utf-8", errors="replace"))

    def integrity(self) -> tuple[object, list[object]]:
        with sqlite3.connect(self.guard_home / "guard.db") as connection:
            row = connection.execute("select payload_json from sync_state where state_key = 'policy_integrity'")
            stored = row.fetchone()
            signed = [item[0] for item in connection.execute("select integrity_generation from policy_decisions")]
        return (json.loads(stored[0]) if stored else None), signed


def _start_line(stderr: str) -> str:
    for line in stderr.splitlines():
        if line.startswith((_LANE_READY, _HAND_OFF, _NOT_READY)):
            return line
    raise AssertionError(f"the relay wrote no start line: {stderr[-2000:]}")


def _until(condition: Callable[[], T | None | bool], what: str) -> T:
    deadline = time.monotonic() + _WAIT_SECONDS
    while time.monotonic() < deadline:
        value = condition()
        if value:
            return cast(T, value)
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture
def installed(tmp_path: Path) -> Iterator[_Install]:
    install = _Install(tmp_path, _runtime())
    try:
        result = install.guard(
            "install", "codex", "--workspace", str(install.workspace), "--json", extra={"HOL_GUARD_MCP_RELAY": "native"}
        )
        assert result.returncode == 0, result.stderr[-2000:]
        result = install.guard("daemon", "ensure", "--workspace", str(install.workspace))
        assert result.returncode == 0, result.stderr[-2000:]
        yield install
    finally:
        install.guard("daemon", "stop", "--json")


def test_a_fresh_install_starts_ready_and_rebinds_after_a_policy_write(installed: _Install) -> None:
    _until(lambda: (installed.guard_home / _ACK).is_file(), "the direct-lane ACK")
    # The lane is bound once the only reason left is the unreported server.
    _until(lambda: installed.relay_start() == _SERVER_UNKNOWN, "a lane bound but for the server")
    assert installed.relay_list_tools() == _SERVER_UNKNOWN
    start = _until(lambda: (line := installed.relay_start()).startswith(_LANE_READY) and line, "a ready lane")
    assert start.startswith(_LANE_READY), start
    state, signed = installed.integrity()
    assert isinstance(state, dict) and signed == []

    written = run_bounded(
        [sys.executable, "-c", _WRITE_POLICY, str(installed.guard_home)],
        env=installed.env,
        cwd=installed.workspace,
        timeout=120,
        text=True,
    )
    assert written.returncode == 0, written.stderr[-2000:]

    # The write leaves the stored state behind the generation it signed; only
    # the daemon's republish brings it current.
    def current() -> dict[str, object] | None:
        stored, generations = installed.integrity()
        if isinstance(stored, dict) and generations and stored.get("generation") == generations[0]:
            return stored
        return None

    republished = _until(current, "the republished integrity state")
    assert republished != state
    assert republished["mode"] == "protected"
    after = _until(lambda: (line := installed.relay_start()).startswith(_LANE_READY) and line, "a ready lane")
    assert after.startswith(_LANE_READY), after

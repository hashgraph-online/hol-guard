"""Launching a pasted script as an MCP server only on evidence from its source.

Recognizing a command as MCP launches it with its real arguments. A resident
that advertises ``local-cli-help-mcp-evidence-v1`` says from the source alone
whether a script serves MCP (``rust/.../local_cli_help_script_facts.rs``);
these tests stand a resident in for it and cover what Guard launches.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
from codex_plugin_scanner.guard.local_cli_trust import utc_now
from codex_plugin_scanner.guard.native_local_cli_help_parse import SourceRead
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_source_evidence import script_may_serve_mcp
from codex_plugin_scanner.guard.store import GuardStore

BRIDGE = "codex_plugin_scanner.guard.native_local_cli_help_parse"
EVIDENCE = "codex_plugin_scanner.guard.runtime.local_mcp_source_evidence"

_FAKE_MCP = """import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "demo"}},
        }), flush=True)
    elif method == "tools/list":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [{"name": "list_pages", "description": "List"}]},
        }), flush=True)
        break
"""


def _resident(
    monkeypatch: pytest.MonkeyPatch,
    serving: set[str],
    *,
    reads_evidence: bool | None = True,
    unreadable: bool = False,
) -> list[str]:
    """Stand in a resident; ``serving`` holds the source texts it calls MCP servers."""

    read: list[str] = []

    def _source(**kwargs: object) -> SourceRead | None:
        text = str(kwargs["text"])
        read.append(text)
        if unreadable:
            return None
        imports = tuple(line.split()[1] for line in text.splitlines() if line.startswith("#import "))
        return SourceRead(
            rows=(),
            help_handler="none",
            imports=imports,
            mcp_server=bool(kwargs.get("mcp_evidence")) and text in serving,
        )

    monkeypatch.setattr(f"{BRIDGE}.resident_reads_mcp_evidence", lambda: reads_evidence)
    monkeypatch.setattr(f"{BRIDGE}.resident_reads_sources_first", lambda: True)
    monkeypatch.setattr(f"{BRIDGE}.native_local_cli_source_read", _source)
    monkeypatch.setattr(f"{BRIDGE}.native_local_cli_help_commands", lambda **_: ())
    return read


def _script(home: Path, name: str, text: str) -> Path:
    path = home / name
    path.write_text(text, encoding="utf-8")
    return path


def _serves(command: str, home: Path) -> bool:
    return script_may_serve_mcp(command, cwd=home, home_dir=home, guard_home=home)


def test_a_script_is_launched_only_when_its_source_serves_mcp(tmp_path: Path, monkeypatch) -> None:
    server = _script(tmp_path, "server.py", "from mcp.server.fastmcp import FastMCP\n")
    ship = _script(tmp_path, "ship.py", "import sys\nprint(sys.argv)\n")
    _resident(monkeypatch, {server.read_text()})
    assert _serves(f"python3 {server} serve", tmp_path)
    assert not _serves(f"python3 {ship} deploy", tmp_path)


def test_a_followed_local_module_can_carry_the_evidence(tmp_path: Path, monkeypatch) -> None:
    module = _script(tmp_path, "server_impl.py", "import fastmcp\n")
    entry = _script(tmp_path, "entry.py", "#import ./server_impl.py\nimport server_impl\n")
    _resident(monkeypatch, {module.read_text()})
    assert _serves(f"python3 {entry}", tmp_path)


def test_a_local_package_initializer_can_carry_the_evidence(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "server"
    package.mkdir()
    initializer = _script(package, "__init__.py", "from fastmcp import FastMCP\n")
    entry = _script(tmp_path, "entry.py", "#import ./server.py\nfrom server import mcp\n")
    _resident(monkeypatch, {initializer.read_text()})
    assert _serves(f"python3 {entry}", tmp_path)


def test_a_script_run_through_a_shell_is_read_not_the_shell(tmp_path: Path, monkeypatch) -> None:
    ship = _script(tmp_path, "ship.sh", "#!/bin/bash\necho deploy\n")
    ship.chmod(0o755)
    read = _resident(monkeypatch, set())
    assert not _serves(f"bash {ship} deploy", tmp_path)
    assert not _serves(f"{ship} deploy", tmp_path)
    assert read == [ship.read_text(), ship.read_text()]


def test_a_failed_lookup_or_unreadable_script_never_launches(tmp_path: Path, monkeypatch) -> None:
    ship = _script(tmp_path, "ship.py", "import sys\n")
    read = _resident(monkeypatch, {ship.read_text()})
    ship.chmod(0)
    try:
        assert not _serves(f"python3 {ship} deploy", tmp_path)
    finally:
        ship.chmod(0o644)
    monkeypatch.setattr(f"{EVIDENCE}.identify_unlisted_cli", lambda *_args, **_kwargs: None)
    assert not _serves(f"python3 {ship} deploy", tmp_path)
    assert read == []


def test_an_older_resident_keeps_the_launch(tmp_path: Path, monkeypatch) -> None:
    ship = _script(tmp_path, "ship.py", "import sys\n")
    read = _resident(monkeypatch, set(), reads_evidence=False)
    assert _serves(f"python3 {ship} deploy", tmp_path)
    assert read == []


def test_an_unreadable_status_or_answer_never_launches(tmp_path: Path, monkeypatch) -> None:
    ship = _script(tmp_path, "ship.py", "import sys\n")
    read = _resident(monkeypatch, set(), reads_evidence=None)
    assert not _serves(f"python3 {ship} deploy", tmp_path)
    assert read == []
    _resident(monkeypatch, {ship.read_text()}, unreadable=True)
    assert not _serves(f"python3 {ship} deploy", tmp_path)


def test_a_compiled_program_keeps_the_launch(tmp_path: Path, monkeypatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    program = bin_dir / "demo-server"
    program.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    program.chmod(0o755)
    monkeypatch.setenv("PATH", os.pathsep.join((str(bin_dir), "/usr/bin", "/bin")))
    read = _resident(monkeypatch, set(), reads_evidence=None)
    assert _serves("demo-server --stdio", tmp_path)
    assert read == []


def _recognizer(tmp_path: Path, monkeypatch) -> tuple[Path, LocalCliApiService]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.local_cli_api.Path.home", staticmethod(lambda: home))
    return home, LocalCliApiService(store=GuardStore(home))


def test_recognize_never_launches_a_script_without_evidence(tmp_path: Path, monkeypatch) -> None:
    home, service = _recognizer(tmp_path, monkeypatch)
    ran = tmp_path / "ran"
    script = _script(home, "ship.py", f"from pathlib import Path\nPath({str(ran)!r}).write_text('ran')\n")
    _resident(monkeypatch, set())
    service.recognize({"command": f"python3 {script} deploy"})
    assert not ran.exists()


def test_a_stored_connection_exempts_only_its_own_launch(tmp_path: Path, monkeypatch) -> None:
    home, service = _recognizer(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.local_cli_api.discover_harness_mcp_servers", lambda **_kwargs: []
    )
    identity = UnlistedCliIdentity(
        cli_id="local-cli.mcp-stored",
        name="Stored connector",
        kind="executable",
        identity_hash="d" * 64,
        example_label="Observed through a host",
        interpreter_name=None,
    )
    service._store.record_local_cli_observation(
        identity, seen_at=utc_now(), surface="mcp", server_command="other-server", server_args_hash="e" * 64
    )
    ran = tmp_path / "ran"
    script = _script(home, "ship.py", f"from pathlib import Path\nPath({str(ran)!r}).write_text('ran')\n")
    _resident(monkeypatch, set())
    service.recognize({"cli_id": identity.cli_id, "command": f"python3 {script} deploy"})
    assert not ran.exists()


def test_recognize_launches_a_script_whose_source_serves_mcp(tmp_path: Path, monkeypatch, native_mcp_probe) -> None:
    home, service = _recognizer(tmp_path, monkeypatch)
    native_mcp_probe(home)
    server = _script(home, "server.py", _FAKE_MCP)
    _resident(monkeypatch, {_FAKE_MCP})
    item = service.recognize({"command": f"python3 {server}"})["item"]
    assert isinstance(item, dict)
    assert item["surface"] == "mcp"

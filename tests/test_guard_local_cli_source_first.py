"""Reading a script's source before Guard runs it with --help.

A resident that advertises ``local-cli-help-source-first-v1`` says what a
script takes and whether it answers --help from the source alone. The
reading is the resident's (``rust/.../local_cli_help_script*.rs``); these
tests stand a resident in for it and cover what Guard runs on its answer.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_local_cli_help_parse import SourceRead
from codex_plugin_scanner.guard.runtime.local_cli_help import discover_local_cli_commands
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_cli_script_source import MAX_FOLLOWED_IMPORTS, local_import_paths

BRIDGE = "codex_plugin_scanner.guard.native_local_cli_help_parse"

PIN_SCRIPT = """#!/usr/bin/env node
const [,, action] = process.argv;
if (action !== 'pin' && action !== 'unpin') process.exit(1);
"""


def _identity(name: str, kind: str = "script") -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=f"local-cli.{name}-00000000",
        name=name,
        kind=kind,
        identity_hash="0" * 64,
        example_label=name,
    )


def _row(name: str, description: str = "") -> dict[str, object]:
    return {"command_id": name, "name": name, "usage": name, "description": description, "parent_id": None}


def _read(*names: str, handler: str = "none", imports: Sequence[str] = ()) -> SourceRead:
    return SourceRead(rows=tuple(_row(name) for name in names), help_handler=handler, imports=tuple(imports))


def _resident(
    monkeypatch: pytest.MonkeyPatch,
    sources: dict[str, SourceRead | None],
    help_rows: tuple[dict[str, object], ...] | None = (),
) -> list[str]:
    """Stand in a source-first resident; return the source texts it was sent."""

    read: list[str] = []

    def _source(**kwargs: object) -> SourceRead | None:
        text = str(kwargs["text"])
        read.append(text)
        return sources.get(text)

    monkeypatch.setattr(f"{BRIDGE}.resident_reads_sources_first", lambda: True)
    monkeypatch.setattr(f"{BRIDGE}.native_local_cli_source_read", _source)
    monkeypatch.setattr(f"{BRIDGE}.native_local_cli_help_commands", lambda **_: help_rows)
    return read


def _probe(output: str = "Usage: tool <command>\n") -> tuple[list[tuple[str, ...]], object]:
    ran: list[tuple[str, ...]] = []

    def run(argv: Sequence[str]) -> str:
        ran.append(tuple(argv))
        return output

    return ran, run


def _script(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _ids(commands) -> list[str]:
    return [command.command_id for command in commands]


def test_a_script_that_never_looks_for_help_is_not_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = _script(tmp_path, "pin.mjs", PIN_SCRIPT)
    _resident(monkeypatch, {PIN_SCRIPT: _read("pin", "unpin")})
    ran, probe = _probe()
    commands, status = discover_local_cli_commands(
        _identity("pin.mjs"), ("/usr/bin/node", str(script), "--help"), runner=probe
    )
    assert ran == []
    assert status == "ok"
    assert _ids(commands) == ["root", "pin", "unpin", "other"]


def test_a_script_with_nothing_to_find_is_still_not_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = _script(tmp_path, "pin.mjs", PIN_SCRIPT)
    _resident(monkeypatch, {PIN_SCRIPT: _read()})
    ran, probe = _probe()
    _, status = discover_local_cli_commands(
        _identity("pin.mjs"), ("/usr/bin/node", str(script), "--help"), runner=probe
    )
    assert (ran, status) == ([], "empty")


def test_a_resident_that_cannot_read_the_source_runs_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = _script(tmp_path, "pin.mjs", PIN_SCRIPT)
    _resident(monkeypatch, {PIN_SCRIPT: None})
    ran, probe = _probe()
    _, status = discover_local_cli_commands(
        _identity("pin.mjs"), ("/usr/bin/node", str(script), "--help"), runner=probe
    )
    assert (ran, status) == ([], "failed")


def test_a_runtime_whose_status_cannot_be_read_runs_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A busy or missing resident is not an older one: the script is never run unread."""

    script = _script(tmp_path, "pin.mjs", PIN_SCRIPT)
    monkeypatch.setattr(f"{BRIDGE}.resident_reads_sources_first", lambda: None)
    ran, probe = _probe()
    _, status = discover_local_cli_commands(
        _identity("pin.mjs"), ("/usr/bin/node", str(script), "--help"), runner=probe
    )
    assert (ran, status) == ([], "failed")


@pytest.mark.parametrize(
    "status",
    [
        RuntimeError("native_runtime_status_deadline"),
        SimpleNamespace(available=False, compatible=True, capabilities=SimpleNamespace(features=())),
        SimpleNamespace(available=True, compatible=False, capabilities=SimpleNamespace(features=())),
        SimpleNamespace(available=True, compatible=True, capabilities=None),
    ],
)
def test_an_unreadable_runtime_status_is_unknown_not_older(monkeypatch: pytest.MonkeyPatch, status: object) -> None:
    from codex_plugin_scanner.guard import native_local_cli_help_parse as bridge

    def _status() -> object:
        if isinstance(status, Exception):
            raise status
        return status

    monkeypatch.setattr(bridge, "native_runtime_status", _status)
    assert bridge.resident_reads_sources_first() is None


def test_only_a_runtime_that_lists_its_features_can_be_older(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_local_cli_help_parse as bridge

    def _listing(*features: str) -> object:
        return SimpleNamespace(available=True, compatible=True, capabilities=SimpleNamespace(features=features))

    monkeypatch.setattr(bridge, "native_runtime_status", lambda: _listing("local-cli-help-parse-v1"))
    assert bridge.resident_reads_sources_first() is False
    monkeypatch.setattr(bridge, "native_runtime_status", lambda: _listing(bridge.LOCAL_CLI_HELP_SOURCE_FIRST_FEATURE))
    assert bridge.resident_reads_sources_first() is True


def test_a_script_that_answers_help_itself_runs_once_and_never_per_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A hand-written check answers only the top-level --help; ``build --help`` could run build."""

    script = _script(tmp_path, "tool.py", "import sys\n")
    _resident(monkeypatch, {"import sys\n": _read("build", "--dry-run", handler="script")}, (_row("build", "Build"),))
    ran, probe = _probe()
    commands, status = discover_local_cli_commands(
        _identity("tool.py"), ("/usr/bin/python3", str(script), "--help"), runner=probe
    )
    assert ran == [("/usr/bin/python3", str(script), "--help")]
    assert status == "ok"
    assert _ids(commands) == ["root", "build", "--dry-run", "other"]
    # Help output describes a command better than the source does.
    assert commands[1].description == "Build"


def test_a_parser_library_answers_help_for_each_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = _script(tmp_path, "tool.py", "import argparse\n")
    _resident(monkeypatch, {"import argparse\n": _read("build", handler="framework")}, (_row("build"),))
    ran, probe = _probe()
    discover_local_cli_commands(_identity("tool.py"), ("/usr/bin/python3", str(script), "--help"), runner=probe)
    assert ran == [
        ("/usr/bin/python3", str(script), "--help"),
        ("/usr/bin/python3", str(script), "build", "--help"),
    ]


def test_a_local_module_the_script_imports_is_read_too(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entry = "import { main } from './lib/cli.mjs';\nmain();\n"
    module = "switch (process.argv[2]) { case 'sync': break; }\n"
    script = _script(tmp_path, "tool.mjs", entry)
    (tmp_path / "lib").mkdir()
    _script(tmp_path / "lib", "cli.mjs", module)
    read = _resident(monkeypatch, {entry: _read(imports=["./lib/cli.mjs"]), module: _read("sync")})
    ran, probe = _probe()
    commands, _ = discover_local_cli_commands(
        _identity("tool.mjs"), ("/usr/bin/node", str(script), "--help"), runner=probe
    )
    assert read == [entry, module]
    assert ran == []
    assert "sync" in _ids(commands)


def test_help_handled_in_an_imported_module_lets_the_script_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = "from cli import main\nmain()\n"
    module = "import argparse\n"
    script = _script(tmp_path, "tool.py", entry)
    _script(tmp_path, "cli.py", module)
    _resident(monkeypatch, {entry: _read(imports=["./cli.py"]), module: _read(handler="framework")})
    ran, probe = _probe()
    discover_local_cli_commands(_identity("tool.py"), ("/usr/bin/python3", str(script), "--help"), runner=probe)
    assert ran == [("/usr/bin/python3", str(script), "--help")]


def test_a_compiled_program_still_runs_its_help(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    program = tmp_path / "tool"
    program.write_bytes(b"\xcf\xfa\xed\xfe binary")
    read = _resident(monkeypatch, {}, (_row("deploy"),))
    ran, probe = _probe()
    commands, status = discover_local_cli_commands(
        _identity("tool", kind="executable"), (str(program), "--help"), runner=probe
    )
    assert read == []
    assert ran[0] == (str(program), "--help")
    assert (status, "deploy" in _ids(commands)) == ("ok", True)


def test_only_script_files_inside_the_scripts_folder_are_followed(tmp_path: Path) -> None:
    folder = tmp_path / "tool"
    folder.mkdir()
    script = _script(folder, "main.mjs", "")
    _script(folder, "cli.mjs", "")
    _script(folder, "data.json", "{}")
    _script(tmp_path, "outside.mjs", "")
    (folder / "escape.mjs").symlink_to(tmp_path / "outside.mjs")
    (folder / "pkg").mkdir()
    imports = ["./cli", "./data.json", "./../outside.mjs", "./escape.mjs", "./pkg", "./main.mjs", "./missing.mjs"]
    assert local_import_paths(str(script), imports) == (str((folder / "cli.mjs").resolve()),)


def test_at_most_a_few_imports_are_followed(tmp_path: Path) -> None:
    script = _script(tmp_path, "main.py", "")
    names = [f"m{index}" for index in range(MAX_FOLLOWED_IMPORTS + 3)]
    for name in names:
        _script(tmp_path, f"{name}.py", "")
    found = local_import_paths(str(script), [f"./{name}.py" for name in names])
    assert len(found) == MAX_FOLLOWED_IMPORTS


@pytest.mark.skipif(os.name == "nt", reason="symlinked folders need POSIX permissions")
def test_a_script_reached_through_a_symlink_reads_beside_its_real_file(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    script = _script(real, "main.py", "")
    _script(real, "cli.py", "")
    link = tmp_path / "bin"
    link.mkdir()
    (link / "main.py").symlink_to(script)
    assert local_import_paths(str(link / "main.py"), ["./cli.py"]) == (str((real / "cli.py").resolve()),)


@pytest.mark.parametrize(
    "payload",
    [
        {"commands": [], "imports": []},
        {"commands": [], "help_handler": "maybe", "imports": []},
        {"commands": [], "help_handler": "none", "imports": "./lib.mjs"},
        {"commands": [], "help_handler": "none", "imports": ["/etc/passwd"]},
        {"commands": [], "help_handler": "none", "imports": [7]},
        {"commands": [{"command_id": "x"}], "help_handler": "none", "imports": []},
    ],
)
def test_a_source_read_with_a_malformed_field_is_discarded_whole(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: dict[str, object]
) -> None:
    from codex_plugin_scanner.guard import native_local_cli_help_parse as bridge

    unusable: list[Path] = []
    monkeypatch.setattr(bridge, "_request", lambda *args, **kwargs: payload)
    monkeypatch.setattr(bridge, "_unusable", lambda home: unusable.append(home))
    assert bridge.native_local_cli_source_read(guard_home=tmp_path, text="x", invocation=("tool",)) is None
    assert unusable == [tmp_path]


def test_a_well_formed_source_read_keeps_every_field(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_local_cli_help_parse as bridge

    payload = {"commands": [_row("go")], "help_handler": "script", "imports": ["./lib/run.mjs"]}
    monkeypatch.setattr(bridge, "_request", lambda *args, **kwargs: payload)
    read = bridge.native_local_cli_source_read(guard_home=tmp_path, text="x", invocation=("tool",))
    assert read == SourceRead(rows=(_row("go"),), help_handler="script", imports=("./lib/run.mjs",))

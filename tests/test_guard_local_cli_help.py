"""The Python side of local CLI command discovery.

Reading a script's source, running ``--help`` and parsing what it prints is
the native ``local-cli-discover`` command
(``rust/crates/guard-runtime/src/local_cli_discover.rs``). The parse's
decisions are recorded in ``tests/fixtures/guard-local-cli-help-parse.v1.json``,
which the Rust suite replays. The tests here cover the request Guard sends, how
it reads the answer, and the catalog merge around it.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime, native_runtime
from codex_plugin_scanner.guard.runtime.local_cli_commands import (
    LocalCliCommand,
    is_local_cli_command_id,
    merge_discovered_commands,
    slug_local_cli_command_ids,
)
from codex_plugin_scanner.guard.runtime.local_cli_help import (
    LOCAL_CLI_DISCOVER_COMMAND,
    LOCAL_CLI_DISCOVER_FEATURE,
    discover_local_cli_commands,
)
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli
from tests.local_cli_command_id_client import command_tokens_for_invocation, match_command_id

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/guard-local-cli-help-parse.v1.json"


def _command(command_id: str, description: str = "", parent_id: str | None = None) -> LocalCliCommand:
    name = command_id.rpartition(".")[2]
    return LocalCliCommand(
        command_id=command_id,
        name=name,
        usage=name,
        description=description,
        parent_id=parent_id,
    )


def test_the_fixture_keeps_recording_the_dialects_rust_replays() -> None:
    names = {case["name"] for case in json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]}
    assert {
        "wrangler-click-style",
        "argparse-choice-set",
        "cobra-available-commands",
        "yargs-groups",
        "yargs-nested-group",
    } <= names


def _identity(name: str = "wrangler") -> UnlistedCliIdentity:
    return UnlistedCliIdentity(
        cli_id=f"local-cli.{name}-00000000",
        name=name,
        kind="executable",
        identity_hash="0" * 64,
        example_label=name,
    )


def _status(tmp_path: Path, features: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "hol-guard-runtime"),
        capabilities=SimpleNamespace(features=features),
    )


def _native(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    response: object,
    *,
    features: tuple[str, ...] = (LOCAL_CLI_DISCOVER_FEATURE,),
    returncode: int = 0,
) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status(tmp_path, features))

    def run(argv: tuple[str, ...], **options: object) -> SimpleNamespace:
        assert argv[1:] == (LOCAL_CLI_DISCOVER_COMMAND, "--stdin")
        sent.append({**json.loads(str(options["input_text"])), "_stop_event": options.get("stop_event")})
        return SimpleNamespace(
            returncode=returncode,
            timed_out=False,
            output_limit_exceeded=False,
            containment_failed=False,
            stdout=json.dumps(response),
        )

    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", run)
    return sent


def _row(command_id: str, parent_id: str | None = None) -> dict[str, object]:
    name = command_id.replace(".", " ")
    return {"command_id": command_id, "name": name, "usage": name, "description": "", "parent_id": parent_id}


def _ids(commands: tuple[LocalCliCommand, ...]) -> list[str]:
    return [command.command_id for command in commands]


def test_discovery_sends_the_verified_argv(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    rows = [_row("deploy"), _row("deploy.preview", "deploy")]
    sent = _native(monkeypatch, tmp_path, {"ok": True, "result": {"commands": rows, "status": "ok"}})
    cancel = threading.Event()

    commands, status = discover_local_cli_commands(_identity(), ("/opt/wrangler", "--help"), cancel=cancel)

    assert status == "ok"
    assert _ids(commands) == ["root", "deploy", "deploy.preview", "other"]
    assert commands[2].parent_id == "deploy"
    assert sent == [
        {"name": "wrangler", "kind": "executable", "argv": ["/opt/wrangler", "--help"], "_stop_event": cancel}
    ]


def test_a_cli_that_names_nothing_is_still_empty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _native(monkeypatch, tmp_path, {"ok": True, "result": {"commands": [], "status": "empty"}})
    commands, status = discover_local_cli_commands(_identity(), ("/opt/wrangler", "--help"))
    assert status == "empty"
    assert _ids(commands) == ["root", "other"]


@pytest.mark.parametrize(
    "response",
    [
        {"ok": False, "error": "argv must end with --help"},
        {"ok": True, "result": {"commands": [], "status": "maybe"}},
        {"ok": True, "result": {"commands": [{"command_id": "deploy"}], "status": "ok"}},
        {"ok": True, "result": {"commands": [{**_row("deploy"), "parent_id": 3}], "status": "ok"}},
        {"ok": True, "result": "ok"},
    ],
)
def test_an_answer_guard_cannot_read_is_a_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: object
) -> None:
    _native(monkeypatch, tmp_path, response)
    commands, status = discover_local_cli_commands(_identity(), ("/opt/wrangler", "--help"))
    assert status == "failed"
    assert _ids(commands) == ["root", "other"]


def test_a_runtime_without_the_command_is_a_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _native(monkeypatch, tmp_path, {"ok": True, "result": {"commands": [], "status": "ok"}}, features=())
    _, status = discover_local_cli_commands(_identity(), ("/opt/wrangler", "--help"))
    assert status == "failed"
    assert sent == []


def test_a_command_that_exits_badly_is_a_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _native(monkeypatch, tmp_path, {"ok": True, "result": {"commands": [], "status": "ok"}}, returncode=2)
    _, status = discover_local_cli_commands(_identity(), ("/opt/wrangler", "--help"))
    assert status == "failed"


def test_a_cancel_set_beforehand_starts_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sent = _native(monkeypatch, tmp_path, {"ok": True, "result": {"commands": [], "status": "ok"}})
    cancel = threading.Event()
    cancel.set()
    _, status = discover_local_cli_commands(_identity(), ("/opt/wrangler", "--help"), cancel=cancel)
    assert status == "failed"
    assert sent == []


def test_merge_keeps_root_and_other() -> None:
    discovered = tuple(_command(name) for name in ("docs", "init", "dev", "deploy", "pages"))
    merged = merge_discovered_commands("wrangler", discovered)
    assert merged[0].command_id == "root"
    assert merged[-1].command_id == "other"
    assert [command.command_id for command in merged[1:-1]] == ["docs", "init", "dev", "deploy", "pages"]


def test_match_longest_subcommand(tmp_path: Path) -> None:
    tool = tmp_path / "ship"
    tool.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    tool.chmod(0o755)
    identity = identify_unlisted_cli(f"{tool} pages deploy --env prod", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    tokens = command_tokens_for_invocation(
        f"{tool} pages deploy --env prod",
        cwd=tmp_path,
        home_dir=tmp_path,
        identity=identity,
    )
    assert tokens == ("pages", "deploy")
    catalog = merge_discovered_commands("ship", (_command("pages", "Pages"),))
    assert match_command_id(tokens, catalog) == "pages"
    nested = merge_discovered_commands(
        "ship",
        (_command("pages", "Pages"), _command("pages.deploy", "Deploy", parent_id="pages")),
    )
    assert match_command_id(tokens, nested) == "pages.deploy"


def test_option_ids_are_catalog_ids_but_never_tool_slugs() -> None:
    for option in ("--dry-run", "-n", "--2fa"):
        assert is_local_cli_command_id(option)
    for bad in ("-", "--", "-xy", "---x", "--a.b"):
        assert not is_local_cli_command_id(bad)
    assert not slug_local_cli_command_ids(("--dry-run",))[0].startswith("-")


def test_a_catalog_without_options_keeps_its_root_wording() -> None:
    plain = merge_discovered_commands("tool", (_command("deploy"),))
    assert plain[0].description == "Run tool without a subcommand."

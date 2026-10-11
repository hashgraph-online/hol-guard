from __future__ import annotations

import argparse
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_contained_write as cli_module
from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition


def test_cli_parser_and_json_output_expose_no_paths_or_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    result = SimpleNamespace(
        exit_code=0,
        stdout="private-content",
        stderr="",
        proof=SimpleNamespace(binding_digest="proof-digest"),
        decision=SimpleNamespace(disposition=FinalDisposition.SILENT_CONTAINED),
        operation_id="copy-generated",
        output_digest="output-digest",
    )
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)
    args = parser.parse_args(
        ("contained-write", "--workspace", str(workspace), "copy", "in.json", "out.json", "--json")
    )
    seen: dict[str, object] = {}

    def execute_write(operation: str, **kwargs: object) -> SimpleNamespace:
        seen["operation"] = operation
        seen.update(kwargs)
        return result

    monkeypatch.setattr(cli_module, "try_execute_contained_workspace_write", execute_write)
    output = io.StringIO()
    status = cli_module._run_guard_contained_write_command(
        args,
        guard_home=guard_home,
        workspace=workspace,
        output_stream=output,
    )

    assert status == 0
    assert seen["operation"] == "copy-generated"
    assert seen["source"] == "in.json"
    assert seen["target"] == "out.json"
    payload = output.getvalue()
    assert "private-content" not in payload
    assert str(tmp_path) not in payload
    assert '"decision":"silent-contained"' in payload

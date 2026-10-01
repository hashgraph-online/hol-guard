"""Maintainer preparation validates exact declarative source/fixture bindings."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from tests.extension_builder_support import REPOSITORY

spec = importlib.util.spec_from_file_location(
    "prepare_extension_contribution", REPOSITORY / "scripts/prepare_extension_contribution.py"
)
assert spec and spec.loader
prepare = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = prepare
spec.loader.exec_module(prepare)


def source() -> dict[str, object]:
    return {"schemaVersion": "guard.command-extension-source.v1", "extension": {"extension_id": "command.demo"}}


def fixture(payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "guard.command-extension-fixtures.v1",
        "build": {"schema": "guard.command-extension-build.v1", "sources": [payload]},
        "cases": [],
    }


def write_inputs(root: Path) -> tuple[Path, Path]:
    source_path = root / "contributions/command-sources/command.demo.json"
    fixture_path = root / "tests/fixtures/command-source-demo.v1.json"
    source_path.parent.mkdir(parents=True)
    fixture_path.parent.mkdir(parents=True)
    source_path.write_text(json.dumps(source()))
    fixture_path.write_text(json.dumps(fixture(source())))
    return source_path, fixture_path


def test_changed_source_requires_a_fixture_bound_to_the_exact_json_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare, "ROOT", tmp_path)
    source_path, fixture_path = write_inputs(tmp_path)
    assert prepare._validate_changed_source_fixture_pairs(
        {source_path.relative_to(tmp_path).as_posix()}, [fixture_path]
    ) == [fixture_path]
    fixture_path.write_text(json.dumps(fixture({"extension": {"extension_id": "command.demo"}, "changed": True})))
    with pytest.raises(ValueError, match="matching portable fixture"):
        prepare._validate_changed_source_fixture_pairs({source_path.relative_to(tmp_path).as_posix()}, [fixture_path])


def test_changed_fixture_must_bind_to_the_current_canonical_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare, "ROOT", tmp_path)
    _, fixture_path = write_inputs(tmp_path)
    fixture_path.write_text(json.dumps(fixture({"extension": {"extension_id": "command.demo"}, "changed": True})))
    with pytest.raises(ValueError, match="Changed fixture needs to bind the exact canonical source"):
        prepare._validate_changed_source_fixture_pairs({fixture_path.relative_to(tmp_path).as_posix()}, [fixture_path])


def test_deleted_fixture_must_leave_a_binding_for_its_current_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare, "ROOT", tmp_path)
    _, fixture_path = write_inputs(tmp_path)
    fixture_path.unlink()
    monkeypatch.setattr(prepare, "_previous_fixture_source_ids", lambda *_: {"command.demo": source()})
    with pytest.raises(ValueError, match="matching portable fixture"):
        prepare._validate_changed_source_fixture_pairs(
            {fixture_path.relative_to(tmp_path).as_posix()}, [], revision="base"
        )


def test_prepare_rejects_source_or_fixture_paths_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(prepare, "ROOT", tmp_path)
    outside = tmp_path.parent / "outside-fixture.json"
    outside.write_text(json.dumps(fixture(source())))

    with pytest.raises(ValueError, match="inside this repository"):
        prepare._load_object(outside)


def test_prepare_checks_fixture_without_executing_a_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(prepare, "ROOT", tmp_path)
    source_path, fixture_path = write_inputs(tmp_path)
    compiler = tmp_path / "guard-command-source"
    compiler.write_text("compiler")
    calls: list[tuple[list[str], bytes | None]] = []

    def run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
        calls.append((command, input_bytes))
        if command[-1] == "test":
            return b'{"ok":true,"target_commands_executed":0}'
        return b"{}"

    monkeypatch.setattr(prepare, "_run", run)
    assert (
        prepare.main(
            [
                "--check",
                "--compiler",
                str(compiler),
                "--source",
                str(source_path),
                "--fixture",
                str(fixture_path),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "checked": True,
        "fixtures": ["tests/fixtures/command-source-demo.v1.json"],
        "ok": True,
        "targetCommandsExecuted": 0,
    }
    assert calls[0][0][-1] == "test"
    assert calls[0][1] == fixture_path.read_bytes()
    assert all("--check" in command for command, _ in calls[1:])


def test_authoring_workflow_compares_every_pr_source_change_to_its_base() -> None:
    workflow = (REPOSITORY / ".github/workflows/extension-builder-ci.yml").read_text(encoding="utf-8")
    assert "fetch-depth: 0" in workflow
    assert '--changed-from "${{ github.event.pull_request.base.sha }}"' in workflow

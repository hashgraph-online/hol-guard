"""Maintainer preparation validates exact declarative source/fixture bindings."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

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
    assert "base=$(git rev-parse HEAD^1)" in workflow
    assert 'arguments+=(--changed-from "$base")' in workflow


@pytest.mark.skipif(os.name == "nt", reason="The workflow gate executes in Bash")
@pytest.mark.parametrize("generated_in_pr", [False, True])
def test_authoring_gate_distinguishes_upstream_projections_from_pr_changes(
    tmp_path: Path, generated_in_pr: bool
) -> None:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def write(relative: str, content: str) -> None:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    git("init", "--initial-branch=main")
    write("contracts/extensions/native-command-program.v1.json", "old program\n")
    write("contracts/extensions/command-catalog.v1.json", "old catalog\n")
    write("src/fixture", "fixture\n")
    write("docs/fixture", "fixture\n")
    git("add", ".")
    git("commit", "-m", "base")
    old_base = git("rev-parse", "HEAD")
    git("checkout", "-b", "contribution")
    write("contributions/command-sources/command.demo.json", "source\n")
    write("contracts/extensions/trust-class-map.v1.json", "external contribution\n")
    if generated_in_pr:
        write("contracts/extensions/command-catalog.v1.json", "contributor projection\n")
    git("add", ".")
    git("commit", "-m", "contribution")
    git("checkout", "main")
    write("contracts/extensions/native-command-program.v1.json", "new upstream program\n")
    git("add", ".")
    git("commit", "-m", "upstream regeneration")
    git("merge", "--no-ff", "contribution", "-m", "synthetic PR merge")

    # Only the gate is under test; native compilation is covered by the builder suite.
    write("bin/uv", '#!/bin/sh\ncase "$*" in *detect_pending_extension_regen.py*) echo true;; esac\n')
    (tmp_path / "bin/uv").chmod(0o755)
    workflow = yaml.safe_load((REPOSITORY / ".github/workflows/extension-builder-ci.yml").read_text())
    commands = next(
        step["run"]
        for step in workflow["jobs"]["authoring"]["steps"]
        if step.get("name") == "Verify native public directory projections"
    )
    commands = commands.replace("${{ github.event_name }}", "pull_request")
    commands = commands.replace("${{ github.event.pull_request.base.sha }}", old_base)
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", commands],
        cwd=tmp_path,
        env={
            **os.environ,
            "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "HOL_GUARD_NATIVE_SOURCE_COMPILER": "fixture-compiler",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert (completed.returncode != 0) is generated_in_pr, completed.stderr
    assert ("generated projections are maintainer-owned" in completed.stderr) is generated_in_pr

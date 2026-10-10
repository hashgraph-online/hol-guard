"""Keep native build scratch outputs separate from public contribution records."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def projection_builder(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "projection_destination_test", ROOT / "scripts/build_native_command_program.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    compiler = tmp_path / "compiler"
    compiler.touch()
    trust = {"classes": {"external": ["command.example"]}}
    program = {
        "extensions": [{"extension_id": "command.example"}],
        "program_digest": "a" * 64,
        "catalog_digest": "b" * 64,
    }
    descriptor = {"id": "command.example", "description": "Current compiled metadata"}
    compiled = {
        "catalog_projection_kind": "complete",
        "program": program,
        "catalog": [],
        "descriptors": [descriptor],
        "source_digest": "c" * 64,
        "implementation_digest": "d" * 64,
    }
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "ARTIFACT", tmp_path / "contracts/extensions/native-command-program.v1.json")
    monkeypatch.setattr(
        module,
        "build_request",
        lambda: {
            "trust": trust,
            "sources": [{"extension": {"extension_id": "command.example"}}],
            "mcp_sources": [],
        },
    )
    monkeypatch.setattr(module, "implementation_digest", lambda: "d" * 64)
    public_blobs = {}

    def run(command, **kwargs):
        if command[0] == "git":
            content = public_blobs.get(command[-1])
            return subprocess.CompletedProcess(command, int(content is None), content or b"", b"")
        response = {
            "compile": compiled,
            "export-built": compiled,
            "export-trust": trust,
            "evaluate-batch": program,
        }[command[-1]]
        return subprocess.CompletedProcess(command, 0, json.dumps(response).encode())

    monkeypatch.setattr(module.subprocess, "run", run)

    def build(*arguments):
        monkeypatch.setattr(sys, "argv", ["build", "--compiler", str(compiler), *arguments])
        return module.main()

    build.public_blobs = public_blobs
    return build, descriptor


def test_normal_build_and_check_preserve_stale_and_extra_public_records(tmp_path, projection_builder):
    build, descriptor = projection_builder
    public = tmp_path / "contributions/extensions"
    public.mkdir(parents=True)
    original = {
        "command.example.json": b'{"description":"Published profile with its existing links"}\n',
        "command.retired.json": b'{"description":"Existing public reference"}\n',
    }
    for name, content in original.items():
        (public / name).write_bytes(content)
    assert build() == 0
    generated = tmp_path / "contracts/extensions/build-descriptors/command.example.json"
    assert json.loads(generated.read_bytes()) == descriptor
    assert build("--check") == 0
    assert {path.name: path.read_bytes() for path in public.iterdir()} == original


def test_check_rejects_stale_runtime_output_without_repairing_it(tmp_path, projection_builder, capsys):
    build, _ = projection_builder
    assert build() == 0
    generated = tmp_path / "contracts/extensions/build-descriptors/command.example.json"
    generated.write_bytes(b"{}\n")
    capsys.readouterr()
    assert build("--check") == 1
    result = json.loads(capsys.readouterr().out)
    assert "contracts/extensions/build-descriptors/command.example.json" in result["stale"]
    assert generated.read_bytes() == b"{}\n"


def test_publication_explicitly_selects_public_destination(tmp_path, projection_builder):
    build, descriptor = projection_builder
    assert build("--descriptor-dir", "contributions/extensions") == 0
    published = tmp_path / "contributions/extensions/command.example.json"
    assert json.loads(published.read_bytes()) == descriptor
    assert build("--descriptor-dir", "contributions/extensions", "--check") == 0
    assert not (tmp_path / "contracts/extensions/build-descriptors").exists()


def test_selected_public_record_preserves_unrelated_public_files(tmp_path, projection_builder):
    build, descriptor = projection_builder
    public = tmp_path / "contributions/extensions"
    public.mkdir(parents=True)
    unrelated = public / "command.unrelated.json"
    unrelated.write_bytes(b"Public publisher record and references\n")
    assert build("--publish-descriptor", "command.example") == 0
    assert json.loads((public / "command.example.json").read_bytes()) == descriptor
    assert unrelated.read_bytes() == b"Public publisher record and references\n"
    assert build("--publish-descriptor", "command.example", "--check") == 0


def test_scratch_repair_cannot_hide_missing_committed_public_record(tmp_path, projection_builder, capsys):
    build, descriptor = projection_builder
    assert build("--publish-descriptor", "command.example") == 0
    capsys.readouterr()
    assert build("--check-public-descriptors") == 1
    assert json.loads(capsys.readouterr().out)["stale_public_descriptors"] == [
        "contributions/extensions/command.example.json"
    ]
    build.public_blobs["HEAD:contributions/extensions/command.example.json"] = (
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    assert build("--check-public-descriptors") == 0


def test_publication_does_not_automatically_delete_public_references(tmp_path, projection_builder):
    build, _ = projection_builder
    public = tmp_path / "contributions/extensions"
    public.mkdir(parents=True)
    retired = public / "command.retired.json"
    retired.write_bytes(b"Existing public reference\n")
    with pytest.raises(ValueError, match="explicit retirement"):
        build("--descriptor-dir", "contributions/extensions")
    assert retired.read_bytes() == b"Existing public reference\n"

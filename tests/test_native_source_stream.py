"""Build orchestration preserves raw native-validation inputs and bounded I/O."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def generator(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "source_stream_test", ROOT / "scripts/build_native_command_program.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(
        module, "_trust_request_payload", lambda: {"classes": {"external": ["command.one", "command.two"]}}
    )
    (tmp_path / "contributions/command-sources").mkdir(parents=True)
    (tmp_path / "contributions/mcp-servers").mkdir(parents=True)
    return module


def write_source(generator, identity, data=None):
    path = generator.ROOT / f"contributions/command-sources/{identity}.json"
    path.write_bytes(data or json.dumps({"extension": {"extension_id": identity}}).encode())
    return path


def read_frame(stream):
    return stream.read(int.from_bytes(stream.read(4), "big"))


def test_raw_records_above_the_old_aggregate_budget_are_not_normalized(generator):
    one = b'{"extension":{"extension_id":"command.one"}}' + b" " * (5 * 1024 * 1024)
    two = b'{"extension":{"extension_id":"command.two"}}' + b"\n" * (5 * 1024 * 1024)
    write_source(generator, "command.one", one)
    write_source(generator, "command.two", two)
    with generator.source_stream() as (stream, trust, paths):
        assert stream.read(5) == b"HGCS\x01"
        header = json.loads(read_frame(stream))
        assert header == {
            "schema": "guard.command-extension-source-stream.v1",
            "sources": 2,
            "mcp_sources": 0,
            "trust": trust,
        }
        assert read_frame(stream) == one
        assert read_frame(stream) == two
        assert stream.read() == b""
        assert [path.stem for path in paths] == ["command.one", "command.two"]
    assert stream.closed


@pytest.mark.parametrize("kind", ["source", "directory"])
def test_symlink_inputs_are_rejected(generator, tmp_path, kind):
    path = write_source(generator, "command.one")
    if kind == "source":
        target = tmp_path / "source.json"
        path.rename(target)
        path.symlink_to(target)
    else:
        directory = path.parent
        target = tmp_path / "sources"
        directory.rename(target)
        directory.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="invalid source file"), generator.source_stream():
        pytest.fail("symlink must not be accepted")


@pytest.mark.parametrize(
    "data,reason",
    [
        (b'{"extension":{"extension_id":"command.other"}}', "filename/identity"),
        (b'{"extension":{"extension_id":"command.one","extension_id":"command.one"}}', "duplicate source key"),
        (b" " * (8 * 1024 * 1024 + 1), "invalid source file"),
    ],
)
def test_invalid_records_fail_before_compiler_launch(generator, data, reason):
    write_source(generator, "command.one", data)
    with pytest.raises(ValueError, match=reason), generator.source_stream():
        pytest.fail("invalid source must not be accepted")


def test_mcp_record_is_forwarded_raw_for_the_native_validator(generator):
    write_source(generator, "command.one")
    raw = b'{"id":"mcp.example","id":"mcp.duplicate"}'
    (generator.ROOT / "contributions/mcp-servers/example.json").write_bytes(raw)
    with generator.source_stream() as (stream, _, paths):
        stream.read(5)
        assert json.loads(read_frame(stream))["mcp_sources"] == 1
        read_frame(stream)
        assert read_frame(stream) == raw
        assert paths[-1].name == "example.json"


@pytest.mark.parametrize("output", [b"", b"panic\xff", b"[]", b"null", b'"error"', b'{"pointer":0}', b'{"code":null}'])
def test_compiler_crashes_keep_exit_status_and_a_bounded_excerpt(generator, output):
    failure = generator.compilation_failure(subprocess.CompletedProcess([], -9, output), [])
    assert isinstance(failure, ValueError)
    assert "exit -9" in str(failure)
    assert output[:1024].decode(errors="replace") in str(failure)
    failure = generator.compilation_failure(subprocess.CompletedProcess([], 2, b"x" * 5000), [])
    assert len(str(failure)) < 1100


@pytest.mark.parametrize("pointer", [None, 0, [], "/records/9999999999", "/records/²"])
def test_invalid_diagnostic_pointers_cannot_hide_native_errors(generator, pointer):
    output = json.dumps({"code": "invalid_source", "pointer": pointer}).encode()
    assert "invalid_source" in str(generator.compilation_failure(subprocess.CompletedProcess([], 2, output), []))


def test_structured_failure_names_the_exact_source(generator):
    paths = [generator.ROOT / "contributions/command-sources/command.one.json"]
    output = b'{"code":"command_source_json_invalid","pointer":"/records/0"}'
    failure = generator.compilation_failure(subprocess.CompletedProcess([], 2, output), paths)
    assert "contributions/command-sources/command.one.json" in str(failure)
    assert "command_source_json_invalid" in str(failure)

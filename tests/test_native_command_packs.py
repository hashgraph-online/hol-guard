"""Immutable compiler objects cannot replace a complete root on failed builds."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def generator(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location("pack_builder_test", ROOT / "scripts/build_native_command_packs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.legacy, "ROOT", tmp_path)
    monkeypatch.setattr(module.legacy, "implementation_digest", lambda: "test")
    (tmp_path / "contributions/command-sources").mkdir(parents=True)
    (tmp_path / "contributions/mcp-servers").mkdir(parents=True)
    (tmp_path / "contracts/extensions/trust").mkdir(parents=True)
    (tmp_path / "contributions/command-sources/command.one.json").write_text(
        '{"extension":{"extension_id":"command.one"}}'
    )
    (tmp_path / "contracts/extensions/trust/command.one.v1.json").write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.one",
                "trustClass": "external",
            }
        )
    )
    return module


def fake_compiler(generator, monkeypatch, rows, status=0):
    data = b"".join(json.dumps(row).encode() + b"\n" for row in rows)

    class Process:
        stdout = io.BytesIO(data)

        def wait(self):
            return status

        def poll(self):
            return status

    monkeypatch.setattr(generator.subprocess, "Popen", lambda *args, **kwargs: Process())


def object_row(data=b'{"schema":"test"}'):
    return {
        "kind": "object",
        "sha256": hashlib.sha256(data).hexdigest(),
        "length": len(data),
        "data": base64.b64encode(data).decode(),
    }


def root_row():
    return valid_rows()[-1]


def valid_rows():
    rows = {}

    def blob(value):
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        row = object_row(data)
        rows[row["sha256"]] = row
        return {"sha256": row["sha256"], "length": len(data), "expanded_length": len(data), "kind": "data"}

    program = {"schema": "guard.native-command-program.v1", "nodes": {}, "trust_digest": "0" * 64}
    encoded = json.dumps(program, sort_keys=True, separators=(",", ":")).encode()
    program["program_digest"] = hashlib.sha256(b"hol-guard.native-command-program.v1\0" + encoded).hexdigest()
    manifest = {
        "schema": "guard.command-policy-pack.v1",
        "extension_id": "command.one",
        "engine": "test",
        "semantic_profile": "cpython-3.12-ucd15",
        "source_digest": "0" * 64,
        "trust_digest": "0" * 64,
        "program_digest": program["program_digest"],
        "cache_key": "0" * 64,
        "program": blob(program),
        "catalog": blob([]),
        "descriptors": blob([]),
    }
    index = blob(
        {"schema": "guard.pack-index.v1", "kind": "leaf", "prefix": "", "entries": [["command.one", blob(manifest)]]}
    )
    return [
        *rows.values(),
        {"kind": "root", "schema": "guard.command-pack-release.v1", "extensions": 1, "engine": "test", "index": index},
    ]


def test_unchanged_objects_are_verified_and_reused(generator, monkeypatch, tmp_path):
    output = tmp_path / "packs"
    fake_compiler(generator, monkeypatch, valid_rows())
    first = generator.stage(Path("compiler"), output)
    fake_compiler(generator, monkeypatch, valid_rows())
    second = generator.stage(Path("compiler"), output)
    assert first["release_sha256"] == second["release_sha256"]
    count = len(valid_rows()) - 1
    assert (first["created_objects"], second["created_objects"], second["reused_objects"]) == (count, 0, count)
    assert second["changed_object_bytes"] == 0


@pytest.mark.parametrize(
    "rows,status",
    [
        ([object_row()], 0),
        ([object_row(), root_row()], 1),
        ([object_row(), root_row(), root_row()], 0),
        ([object_row(), {**root_row(), "extensions": 2}], 0),
        ([{**object_row(), "sha256": "0" * 64}, root_row()], 0),
        ([{**object_row(), "length": 0}, root_row()], 0),
        ([*valid_rows()[:-1], {**root_row(), "engine": "stale"}], 0),
        ([*valid_rows()[:-1], {**root_row(), "index": {**root_row()["index"], "sha256": "0" * 64}}], 0),
    ],
)
def test_failed_builds_preserve_previous_complete_root(generator, monkeypatch, tmp_path, rows, status):
    output = tmp_path / "packs"
    output.mkdir()
    previous = b'{"previous":"complete"}\n'
    (output / "release.json").write_bytes(previous)
    fake_compiler(generator, monkeypatch, rows, status)
    with pytest.raises(ValueError):
        generator.stage(Path("compiler"), output)
    assert (output / "release.json").read_bytes() == previous


def test_poisoned_cache_cannot_substitute_a_pack(generator, monkeypatch, tmp_path):
    output = tmp_path / "packs"
    fake_compiler(generator, monkeypatch, valid_rows())
    generator.stage(Path("compiler"), output)
    previous = (output / "release.json").read_bytes()
    (output / "objects" / f"{valid_rows()[0]['sha256']}.json").write_bytes(b"poison")
    fake_compiler(generator, monkeypatch, valid_rows())
    with pytest.raises(ValueError, match="failed integrity"):
        generator.stage(Path("compiler"), output)
    assert (output / "release.json").read_bytes() == previous


def test_mcp_source_uses_its_existing_native_trust_identity(generator, tmp_path):
    (tmp_path / "contributions/mcp-servers/mcp.example.json").write_text('{"id":"mcp.example"}')
    (tmp_path / "contracts/extensions/trust/command.mcp-example.v1.json").write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": "command.mcp-example",
                "trustClass": "external",
            }
        )
    )
    output = io.BytesIO()
    assert generator.input_stream(tmp_path, output) == 2
    assert b"command.mcp-example" in output.getvalue()
    assert b'{"id":"mcp.example"}' in output.getvalue()


def test_symlink_output_is_rejected_before_compilation(generator, tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "packs"
    output.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        generator.stage(Path("compiler"), output)


def test_concurrent_object_writers_publish_only_complete_bytes(generator, tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    import command_pack_store as store

    data = b"x" * 65536
    digest = hashlib.sha256(data).hexdigest()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.publish_object(tmp_path, digest, data), range(32)))
    assert sum(results) == 1
    assert (tmp_path / f"{digest}.json").read_bytes() == data
    assert not list(tmp_path.glob(".obj-*"))


def test_interrupted_object_publication_can_be_retried(generator, monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.catalog_delivery import pack_store as store

    data = b"completed temporary bytes"
    digest = hashlib.sha256(data).hexdigest()
    link = store.os.link

    def interrupt(source, target):
        assert Path(source).read_bytes() == data
        raise OSError("simulated interruption before publication")

    monkeypatch.setattr(store.os, "link", interrupt)
    with pytest.raises(OSError, match="interruption"):
        store.publish_object(tmp_path, digest, data)
    assert not (tmp_path / f"{digest}.json").exists()
    assert not list(tmp_path.glob(".obj-*"))
    monkeypatch.setattr(store.os, "link", link)
    assert store.publish_object(tmp_path, digest, data)


@pytest.mark.parametrize("target", ["relative-target", "/absolute-target"])
def test_bootstrap_target_is_resolved_from_repository_not_calling_directory(generator, monkeypatch, tmp_path, target):
    calls = []
    monkeypatch.setenv("CARGO_TARGET_DIR", target)
    monkeypatch.setattr(generator.subprocess, "run", lambda command, **kwargs: calls.append((command, kwargs)))
    expected = Path(target) if Path(target).is_absolute() else tmp_path / target
    executable = "guard-pack-compiler.exe" if generator.os.name == "nt" else "guard-pack-compiler"
    assert generator.bootstrap_compiler() == expected / "release" / executable
    command, options = calls[0]
    assert command[-2:] == ["-p", "guard-pack-compiler"]
    assert "--locked" in command and "+1.88.0" in command
    assert options == {"cwd": tmp_path, "check": True}


def compiler_session(generator, monkeypatch, *, invalid=False, broken_pipe=False):
    rows = [{"kind": "compilation", "stats": {"compiled": 1, "reused": 0, "retained_encoded_bytes": 0}}, *valid_rows()]
    data = b"".join(json.dumps(row).encode() + b"\n" for row in rows)
    if invalid:
        data = b'{"kind":"unexpected"}\n' + data

    class Input(io.BytesIO):
        def write(self, data):
            if broken_pipe:
                raise BrokenPipeError("compiler rejected early")
            return super().write(data)

    class Process:
        def __init__(self):
            self.stdin = Input()
            self.stdout = io.BytesIO(b'{"ok":false,"code":"command_pack_metadata_invalid"}\n' if broken_pipe else data)
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, **kwargs):
            self.returncode = 2 if broken_pipe else 0
            return self.returncode

    process = Process()
    monkeypatch.setattr(generator.subprocess, "Popen", lambda *args, **kwargs: process)
    return generator.PackCompilerSession(Path("compiler")), process


def test_failed_session_cannot_publish_leftover_root_on_a_later_build(generator, monkeypatch, tmp_path):
    session, process = compiler_session(generator, monkeypatch, invalid=True)
    destination = tmp_path / "packs"
    destination.mkdir()
    previous = b'{"previous":"complete"}'
    (destination / "release.json").write_bytes(previous)
    with session:
        with pytest.raises(ValueError, match="compilation failed"):
            generator.stage(Path("compiler"), destination, session=session)
        assert session.closed and process.stdout.closed
        with pytest.raises(ValueError, match="closed"):
            generator.stage(Path("compiler"), destination, session=session)
    assert (destination / "release.json").read_bytes() == previous


def test_concurrent_session_request_is_rejected_without_poisoning_owner(generator, monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    session, _ = compiler_session(generator, monkeypatch)
    with session:
        with session.request(), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(generator.stage, Path("compiler"), tmp_path / "concurrent", session=session)
            with pytest.raises(ValueError, match="request in progress"):
                future.result()
        assert not session.closed
        report = generator.stage(Path("compiler"), tmp_path / "packs", session=session)
        assert report["extensions"] == 1
        assert report["compilation"]["compiled"] == 1


def test_early_native_rejection_retains_diagnostic_and_closes_session(generator, monkeypatch, tmp_path):
    session, _ = compiler_session(generator, monkeypatch, broken_pipe=True)
    with session:
        with pytest.raises(ValueError, match="command_pack_metadata_invalid"):
            generator.stage(Path("compiler"), tmp_path / "packs", session=session)
        assert session.closed
    assert not (tmp_path / "packs/release.json").exists()

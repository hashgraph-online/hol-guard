from __future__ import annotations

import hashlib
import json
import stat
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder import native_source_compiler as compiler


@pytest.fixture(autouse=True)
def _isolate_native_compiler_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep packaged-resource tests independent of CI's test compiler."""

    monkeypatch.delenv("HOL_GUARD_NATIVE_SOURCE_COMPILER", raising=False)
    monkeypatch.delenv("HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER", raising=False)


def _fake_compiler(tmp_path: Path, *, output: dict[str, object] | None = None) -> Path:
    payload = json.dumps(output or {"ok": True, "implementation_digest": "c" * 64})
    path = tmp_path / "guard-command-source"
    path.write_text(
        f"#!/usr/bin/env python3\nimport sys\nsys.stdin.read()\nprint({payload!r})\n",
        encoding="utf-8",
    )
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


def test_compile_source_uses_explicit_native_compiler_and_canonical_stdin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_compiler(tmp_path, output={"program": {}, "source_digest": "a" * 64})
    calls: list[tuple[list[str], bytes, float]] = []

    def record_run(arguments: list[str], payload: bytes, *, timeout: float) -> tuple[int, bytes, bytes]:
        calls.append((arguments, payload, timeout))
        return 0, json.dumps({"program": {}, "source_digest": "a" * 64}).encode(), b""

    monkeypatch.setattr(compiler, "_run_bounded", record_run)
    request = {"schema": "guard.command-extension-build.v1", "sources": [], "trust": {}, "mcp_sources": []}

    result = compiler.compile_source(request, compiler=executable)

    assert result["source_digest"] == "a" * 64
    assert calls[0][0][1:] == ["compile"]
    assert Path(calls[0][0][0]).name == "guard-command-source"
    assert calls[0][1] == (b'{"mcp_sources":[],"schema":"guard.command-extension-build.v1","sources":[],"trust":{}}\n')


def test_packaged_compiler_manifest_binds_runtime_identity_and_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_compiler(tmp_path)
    raw = executable.read_bytes()
    native = tmp_path / "_native"
    native.mkdir()
    packaged = native / executable.name
    packaged.write_bytes(raw)
    packaged.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    source_sha = "a" * 40
    base_program_digest = "b" * 64
    manifest = {
        "schema": "hol-guard-native-source-compiler.v1",
        "protocol_version": 1,
        "package_version": "3.0.1",
        "target": "x86_64-unknown-linux-gnu",
        "platform_tag": "manylinux_2_17_x86_64",
        "source_sha": source_sha,
        "implementation_digest": "c" * 64,
        "base_program_digest": base_program_digest,
        "compiler_sha256": hashlib.sha256(raw).hexdigest(),
        "compiler_size": len(raw),
    }
    (native / "source-compiler-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (native / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "schema": "hol-guard-native-runtime.v1",
                "package_version": "3.0.1",
                "source_sha": source_sha,
                "target": manifest["target"],
                "platform_tag": manifest["platform_tag"],
            }
        ),
        encoding="utf-8",
    )
    program = tmp_path / "native-command-program.v1.json"
    program.write_text(json.dumps({"program_digest": base_program_digest}), encoding="utf-8")
    monkeypatch.setattr(compiler, "_NATIVE_PACKAGE", native)
    monkeypatch.setattr(compiler, "_PACKAGED_PROGRAM", program)
    monkeypatch.setattr(compiler.metadata, "version", lambda _name: "3.0.1")

    assert compiler.find_packaged_source_compiler() == packaged
    packaged.write_bytes(b"x" * len(raw))
    with pytest.raises(compiler.NativeSourceCompilerError, match="hash"):
        compiler.find_packaged_source_compiler()


def test_compiler_request_is_bounded_before_subprocess(tmp_path: Path) -> None:
    executable = _fake_compiler(tmp_path)
    request = {"schema": "guard.command-extension-build.v1", "sources": ["x" * compiler._MAX_INPUT_BYTES]}
    with pytest.raises(compiler.NativeSourceCompilerError, match="input bound"):
        compiler.compile_source(request, compiler=executable)


def _packaged_compiler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    output: dict[str, object] | None = None,
) -> tuple[Path, dict[str, object]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    executable = _fake_compiler(tmp_path, output=output)
    raw = executable.read_bytes()
    native = tmp_path / "native"
    native.mkdir()
    packaged = native / compiler._COMPILER_NAME
    packaged.write_bytes(raw)
    packaged.chmod(0o700)
    manifest: dict[str, object] = {
        "schema": "hol-guard-native-source-compiler.v1",
        "protocol_version": 1,
        "package_version": "3.0.1",
        "target": "x86_64-unknown-linux-gnu",
        "platform_tag": "manylinux_2_17_x86_64",
        "source_sha": "a" * 40,
        "implementation_digest": "c" * 64,
        "base_program_digest": "b" * 64,
        "compiler_sha256": hashlib.sha256(raw).hexdigest(),
        "compiler_size": len(raw),
    }
    (native / compiler._MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    (native / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "schema": "hol-guard-native-runtime.v1",
                **{field: manifest[field] for field in ("package_version", "source_sha", "target", "platform_tag")},
            }
        ),
        encoding="utf-8",
    )
    program = tmp_path / "program.json"
    program.write_text(json.dumps({"program_digest": manifest["base_program_digest"]}), encoding="utf-8")
    monkeypatch.setattr(compiler, "_NATIVE_PACKAGE", native)
    monkeypatch.setattr(compiler, "_PACKAGED_PROGRAM", program)
    monkeypatch.setattr(compiler.metadata, "version", lambda _name: "3.0.1")
    return packaged, manifest


@pytest.mark.parametrize(
    "environment_name", ["HOL_GUARD_NATIVE_SOURCE_COMPILER", "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"]
)
def test_packaged_compiler_rejects_environment_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, environment_name: str
) -> None:
    _packaged_compiler(tmp_path, monkeypatch)
    override = _fake_compiler(tmp_path)
    monkeypatch.setenv(environment_name, str(override))

    def reject_execution(*_args: object, **_kwargs: object) -> None:
        pytest.fail("packaged authoring must reject environment overrides before executing a compiler")

    monkeypatch.setattr(compiler, "_run_bounded", reject_execution)

    with pytest.raises(
        compiler.NativeSourceCompilerError, match="override is not permitted alongside a packaged compiler"
    ):
        compiler.compile_source({"base": "packaged"})


@pytest.mark.parametrize("field", ["package_version", "source_sha", "target", "platform_tag"])
def test_packaged_compiler_requires_matching_runtime_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    _packaged_compiler(tmp_path, monkeypatch)
    runtime_path = compiler._NATIVE_PACKAGE / "runtime-manifest.json"
    runtime = json.loads(runtime_path.read_text())
    runtime[field] = "different"
    runtime_path.write_text(json.dumps(runtime), encoding="utf-8")

    with pytest.raises(compiler.NativeSourceCompilerError, match=field):
        compiler.find_packaged_source_compiler()


def test_packaged_compiler_requires_runtime_manifest_and_packaged_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _packaged_compiler(tmp_path, monkeypatch)
    (compiler._NATIVE_PACKAGE / "runtime-manifest.json").unlink()
    with pytest.raises(compiler.NativeSourceCompilerError, match="runtime manifest"):
        compiler.find_packaged_source_compiler()

    _packaged_compiler(tmp_path / "second", monkeypatch)
    compiler._PACKAGED_PROGRAM.write_text(json.dumps({"program_digest": "d" * 64}), encoding="utf-8")
    with pytest.raises(compiler.NativeSourceCompilerError, match="packaged program"):
        compiler.find_packaged_source_compiler()


@pytest.mark.parametrize("field", ["implementation_digest", "base_program_digest"])
def test_packaged_compile_requires_reported_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    output: dict[str, object] = {
        "implementation_digest": "c" * 64,
        "base_program_digest": "b" * 64,
        "program": {},
    }
    output[field] = "d" * 64
    _packaged_compiler(tmp_path, monkeypatch, output=output)

    with pytest.raises(compiler.NativeSourceCompilerError, match="identity"):
        compiler.compile_source({"base": "packaged"})


def test_verified_snapshot_prevents_path_replacement_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _fake_compiler(tmp_path)
    expected = executable.read_bytes()

    def replace_and_observe(arguments: list[str], payload: bytes, *, timeout: float) -> tuple[int, bytes, bytes]:
        executable.write_bytes(b"replaced")
        assert Path(arguments[0]).read_bytes() == expected
        return 0, b'{"ok":true}', b""

    monkeypatch.setattr(compiler, "_run_bounded", replace_and_observe)
    assert compiler.run_source_compiler("validate", {}, compiler=executable) == {"ok": True}


@pytest.mark.parametrize("operation", ["validate", "check", "test", "compare"])
@pytest.mark.parametrize("mismatch", [None, "base", "program", "implementation", "missing-program"])
def test_packaged_compact_validation_requires_matching_compilation_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, mismatch: str | None
) -> None:
    _packaged_compiler(tmp_path, monkeypatch)
    calls: list[tuple[str, bytes, str]] = []
    result_digest_field = "candidate_program_digest" if operation == "compare" else "program_digest"
    compact: dict[str, object] = {"ok": True, result_digest_field: "d" * 64}
    if operation != "test":
        compact["implementation_digest"] = "c" * 64
    if mismatch == "missing-program":
        compact.pop(result_digest_field)
    compiled = {
        "program": {"program_digest": "e" * 64 if mismatch == "program" else "d" * 64},
        "implementation_digest": "e" * 64 if mismatch == "implementation" else "c" * 64,
        "base_program_digest": "e" * 64 if mismatch == "base" else "b" * 64,
    }
    if mismatch == "missing-program":
        compiled["program"] = {}

    def respond(arguments: list[str], payload: bytes, *, timeout: float) -> tuple[int, bytes, bytes]:
        calls.append((arguments[1], payload, arguments[0]))
        return 0, json.dumps(compiled if arguments[1] == "compile" else compact).encode(), b""

    monkeypatch.setattr(compiler, "_run_bounded", respond)
    build = {"base": "packaged"}
    request = {"build": build, "cases": []} if operation in {"test", "compare"} else build
    if mismatch is not None:
        with pytest.raises(compiler.NativeSourceCompilerError, match=r"identit|program digest"):
            compiler.run_source_compiler(operation, request, digest="d" * 64 if operation == "check" else None)
    else:
        assert (
            compiler.run_source_compiler(operation, request, digest="d" * 64 if operation == "check" else None)
            == compact
        )
    assert [call[0] for call in calls] == [operation, "compile"]
    assert calls[0][2] == calls[1][2]
    assert json.loads(calls[1][1]) == build
    assert json.loads(calls[0][1]) == request


def test_subprocess_output_and_timeout_are_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    noisy = tmp_path / "guard-command-source"
    noisy.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdout.write('x' * 1025)\n", encoding="utf-8")
    noisy.chmod(0o700)
    monkeypatch.setattr(compiler, "_MAX_OUTPUT_BYTES", 1024)
    with pytest.raises(compiler.NativeSourceCompilerError, match="output exceeds"):
        compiler.run_source_compiler("validate", {}, compiler=noisy)

    sleeper = tmp_path / "sleeper"
    sleeper.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(30)\n", encoding="utf-8")
    sleeper.chmod(0o700)
    started = time.monotonic()
    with pytest.raises(compiler.NativeSourceCompilerError, match="timed out"):
        compiler.run_source_compiler("validate", {"sources": ["x" * (1024 * 1024)]}, compiler=sleeper, timeout=0.05)
    assert time.monotonic() - started < 5

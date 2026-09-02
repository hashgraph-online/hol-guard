from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

import scripts.build_native_hol_guard_wheel as wheel_builder
from scripts.build_native_hol_guard_wheel import NativeWheelError, build_native_wheel

_VERSION = "3.0.0a7"
_SOURCE_SHA = "a" * 40
_RULE_DIGEST = "b" * 64
_PLATFORM_TAG = "manylinux_2_28_x86_64"
_TARGET = "x86_64-unknown-linux-gnu"


@pytest.fixture(autouse=True)
def _stub_runtime_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        payload = {
            "protocol_version": 1,
            "runtime_version": _VERSION,
            "rule_digest": _RULE_DIGEST,
            "build_sha": _SOURCE_SHA,
        }
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps(payload, separators=(",", ":")).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(wheel_builder.subprocess, "run", fake_run)


def _write_source_wheel(
    tmp_path: Path,
    *,
    version: str = _VERSION,
    unsafe_name: str | None = None,
    extra_entries: dict[str, bytes] | None = None,
) -> Path:
    path = tmp_path / f"hol_guard-{version}-py3-none-any.whl"
    dist_info = f"hol_guard-{version}.dist-info"
    entries = {
        "codex_plugin_scanner/__init__.py": b"__version__ = 'fixture'\n",
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: hol-guard\n"
            f"Version: {version}\n"
            "\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/RECORD": b"",
    }
    if unsafe_name is not None:
        entries[unsafe_name] = b"unsafe"
    if extra_entries is not None:
        entries.update(extra_entries)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


def _write_runtime(tmp_path: Path) -> Path:
    path = tmp_path / "hol-guard-runtime"
    path.write_bytes(b"native-runtime-fixture-v1")
    path.chmod(0o755)
    return path


def _record_digest(content: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    return f"sha256={encoded}"


def _build(tmp_path: Path, *, wheel: Path | None = None, runtime: Path | None = None) -> Path:
    return build_native_wheel(
        source_wheel=wheel or _write_source_wheel(tmp_path),
        runtime=runtime or _write_runtime(tmp_path),
        output_dir=tmp_path / "native",
        version=_VERSION,
        platform_tag=_PLATFORM_TAG,
        target=_TARGET,
        source_sha=_SOURCE_SHA,
        rule_digest=_RULE_DIGEST,
    )


def _set_runtime_capabilities(
    monkeypatch: pytest.MonkeyPatch,
    *,
    protocol_version: int = 1,
    runtime_version: str = _VERSION,
    rule_digest: str = _RULE_DIGEST,
    build_sha: str = _SOURCE_SHA,
) -> None:
    def fake_run(args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        payload = {
            "protocol_version": protocol_version,
            "runtime_version": runtime_version,
            "rule_digest": rule_digest,
            "build_sha": build_sha,
        }
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps(payload, separators=(",", ":")).encode(),
            stderr=b"",
        )

    monkeypatch.setattr(wheel_builder.subprocess, "run", fake_run)


def test_native_wheel_injects_runtime_manifest_and_valid_record(tmp_path: Path) -> None:
    output = _build(tmp_path)
    assert output.name == f"hol_guard-{_VERSION}-py3-none-{_PLATFORM_TAG}.whl"

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        runtime_path = "codex_plugin_scanner/_native/hol-guard-runtime"
        manifest_path = "codex_plugin_scanner/_native/runtime-manifest.json"
        wheel_path = f"hol_guard-{_VERSION}.dist-info/WHEEL"
        record_path = f"hol_guard-{_VERSION}.dist-info/RECORD"
        assert runtime_path in names
        assert manifest_path in names

        wheel_text = archive.read(wheel_path).decode()
        assert "Root-Is-Purelib: false" in wheel_text
        assert f"Tag: py3-none-{_PLATFORM_TAG}" in wheel_text
        assert "Tag: py3-none-any" not in wheel_text

        runtime_bytes = archive.read(runtime_path)
        manifest = json.loads(archive.read(manifest_path))
        assert manifest == {
            "package_version": _VERSION,
            "platform_tag": _PLATFORM_TAG,
            "protocol_version": 1,
            "rule_digest": _RULE_DIGEST,
            "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
            "runtime_size": len(runtime_bytes),
            "schema": "hol-guard-native-runtime.v1",
            "source_sha": _SOURCE_SHA,
            "target": _TARGET,
        }
        runtime_mode = stat.S_IMODE(archive.getinfo(runtime_path).external_attr >> 16)
        assert runtime_mode == 0o755

        rows = list(csv.reader(io.StringIO(archive.read(record_path).decode())))
        by_name = {row[0]: row[1:] for row in rows}
        assert by_name[record_path] == ["", ""]
        for name in names - {record_path}:
            content = archive.read(name)
            assert by_name[name] == [_record_digest(content), str(len(content))]


def test_builder_does_not_modify_source_wheel(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path)
    before = hashlib.sha256(wheel.read_bytes()).hexdigest()
    _ = _build(tmp_path, wheel=wheel)
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == before


def test_builder_refuses_plugin_scanner_artifact(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path)
    scanner_wheel = wheel.with_name(f"plugin_scanner-{_VERSION}-py3-none-any.whl")
    wheel.rename(scanner_wheel)
    with pytest.raises(NativeWheelError, match="expected pure hol-guard wheel"):
        _build(tmp_path, wheel=scanner_wheel)


def test_builder_rejects_archive_path_traversal(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path, unsafe_name="../escaped")
    with pytest.raises(NativeWheelError, match="unsafe path"):
        _build(tmp_path, wheel=wheel)


def test_builder_rejects_noncanonical_archive_path(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path, unsafe_name="codex_plugin_scanner//payload.py")
    with pytest.raises(NativeWheelError, match="unsafe path"):
        _build(tmp_path, wheel=wheel)


def test_builder_rejects_casefold_archive_collision(tmp_path: Path) -> None:
    wheel = _write_source_wheel(
        tmp_path,
        extra_entries={"pkg/File.py": b"one", "pkg/file.py": b"two"},
    )
    with pytest.raises(NativeWheelError, match="canonical path collision"):
        _build(tmp_path, wheel=wheel)


def test_builder_rejects_oversized_archive_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(wheel_builder, "_MAX_SOURCE_ENTRY_BYTES", 256)
    wheel = _write_source_wheel(
        tmp_path,
        extra_entries={"pkg/oversized.bin": b"x" * 257},
    )
    with pytest.raises(NativeWheelError, match="entry is too large"):
        _build(tmp_path, wheel=wheel)


def test_builder_rejects_source_version_mismatch(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path, version="3.0.0a6")
    with pytest.raises(NativeWheelError, match="expected pure hol-guard wheel"):
        _build(tmp_path, wheel=wheel)


def test_builder_refuses_overwrite_without_changing_existing_output(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path)
    runtime = _write_runtime(tmp_path)
    output = _build(tmp_path, wheel=wheel, runtime=runtime)
    before = output.read_bytes()
    with pytest.raises(NativeWheelError, match="refusing to overwrite"):
        _build(tmp_path, wheel=wheel, runtime=runtime)
    assert output.read_bytes() == before


def test_builder_rejects_runtime_rule_digest_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_runtime_capabilities(monkeypatch, rule_digest="c" * 64)
    with pytest.raises(NativeWheelError, match="rule digest"):
        _build(tmp_path)


def test_builder_rejects_runtime_build_sha_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_runtime_capabilities(monkeypatch, build_sha="d" * 40)
    with pytest.raises(NativeWheelError, match="build SHA"):
        _build(tmp_path)


def test_builder_rejects_runtime_version_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_runtime_capabilities(monkeypatch, runtime_version="3.0.0a6")
    with pytest.raises(NativeWheelError, match="package version"):
        _build(tmp_path)


def test_builder_rejects_runtime_protocol_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_runtime_capabilities(monkeypatch, protocol_version=2)
    with pytest.raises(NativeWheelError, match="protocol version"):
        _build(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="symlink fixture uses POSIX executable semantics")
def test_builder_rejects_symlink_runtime(tmp_path: Path) -> None:
    target = _write_runtime(tmp_path)
    link = tmp_path / "runtime-link"
    link.symlink_to(target)
    with pytest.raises(NativeWheelError, match="regular non-symlink"):
        _build(tmp_path, runtime=link)

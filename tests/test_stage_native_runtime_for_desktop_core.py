from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts/release/stage_native_runtime_for_desktop_core.py"
SPEC = importlib.util.spec_from_file_location("stage_native_runtime_for_desktop_core", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _manifest(runtime: bytes, *, version: str = "3.0.12", target: str = "aarch64-apple-darwin") -> dict[str, object]:
    return {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": version,
        "target": target,
        "platform_tag": "macosx_11_0_arm64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }


def _write_wheel(
    path: Path, runtime: bytes, manifest: dict[str, object], *, runtime_name: str = "hol-guard-runtime"
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"codex_plugin_scanner/_native/{runtime_name}", runtime)
        archive.writestr(
            "codex_plugin_scanner/_native/runtime-manifest.json",
            json.dumps(manifest),
        )


def test_stage_from_wheel_extracts_sealed_runtime(tmp_path: Path) -> None:
    runtime = b"native-runtime-bytes"
    wheel = tmp_path / "hol_guard-3.0.12-py3-none-macosx_11_0_arm64.whl"
    _write_wheel(wheel, runtime, _manifest(runtime))
    destination = tmp_path / "native"

    runtime_path, manifest_path = MODULE.stage_from_wheel(
        wheel,
        destination,
        expected_version="3.0.12",
        expected_target="aarch64-apple-darwin",
    )

    assert runtime_path.read_bytes() == runtime
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["runtime_sha256"] == hashlib.sha256(runtime).hexdigest()
    assert oct(runtime_path.stat().st_mode & 0o777) == "0o755"


def _bundle_binding(source_sha: str = "a" * 40) -> dict[str, object]:
    return {
        "schema": "guard.command-pack-bundle.v1",
        "path": "codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/command-pack-bundle.v1.json",
        "sha256": "c" * 64,
        "length": 2168,
        "source_sha": source_sha,
        "engine": "d" * 64,
    }


def test_staging_keeps_the_command_pack_bundle_binding(tmp_path: Path) -> None:
    # Native rejects the installed catalog unless the runtime manifest carries
    # the same binding as the source compiler manifest (#5419).
    runtime = b"native-runtime-bytes"
    wheel = tmp_path / "wheel.whl"
    _write_wheel(wheel, runtime, {**_manifest(runtime), "command_pack_bundle": _bundle_binding()})
    destination = tmp_path / "native"
    runtime_path, manifest_path = MODULE.stage_from_wheel(
        wheel,
        destination,
        expected_version="3.0.12",
        expected_target="aarch64-apple-darwin",
    )
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["command_pack_bundle"] == _bundle_binding()

    runtime_path.write_bytes(runtime + b"-signed")
    runtime_path.chmod(0o755)
    MODULE.refresh_identity(destination)
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["command_pack_bundle"] == _bundle_binding()


@pytest.mark.parametrize(
    "binding",
    [
        _bundle_binding(source_sha="e" * 40),
        {**_bundle_binding(), "path": "elsewhere.json"},
        {**_bundle_binding(), "extra": True},
        {**_bundle_binding(), "length": 0},
        "not-a-binding",
    ],
)
def test_staging_rejects_a_malformed_command_pack_bundle_binding(tmp_path: Path, binding: object) -> None:
    runtime = b"native-runtime-bytes"
    wheel = tmp_path / "wheel.whl"
    _write_wheel(wheel, runtime, {**_manifest(runtime), "command_pack_bundle": binding})
    with pytest.raises(MODULE.NativeRuntimeStageError, match="command pack bundle"):
        MODULE.stage_from_wheel(
            wheel,
            tmp_path / "native",
            expected_version="3.0.12",
            expected_target="aarch64-apple-darwin",
        )


def test_stage_from_wheel_rejects_path_escape(tmp_path: Path) -> None:
    wheel = tmp_path / "evil.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("../escape", b"nope")
        archive.writestr("codex_plugin_scanner/_native/hol-guard-runtime", b"runtime")
        archive.writestr("codex_plugin_scanner/_native/runtime-manifest.json", b"{}")

    with pytest.raises(MODULE.NativeRuntimeStageError, match="unsafe native wheel member"):
        MODULE.stage_from_wheel(
            wheel,
            tmp_path / "native",
            expected_version="3.0.12",
            expected_target="aarch64-apple-darwin",
        )


def test_stage_from_wheel_rejects_version_mismatch(tmp_path: Path) -> None:
    runtime = b"native-runtime-bytes"
    wheel = tmp_path / "wheel.whl"
    _write_wheel(wheel, runtime, _manifest(runtime, version="3.0.11"))

    with pytest.raises(MODULE.NativeRuntimeStageError, match="package version"):
        MODULE.stage_from_wheel(
            wheel,
            tmp_path / "native",
            expected_version="3.0.12",
            expected_target="aarch64-apple-darwin",
        )


def test_stage_from_wheel_rejects_digest_mismatch(tmp_path: Path) -> None:
    runtime = b"native-runtime-bytes"
    manifest = _manifest(runtime)
    manifest["runtime_sha256"] = "c" * 64
    wheel = tmp_path / "wheel.whl"
    _write_wheel(wheel, runtime, manifest)

    with pytest.raises(MODULE.NativeRuntimeStageError, match="digest"):
        MODULE.stage_from_wheel(
            wheel,
            tmp_path / "native",
            expected_version="3.0.12",
            expected_target="aarch64-apple-darwin",
        )


def test_refresh_identity_rewrites_signed_digest(tmp_path: Path) -> None:
    runtime = b"native-runtime-bytes"
    wheel = tmp_path / "wheel.whl"
    _write_wheel(wheel, runtime, _manifest(runtime))
    destination = tmp_path / "native"
    runtime_path, _manifest_path = MODULE.stage_from_wheel(
        wheel,
        destination,
        expected_version="3.0.12",
        expected_target="aarch64-apple-darwin",
    )
    signed = runtime + b"-signed"
    runtime_path.write_bytes(signed)
    runtime_path.chmod(0o755)

    MODULE.refresh_identity(destination)

    payload = json.loads((destination / "runtime-manifest.json").read_text(encoding="utf-8"))
    assert payload["runtime_sha256"] == hashlib.sha256(signed).hexdigest()
    assert payload["runtime_size"] == len(signed)

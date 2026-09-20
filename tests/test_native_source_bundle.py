"""Real packaging/discovery tests with a synthetic capabilities-only child.

These do not exercise the Rust runtime or make an installed-wheel claim.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import sys
import zipfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from scripts.build_native_hol_guard_wheel import NativeWheelError
from tests.native_source_bundle import stage_source_bundle

SOURCE = "a" * 40
DIGEST = "b" * 64


def inputs(tmp_path: Path, overrides: dict[str, object] | None = None) -> dict[str, object]:
    try:
        version = importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        version = "3.0.1"
    wheel = tmp_path / f"hol_guard-{version}-py3-none-any.whl"
    info = f"hol_guard-{version}.dist-info"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"{info}/METADATA", f"Metadata-Version: 2.1\nName: hol-guard\nVersion: {version}\n")
        archive.writestr(f"{info}/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(f"{info}/RECORD", "")
        archive.writestr("codex_plugin_scanner/__init__.py", "")
    runtime = tmp_path / "build-runtime"
    capabilities: dict[str, object] = {
        "protocol_version": 1,
        "runtime_version": version,
        "rule_digest": DIGEST,
        "build_sha": SOURCE,
        "target": "x86_64-unknown-linux-gnu",
        "features": [],
    }
    capabilities.update(overrides or {})
    runtime.write_text(f"#!{sys.executable}\nprint({json.dumps(json.dumps(capabilities))})\n")
    runtime.chmod(0o755)
    package = tmp_path / "source" / "codex_plugin_scanner"
    (package / "guard").mkdir(parents=True)
    return {
        "source_wheel": wheel,
        "runtime": runtime,
        "package_root": package,
        "output_dir": tmp_path / "native-wheel",
        "version": version,
        "source_sha": SOURCE,
        "rule_digest": DIGEST,
        "platform_tag": "linux_x86_64",
        "target": "x86_64-unknown-linux-gnu",
    }


def stage(values: dict[str, object]) -> Path:
    # Narrow the fixture values explicitly rather than bypassing the typed API.
    assert all(isinstance(values[key], Path) for key in ("source_wheel", "runtime", "package_root", "output_dir"))
    return stage_source_bundle(
        source_wheel=Path(str(values["source_wheel"])),
        runtime=Path(str(values["runtime"])),
        package_root=Path(str(values["package_root"])),
        output_dir=Path(str(values["output_dir"])),
        version=str(values["version"]),
        source_sha=str(values["source_sha"]),
        rule_digest=str(values["rule_digest"]),
        platform_tag=str(values["platform_tag"]),
        target=str(values["target"]),
    )


def test_auto_ignores_build_override_then_discovers_verified_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = inputs(tmp_path)
    package = Path(str(values["package_root"]))
    runtime = Path(str(values["runtime"]))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    # Relocate the test package; use the actual production candidate selector,
    # binary validation, manifest decoder and real child capabilities exchange.
    monkeypatch.setattr(native_runtime, "__file__", str(package / "guard" / "native_runtime.py"))
    before = native_runtime.native_runtime_status()
    assert not before.available and before.reason == "native_unavailable"
    selected = stage(values)
    status = native_runtime.native_runtime_status()
    assert status.mode == "auto" and status.available and status.compatible, status.reason
    assert status.identity is not None and status.capabilities is not None
    assert status.identity.path == selected.resolve()
    assert status.identity.path != runtime.resolve()
    assert status.identity.sha256 == hashlib.sha256(runtime.read_bytes()).hexdigest()
    assert status.capabilities.build_sha == SOURCE
    assert {path.name for path in selected.parent.iterdir()} == {"hol-guard-runtime", "runtime-manifest.json"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("build_sha", "c" * 40),
        ("runtime_version", "9.9.9"),
        ("rule_digest", "c" * 64),
        ("protocol_version", 2),
    ],
)
def test_packaging_refuses_mismatched_identity(tmp_path: Path, field: str, value: object) -> None:
    values = inputs(tmp_path, {field: value})
    with pytest.raises(NativeWheelError):
        stage(values)
    assert not (Path(str(values["package_root"])) / "_native").exists()


def test_staging_never_replaces_an_existing_bundle(tmp_path: Path) -> None:
    values = inputs(tmp_path)
    selected = stage(values)
    before = selected.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        stage(values)
    assert selected.read_bytes() == before


def test_auto_refuses_changed_staged_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = inputs(tmp_path)
    package = Path(str(values["package_root"]))
    selected = stage(values)
    selected.write_bytes(selected.read_bytes() + b"# changed\n")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(native_runtime, "__file__", str(package / "guard" / "native_runtime.py"))
    status = native_runtime.native_runtime_status()
    assert status.available and not status.compatible
    assert status.reason == "native_manifest_runtime_mismatch"

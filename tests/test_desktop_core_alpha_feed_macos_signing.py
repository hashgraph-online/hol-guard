"""Regression contracts for macOS PyInstaller signing in the Desktop Core feed."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-core-alpha-feed.yml"
VERIFIER = ROOT / "scripts" / "release" / "verify_pyinstaller_macos_signing.py"


def _publish_steps() -> list[dict[str, object]]:
    payload = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = payload["jobs"]["publish-macos-arm64"]["steps"]
    assert isinstance(steps, list)
    return steps


def _load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_pyinstaller_macos_signing", VERIFIER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_archive(
    path: Path,
    *,
    declared_runtime: str,
    entries: list[tuple[str, bytes, str]],
) -> None:
    module = _load_verifier()
    payload = bytearray()
    toc = bytearray()
    for name, data, typecode in entries:
        offset = len(payload)
        payload.extend(data)
        raw_name = name.encode("utf-8") + b"\0"
        entry_length = module.TOC_HEADER_LENGTH + len(raw_name)
        toc.extend(
            struct.pack(
                module.TOC_FORMAT,
                entry_length,
                offset,
                len(data),
                len(data),
                0,
                typecode.encode("ascii"),
            )
        )
        toc.extend(raw_name)

    raw_runtime = declared_runtime.encode("utf-8")
    assert len(raw_runtime) < 64
    cookie = struct.pack(
        module.COOKIE_FORMAT,
        module.COOKIE_MAGIC,
        len(payload) + len(toc) + module.COOKIE_LENGTH,
        len(payload),
        len(toc),
        312,
        raw_runtime + (b"\0" * (64 - len(raw_runtime))),
    )
    path.write_bytes(bytes(payload) + bytes(toc) + cookie)


def test_signing_identity_is_imported_before_pyinstaller_build() -> None:
    steps = _publish_steps()
    names = [step.get("name") for step in steps]
    assert names.index("Import Apple signing identity") < names.index("Build standalone Core executable")

    build = next(step for step in steps if step.get("name") == "Build standalone Core executable")
    assert build["env"]["APPLE_SIGNING_IDENTITY"] == "${{ secrets.APPLE_SIGNING_IDENTITY }}"
    assert build["env"]["APPLE_TEAM_ID"] == "${{ secrets.APPLE_TEAM_ID }}"
    run = build["run"]
    assert isinstance(run, str)
    assert '--codesign-identity "$APPLE_SIGNING_IDENTITY"' in run
    assert "verify_pyinstaller_macos_signing.py" in run
    assert "verify_pyinstaller_native_runtime.py" in run
    assert '--team-id "$APPLE_TEAM_ID"' in run
    assert run.index(
        'codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$NATIVE_RUNTIME"'
    ) < run.index("uv run --no-sync pyinstaller")
    assert run.index("verify_pyinstaller_macos_signing.py") < run.index("verify_pyinstaller_native_runtime.py")


def test_final_verification_checks_reused_and_new_embedded_team_identity() -> None:
    steps = _publish_steps()
    verify = next(
        step for step in steps if step.get("name") == "Verify exact Apple identity, notarization, and Core contract"
    )
    run = verify["run"]
    assert isinstance(run, str)
    verifier = "python3 -I scripts/release/verify_pyinstaller_macos_signing.py"
    assert verifier in run
    assert run.index(verifier) < run.index('if [[ "$MODE" == "build" ]]; then')


def test_verifier_accepts_framework_runtime_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_verifier()
    archive = tmp_path / "hol-guard"
    runtime = "Python.framework/Versions/3.12/Python"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", runtime.encode() + b"\0", "n"),
            (runtime, b"\xcf\xfa\xed\xfe-runtime", "b"),
            ("helper.dylib", b"\xcf\xfa\xed\xfe-helper", "b"),
        ],
    )
    monkeypatch.setattr(module, "_team_id", lambda _path: "TEAM123")

    module.verify(archive, "TEAM123")


def test_verifier_rejects_framework_runtime_symlink_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_verifier()
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", b"../outside/Python\0", "n"),
            ("helper.dylib", b"\xcf\xfa\xed\xfe-helper", "b"),
        ],
    )
    monkeypatch.setattr(module, "_team_id", lambda _path: "TEAM123")

    with pytest.raises(ValueError, match="escapes the archive root"):
        module.verify(archive, "TEAM123")


def test_verifier_rejects_framework_runtime_symlink_to_non_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_verifier()
    archive = tmp_path / "hol-guard"
    runtime = "Python.framework/Versions/3.12/Python"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[
            ("Python", runtime.encode() + b"\0", "n"),
            (runtime, b"not-a-binary", "x"),
        ],
    )
    monkeypatch.setattr(module, "_team_id", lambda _path: "TEAM123")

    with pytest.raises(ValueError, match="resolves to unsupported TOC type 'x'"):
        module.verify(archive, "TEAM123")


def test_verifier_rejects_missing_cookie_declared_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_verifier()
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="Python",
        entries=[("python_helper", b"\xcf\xfa\xed\xfe", "b")],
    )
    monkeypatch.setattr(module, "_team_id", lambda _path: "TEAM123")

    with pytest.raises(ValueError, match=r"Cookie-declared Python runtime target 'Python'.*found 0"):
        module.verify(archive, "TEAM123")


def test_verifier_rejects_parent_traversal_cookie_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_verifier()
    archive = tmp_path / "hol-guard"
    _fake_archive(
        archive,
        declared_runtime="../Python",
        entries=[
            ("../Python", b"runtime\0", "n"),
            ("../runtime", b"\xcf\xfa\xed\xfe-runtime", "b"),
        ],
    )
    monkeypatch.setattr(module, "_team_id", lambda _path: "TEAM123")

    with pytest.raises(ValueError, match="archive-relative"):
        module.verify(archive, "TEAM123")

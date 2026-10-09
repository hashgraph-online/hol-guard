"""Regression contracts for macOS PyInstaller signing in the Desktop Core feed."""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import subprocess
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
    assert "seal_pyinstaller_native_manifest.py" in run
    assert "verify_pyinstaller_native_runtime.py" in run
    assert '--team-id "$APPLE_TEAM_ID"' in run
    assert run.index(
        'codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$NATIVE_RUNTIME"'
    ) < run.index("uv run --no-sync pyinstaller")
    assert run.index('codesign --remove-signature "$BUILT"') < run.index("seal_pyinstaller_native_manifest.py")
    assert run.index("seal_pyinstaller_native_manifest.py") < run.index("fix_pyinstaller_macos_exe_headers.py")
    assert run.index("fix_pyinstaller_macos_exe_headers.py") < run.index(
        'codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$BUILT"'
    )
    assert run.index(
        'codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$BUILT"'
    ) < run.index("verify_pyinstaller_macos_signing.py")
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
    assert "verify_pyinstaller_native_runtime.py" not in run


def test_reused_core_assets_skip_native_runtime_verifier() -> None:
    steps = _publish_steps()
    build = next(step for step in steps if step.get("name") == "Build standalone Core executable")
    verify = next(
        step for step in steps if step.get("name") == "Verify exact Apple identity, notarization, and Core contract"
    )
    assert build.get("if") == (
        "steps.release.outputs.available == 'true' && steps.registry.outputs.registry_ready == 'true'"
        " && steps.existing.outputs.mode == 'build'"
    )
    assert "verify_pyinstaller_native_runtime.py" in str(build.get("run"))
    assert "verify_pyinstaller_native_runtime.py" not in str(verify.get("run"))


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


NOTARIZE_SCRIPT = ROOT / "scripts" / "release" / "notarize_core_archives.sh"
ONEFILE_ZIP = "core-update-notary.zip"
ONEDIR_ZIP = "hol-guard-core-1.2.3-aarch64-apple-darwin.onedir.zip"


def _run_notarization(tmp_path: Path, outcomes: dict[str, str]) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    xcrun = stubs / "xcrun"
    # Each archive's outcome is keyed by file name: an Apple status, "crash" for a failed submit,
    # or "accepted-then-exit" for an Accepted result from a submit that still exits nonzero.
    # Every submission waits until both have started, so a serial run times out instead of passing.
    xcrun.write_text(
        "#!/bin/bash\n"
        'archive=$(basename "$3")\n'
        'echo "$archive" >> "$STATE/submitted.txt"\n'
        'touch "$STATE/started.$archive"\n'
        "for _ in $(seq 100); do\n"
        '  [[ $(find "$STATE" -name "started.*" | wc -l) -ge 2 ]] && break\n'
        "  sleep 0.05\n"
        "done\n"
        '[[ $(find "$STATE" -name "started.*" | wc -l) -ge 2 ]] || { echo "submissions ran serially" >&2; exit 9; }\n'
        'outcome=$(jq -r --arg archive "$archive" \'.[$archive]\' "$OUTCOMES")\n'
        'if [[ "$outcome" == "crash" ]]; then exit 3; fi\n'
        'if [[ "$outcome" == "accepted-then-exit" ]]; then jq -n \'{status: "Accepted"}\'; exit 4; fi\n'
        "jq -n --arg status \"$outcome\" '{status: $status}'\n",
        encoding="utf-8",
    )
    xcrun.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    outcomes_file = tmp_path / "outcomes.json"
    outcomes_file.write_text(json.dumps(outcomes), encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "STATE": str(state),
        "OUTCOMES": str(outcomes_file),
        "APPLE_ID": "id",
        "APPLE_PASSWORD": "password",
        "APPLE_TEAM_ID": "TEAM123",
    }
    return subprocess.run(
        [
            "bash",
            str(NOTARIZE_SCRIPT),
            str(tmp_path / ONEFILE_ZIP),
            str(tmp_path / "notary-result.json"),
            str(tmp_path / ONEDIR_ZIP),
            str(tmp_path / "notary-result-onedir.json"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_notarization_submits_both_archives_concurrently_and_requires_both_accepted(tmp_path: Path) -> None:
    result = _run_notarization(tmp_path, {ONEFILE_ZIP: "Accepted", ONEDIR_ZIP: "Accepted"})
    assert result.returncode == 0, result.stderr
    submitted = (tmp_path / "state" / "submitted.txt").read_text(encoding="utf-8").split()
    assert sorted(submitted) == sorted([ONEFILE_ZIP, ONEDIR_ZIP])
    assert json.loads((tmp_path / "notary-result.json").read_text(encoding="utf-8"))["status"] == "Accepted"
    assert json.loads((tmp_path / "notary-result-onedir.json").read_text(encoding="utf-8"))["status"] == "Accepted"
    assert "--wait" in NOTARIZE_SCRIPT.read_text(encoding="utf-8")


def test_feed_notarizes_both_archives_through_the_shared_script() -> None:
    step = next(step for step in _publish_steps() if step.get("name") == "Sign and notarize new Core sidecar")
    run = str(step["run"])
    assert "bash scripts/release/notarize_core_archives.sh" in run
    assert '"$RUNNER_TEMP/core-update-notary.zip" "$RUNNER_TEMP/notary-result.json"' in run
    assert '.onedir.zip" \\\n  "$RUNNER_TEMP/notary-result-onedir.json"' in run
    assert "notarytool" not in run


@pytest.mark.parametrize(
    "outcomes",
    [
        {ONEFILE_ZIP: "Invalid", ONEDIR_ZIP: "Accepted"},
        {ONEFILE_ZIP: "Accepted", ONEDIR_ZIP: "Invalid"},
        {ONEFILE_ZIP: "crash", ONEDIR_ZIP: "Accepted"},
        {ONEFILE_ZIP: "Accepted", ONEDIR_ZIP: "crash"},
        {ONEFILE_ZIP: "accepted-then-exit", ONEDIR_ZIP: "Accepted"},
        {ONEFILE_ZIP: "Accepted", ONEDIR_ZIP: "accepted-then-exit"},
    ],
)
def test_notarization_fails_when_either_archive_is_not_accepted(tmp_path: Path, outcomes: dict[str, str]) -> None:
    result = _run_notarization(tmp_path, outcomes)
    assert result.returncode != 0
    assert "submissions ran serially" not in result.stderr

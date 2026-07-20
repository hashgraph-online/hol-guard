from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from codex_plugin_scanner.guard.mdm.manifest import verify_release_manifest


def _command(root: Path, runtime: Path, output: Path) -> list[str]:
    return [
        sys.executable,
        str(root / "scripts" / "mdm" / "generate-release-manifest.py"),
        "--runtime-root",
        str(runtime),
        "--version",
        "3.1.0a1",
        "--build-id",
        "build-1",
        "--platform",
        "macos",
        "--architecture",
        "arm64",
        "--installer-identity",
        "org.hol.guard",
        "--output",
        str(output),
    ]


def test_generator_covers_every_regular_runtime_file(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    runtime = tmp_path / "runtime"
    (runtime / "bin").mkdir(parents=True)
    (runtime / "bin" / "hol-guard").write_bytes(b"runtime")
    (runtime / "release-trusted-keys.json").write_text("{}")
    output = runtime / "release-manifest.json"

    subprocess.run(_command(root, runtime, output), check=True, capture_output=True, text=True)
    payload = json.loads(output.read_text())

    assert [entry["path"] for entry in payload["files"]] == [
        "bin/hol-guard",
        "release-trusted-keys.json",
    ]


def test_generator_rejects_runtime_symlink(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside")
    (runtime / "link").symlink_to(outside)
    output = runtime / "release-manifest.json"

    result = subprocess.run(_command(root, runtime, output), check=False, capture_output=True, text=True)

    assert result.returncode == 2
    assert "runtime contains a symlink" in result.stderr
    assert not output.exists()


def test_generator_rejects_empty_runtime(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    output = runtime / "release-manifest.json"

    result = subprocess.run(_command(root, runtime, output), check=False, capture_output=True, text=True)

    assert result.returncode == 2
    assert "runtime must contain at least one protected file" in result.stderr


def test_generated_manifest_round_trips_through_verifier(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "hol-guard").write_bytes(b"runtime")
    output = runtime / "release-manifest.json"

    subprocess.run(_command(root, runtime, output), check=True, capture_output=True, text=True)

    result = verify_release_manifest(output, runtime, require_signature=False)
    assert result.healthy

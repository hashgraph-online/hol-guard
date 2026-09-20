#!/usr/bin/env python3
"""Admit the four native-wheel CI artifacts without overwriting duplicate wheels."""

from __future__ import annotations

import argparse
import json
import shutil
import stat
import tempfile
from collections.abc import Sequence
from pathlib import Path

from packaging.version import Version

from scripts.ci.validate_release_artifacts import (
    EXPECTED_PLATFORMS,
    ReleaseArtifactError,
    sha256_file,
    validate_wheel_set,
)

ARTIFACT_PLATFORMS = {
    "hol-guard-native-wheel-linux-x64": "manylinux_2_17_x86_64",
    "hol-guard-native-wheel-x86_64-apple-darwin": "macosx_13_0_x86_64",
    "hol-guard-native-wheel-aarch64-apple-darwin": "macosx_11_0_arm64",
    "hol-guard-native-wheel-windows-x64": "win_amd64",
}
MAX_WHEEL_BYTES = 256 * 1024 * 1024


def _directory(path: Path) -> None:
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ReleaseArtifactError(f"artifact directory is not a regular directory: {path.name}")


def _file(path: Path, maximum: int) -> None:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
        raise ReleaseArtifactError(f"artifact member is not a bounded regular file: {path.name}")


def _same_bytes(first: Path, second: Path) -> bool:
    with first.open("rb") as left, second.open("rb") as right:
        while True:
            chunk = left.read(1024 * 1024)
            if chunk != right.read(1024 * 1024):
                return False
            if not chunk:
                return True


def aggregate_artifacts(artifacts_dir: Path, *, version: str, source_sha: str, rule_digest: str) -> dict[str, object]:
    """Check collection identities, compare pure copies, then run the existing validator."""
    parsed_version = Version(version)
    if str(parsed_version) != version or parsed_version.local is not None:
        raise ReleaseArtifactError("release version must be canonical")
    _directory(artifacts_dir)
    if {path.name for path in artifacts_dir.iterdir()} != set(ARTIFACT_PLATFORMS):
        raise ReleaseArtifactError("exactly the four native-wheel matrix artifacts are required")
    pure_name = f"hol_guard-{version.replace('-', '_')}-py3-none-any.whl"
    selected: dict[str, Path] = {}
    digests: dict[str, str] = {}
    records: list[dict[str, object]] = []
    for artifact, platform in ARTIFACT_PLATFORMS.items():
        directory = artifacts_dir / artifact
        _directory(directory)
        entries = list(directory.iterdir())
        if len(entries) > 32:
            raise ReleaseArtifactError("artifact contains too many top-level members")
        for entry in entries:
            if entry.name == "native-dist":
                continue
            if entry.suffix != ".json":
                raise ReleaseArtifactError(f"unexpected artifact member: {entry.name}")
            _file(entry, 16 * 1024 * 1024)
        wheel_dir = directory / "native-dist"
        _directory(wheel_dir)
        native_name = f"hol_guard-{version.replace('-', '_')}-py3-none-{platform}.whl"
        expected = {native_name} if platform == "win_amd64" else {native_name, pure_name}
        wheels = sorted(wheel_dir.iterdir())
        if {wheel.name for wheel in wheels} != expected:
            raise ReleaseArtifactError(f"wheel membership does not match its matrix artifact: {artifact}")
        for wheel in wheels:
            _file(wheel, MAX_WHEEL_BYTES)
            wheel_digest = sha256_file(wheel)
            previous = selected.get(wheel.name)
            if previous is not None and (
                wheel.name != pure_name or digests[wheel.name] != wheel_digest or not _same_bytes(previous, wheel)
            ):
                raise ReleaseArtifactError(f"conflicting duplicate wheel: {wheel.name}")
            records.append(
                {
                    "artifact": artifact,
                    "member": f"native-dist/{wheel.name}",
                    "sha256": wheel_digest,
                    "bytes": wheel.stat().st_size,
                    "identical_duplicate": previous is not None,
                }
            )
            if previous is None:
                selected[wheel.name] = wheel
                digests[wheel.name] = wheel_digest
    # Every duplicate is compared before any file is copied into the shared set.
    with tempfile.TemporaryDirectory(prefix="hol-guard-native-matrix-") as temporary:
        dist = Path(temporary)
        for name, source in selected.items():
            target = dist / name
            shutil.copyfile(source, target)
            if sha256_file(target) != digests[name] or not _same_bytes(source, target):
                raise ReleaseArtifactError(f"wheel changed during collection: {name}")
        evidence = validate_wheel_set(
            dist,
            version=version,
            source_sha=source_sha,
            rule_digest=rule_digest,
            platforms=tuple(sorted(EXPECTED_PLATFORMS)),
        )
    return {
        "schema": "hol-guard-native-matrix-admission.v1",
        "passed": True,
        "collected": records,
        "validation": evidence,
        "scope": "offline wheel identity admission; no installed execution, signing or release qualification",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = aggregate_artifacts(
            args.artifacts_dir, version=args.version, source_sha=args.source_sha, rule_digest=args.rule_digest
        )
    except (OSError, ValueError) as error:
        report = {"schema": "hol-guard-native-matrix-admission.v1", "passed": False, "failure": str(error)}
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

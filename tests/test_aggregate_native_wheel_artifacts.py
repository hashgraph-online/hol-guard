from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scripts.ci.aggregate_native_wheel_artifacts import ARTIFACT_PLATFORMS, aggregate_artifacts, main
from scripts.ci.validate_release_artifacts import EXPECTED_PLATFORMS, ReleaseArtifactError
from tests.test_validate_release_artifacts import RULE_DIGEST, SOURCE_SHA, VERSION, _dist


def _artifacts(root: Path) -> Path:
    canonical = _dist(root / "canonical", tuple(EXPECTED_PLATFORMS))
    artifacts = root / "artifacts"
    for name, platform in ARTIFACT_PLATFORMS.items():
        dest = artifacts / name / "native-dist"
        dest.mkdir(parents=True)
        shutil.copyfile(
            canonical / f"hol_guard-{VERSION}-py3-none-{platform}.whl",
            dest / f"hol_guard-{VERSION}-py3-none-{platform}.whl",
        )
        if platform != "win_amd64":
            shutil.copyfile(
                canonical / f"hol_guard-{VERSION}-py3-none-any.whl", dest / f"hol_guard-{VERSION}-py3-none-any.whl"
            )
    return artifacts


def _admit(artifacts: Path, **overrides: str) -> dict[str, object]:
    arguments = {"version": VERSION, "source_sha": SOURCE_SHA, "rule_digest": RULE_DIGEST} | overrides
    return aggregate_artifacts(artifacts, **arguments)


def test_four_platform_collection_uses_real_validator_and_compares_all_pure_copies(tmp_path: Path) -> None:
    result = _admit(_artifacts(tmp_path))
    validation = result["validation"]
    assert isinstance(validation, dict)
    assert validation["windows_waiver"] is None
    assert validation["platforms"] == sorted(EXPECTED_PLATFORMS)
    assert len(validation["artifacts"]) == 5
    records = result["collected"]
    assert isinstance(records, list)
    assert len(records) == 7
    assert sum(record["identical_duplicate"] for record in records) == 2


@pytest.mark.parametrize(
    "mutation", ["missing_group", "extra_group", "missing_windows", "wrong_group", "duplicate_native"]
)
def test_incomplete_or_ambiguous_artifact_membership_is_rejected(tmp_path: Path, mutation: str) -> None:
    artifacts = _artifacts(tmp_path)
    windows = artifacts / "hol-guard-native-wheel-windows-x64"
    linux = artifacts / "hol-guard-native-wheel-linux-x64"
    native = windows / "native-dist" / f"hol_guard-{VERSION}-py3-none-win_amd64.whl"
    if mutation == "missing_group":
        shutil.rmtree(windows)
    elif mutation == "extra_group":
        (artifacts / "unrelated").mkdir()
    elif mutation == "missing_windows":
        native.unlink()
    elif mutation == "wrong_group":
        native.rename(linux / "native-dist" / native.name)
    else:
        shutil.copyfile(native, windows / "native-dist" / f"hol_guard-{VERSION}-1-py3-none-win_amd64.whl")
    with pytest.raises(ReleaseArtifactError, match=r"artifacts are required|wheel membership"):
        _admit(artifacts)


def test_conflicting_pure_wheel_is_rejected_before_staging(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = _artifacts(tmp_path)
    pure = (
        artifacts
        / "hol-guard-native-wheel-x86_64-apple-darwin"
        / "native-dist"
        / f"hol_guard-{VERSION}-py3-none-any.whl"
    )
    with pure.open("ab") as handle:
        handle.write(b"changed")

    def unexpected_copy(*args: object, **kwargs: object) -> None:
        pytest.fail("a conflicting set must be rejected before staging")

    monkeypatch.setattr("scripts.ci.aggregate_native_wheel_artifacts.shutil.copyfile", unexpected_copy)
    with pytest.raises(ReleaseArtifactError, match="conflicting duplicate"):
        _admit(artifacts)


@pytest.mark.parametrize("field,value", [("source_sha", "c" * 40), ("rule_digest", "d" * 64), ("version", "3.0.2")])
def test_mismatched_build_identity_is_rejected_by_collection_or_validator(
    tmp_path: Path, field: str, value: str
) -> None:
    with pytest.raises(ReleaseArtifactError, match=r"identity mismatch|wheel membership"):
        _admit(_artifacts(tmp_path), **{field: value})


def test_malformed_native_archive_preserves_failed_report(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    native = (
        artifacts / "hol-guard-native-wheel-windows-x64" / "native-dist" / f"hol_guard-{VERSION}-py3-none-win_amd64.whl"
    )
    native.write_bytes(b"not a ZIP")
    output = tmp_path / "report.json"
    assert (
        main(
            [
                "--artifacts-dir",
                str(artifacts),
                "--version",
                VERSION,
                "--source-sha",
                SOURCE_SHA,
                "--rule-digest",
                RULE_DIGEST,
                "--output",
                str(output),
            ]
        )
        == 1
    )
    report = json.loads(output.read_text())
    assert report["passed"] is False
    assert "wheel metadata could not be read" in report["failure"]


def test_symlink_wheel_is_not_admitted(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    native = (
        artifacts / "hol-guard-native-wheel-windows-x64" / "native-dist" / f"hol_guard-{VERSION}-py3-none-win_amd64.whl"
    )
    original = native.with_suffix(".saved")
    native.rename(original)
    native.symlink_to(original)
    original.rename(tmp_path / "saved.whl")
    with pytest.raises(ReleaseArtifactError, match="bounded regular file"):
        _admit(artifacts)


def test_wheel_change_between_comparison_and_staging_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = _artifacts(tmp_path)
    original_copy = shutil.copyfile

    def changed_copy(source: Path, target: Path) -> Path:
        with source.open("ab") as handle:
            handle.write(b"changed after comparison")
        return original_copy(source, target)

    monkeypatch.setattr("scripts.ci.aggregate_native_wheel_artifacts.shutil.copyfile", changed_copy)
    with pytest.raises(ReleaseArtifactError, match="changed during collection"):
        _admit(artifacts)

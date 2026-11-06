from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.release_artifact_sets import (
    ArtifactSetError,
    main,
    registry_wheels,
    remote_for_artifact_set,
    select_upload_artifacts,
)

VERSION = "3.40.0"
PURE = f"hol_guard-{VERSION}-py3-none-any.whl"
NATIVE = f"hol_guard-{VERSION}-py3-none-macosx_11_0_arm64.whl"
SDIST = f"hol_guard-{VERSION}.tar.gz"
WINDOWS_ARM = f"hol_guard-{VERSION}-py3-none-win_arm64.whl"
INTEL_MAC = f"hol_guard-{VERSION}-py3-none-macosx_13_0_x86_64.whl"
LINUX_ARM = f"hol_guard-{VERSION}-py3-none-manylinux_2_17_aarch64.whl"
LOCAL = {PURE: "pure", NATIVE: "native", SDIST: "sdist"}


def test_wheels_artifact_set_leaves_out_only_the_sdist() -> None:
    assert select_upload_artifacts(LOCAL, version=VERSION, artifact_set="wheels") == {PURE: "pure", NATIVE: "native"}
    assert select_upload_artifacts(LOCAL, version=VERSION, artifact_set="full") == LOCAL
    assert select_upload_artifacts(LOCAL, version=VERSION, artifact_set="pure") == {PURE: "pure"}
    with pytest.raises(ArtifactSetError):
        select_upload_artifacts(LOCAL, version=VERSION, artifact_set="sdist")


def test_wheels_artifact_set_accepts_matching_earlier_registry_sdist() -> None:
    remote = {PURE: "pure", NATIVE: "native", SDIST: "sdist"}

    assert remote_for_artifact_set(remote, LOCAL, version=VERSION, artifact_set="wheels") == {
        PURE: "pure",
        NATIVE: "native",
    }


def test_wheels_artifact_set_keeps_mismatched_registry_sdist_visible() -> None:
    remote = {PURE: "pure", NATIVE: "native", SDIST: "different"}

    assert remote_for_artifact_set(remote, LOCAL, version=VERSION, artifact_set="wheels") == remote
    assert remote_for_artifact_set(remote, LOCAL, version=VERSION, artifact_set="full") == remote


def test_wheels_artifact_set_keeps_github_only_platforms_on_the_release() -> None:
    local = {**LOCAL, WINDOWS_ARM: "windows-arm", INTEL_MAC: "intel-mac", LINUX_ARM: "linux-arm"}

    assert select_upload_artifacts(local, version=VERSION, artifact_set="wheels") == {PURE: "pure", NATIVE: "native"}
    assert select_upload_artifacts(local, version=VERSION, artifact_set="full") == local
    assert registry_wheels(local) == [PURE, NATIVE]


def test_stage_pypi_copies_only_registry_wheels(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in (PURE, NATIVE, SDIST, WINDOWS_ARM, INTEL_MAC, LINUX_ARM):
        (dist / name).write_bytes(name.encode())
    output = tmp_path / "pypi"

    assert main(["stage-pypi", "--dist-dir", str(dist), "--output-dir", str(output)]) == 0

    assert sorted(path.name for path in output.iterdir()) == [PURE, NATIVE]
    assert (output / PURE).read_bytes() == PURE.encode()
    assert json.loads(capsys.readouterr().out)["files"] == [PURE, NATIVE]
    assert main(["stage-pypi", "--dist-dir", str(dist), "--output-dir", str(output)]) == 1

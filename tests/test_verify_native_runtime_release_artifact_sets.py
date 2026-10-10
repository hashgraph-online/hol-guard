from __future__ import annotations

import pytest

from scripts.release_artifact_sets import (
    ArtifactSetError,
    remote_for_artifact_set,
    select_upload_artifacts,
)

VERSION = "3.40.0"
PURE = f"hol_guard-{VERSION}-py3-none-any.whl"
NATIVE = f"hol_guard-{VERSION}-py3-none-macosx_11_0_arm64.whl"
SDIST = f"hol_guard-{VERSION}.tar.gz"
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

"""Registry artifact subsets for HOL Guard publication."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

ARTIFACT_SETS: Final = ("full", "wheels", "pure")


class ArtifactSetError(RuntimeError):
    """Raised when a registry artifact set cannot be selected."""


def sdist_name(version: str) -> str:
    return f"hol_guard-{version}.tar.gz"


def select_upload_artifacts(local: Mapping[str, str], *, version: str, artifact_set: str) -> dict[str, str]:
    """Return the registry subset that this publication is allowed to upload.

    ``version`` must already be canonical.
    """

    if artifact_set == "full":
        return dict(local)
    if artifact_set == "wheels":
        # The sdist stays on the GitHub release; pip never selects it because the pure wheel matches everywhere.
        return {filename: digest for filename, digest in local.items() if filename != sdist_name(version)}
    if artifact_set != "pure":
        raise ArtifactSetError("Unsupported Guard registry artifact set")
    wheel = f"hol_guard-{version.replace('-', '_')}-py3-none-any.whl"
    digest = local.get(wheel)
    if digest is None:
        raise ArtifactSetError("Guard pure wheel is missing from the local release set")
    return {wheel: digest}


def remote_for_artifact_set(
    remote: Mapping[str, str],
    complete: Mapping[str, str],
    *,
    version: str,
    artifact_set: str,
) -> dict[str, str]:
    """Drop a registry sdist that predates wheels-only publication when its bytes are the local sdist."""

    sdist = sdist_name(version)
    if artifact_set == "wheels" and sdist in remote and remote[sdist] == complete.get(sdist):
        return {filename: digest for filename, digest in remote.items() if filename != sdist}
    return dict(remote)

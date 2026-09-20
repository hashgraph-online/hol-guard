"""Local-wheel provenance and trusted updater failure results."""

from __future__ import annotations

from pathlib import Path

from .update_artifact import TrustedWheelArtifact
from .update_subprocess import TrustedUpdateContext, UpdateSubprocessError


def _record_verified_local_wheel_receipt(
    payload: dict[str, object],
    *,
    update_context: TrustedUpdateContext,
    trusted_wheel: TrustedWheelArtifact,
    guard_home: Path,
    installed_version: str,
) -> None:
    """Delete staging only after installed PEP 610 metadata binds the exact wheel."""

    try:
        trusted_wheel.revalidate()
        installed_distribution = update_context.query_distribution()
    except (_update.UpdateArtifactError, _update.UpdateSubprocessError):
        _update._retain_local_wheel_staging(
            payload,
            "Retained the private staged wheel because the installed local-wheel provenance could not be verified.",
        )
        return
    archive_install = _update._local_archive_install_payload(installed_distribution.direct_url)
    archive_sha256 = _update._direct_url_archive_sha256(installed_distribution.direct_url)
    staged_path_value = archive_install.get("path") if isinstance(archive_install, dict) else None
    try:
        versions_match = (
            _update.Version(installed_distribution.version)
            == _update.Version(installed_version)
            == _update.Version(trusted_wheel.version)
        )
    except _update.InvalidVersion:
        versions_match = False
    if (
        not versions_match
        or not isinstance(staged_path_value, str)
        or _update.Path(staged_path_value) != trusted_wheel.staged_path
        or archive_sha256 != trusted_wheel.sha256
    ):
        _update._retain_local_wheel_staging(
            payload,
            "Retained the private staged wheel because installed PEP 610 metadata did not bind the exact artifact.",
        )
        return
    try:
        _update.record_local_wheel_receipt(
            trusted_wheel,
            guard_home=guard_home,
            installed_version=installed_version,
        )
    except _update.UpdateArtifactError:
        _update._retain_local_wheel_staging(
            payload,
            "Retained the private staged wheel because its local-source receipt could not be persisted.",
        )
        return
    payload["local_wheel_receipt"] = "recorded"
    trusted_wheel.cleanup()


def _retain_local_wheel_staging(payload: dict[str, object], note: str | None = None) -> None:
    payload["local_wheel_receipt"] = "staging_retained"
    _update._append_payload_note(
        payload,
        note or "Retained the private staged wheel because installer completion could not be verified conclusively.",
    )


def _trusted_update_failure(
    payload: dict[str, object],
    error: UpdateSubprocessError,
    *,
    trusted_wheel: TrustedWheelArtifact | None = None,
    retain_trusted_wheel: bool = False,
) -> tuple[dict[str, object], int]:
    if trusted_wheel is not None:
        if retain_trusted_wheel:
            _update._retain_local_wheel_staging(payload)
        else:
            trusted_wheel.cleanup()
    payload.update(
        {
            "status": "failed",
            "changed": False,
            "reason_code": error.reason_code,
            "error": error.reason_code,
            "message": _update._TRUSTED_UPDATE_FAILURE_MESSAGES.get(
                error.reason_code,
                "HOL Guard update could not complete in its trusted maintenance environment.",
            ),
        }
    )
    return payload, 1


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402

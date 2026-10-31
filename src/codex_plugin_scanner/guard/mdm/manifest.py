"""Signed release-manifest verification for machine-owned runtimes.

The native runtime reads, verifies and hashes the runtime; this module frames
the caller's expectations and keeps the verdict type the integrity and
lifecycle surfaces report.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

RELEASE_MANIFEST_VERIFY_FEATURE = "native-release-manifest-verify-v1"
RELEASE_MANIFEST_VERIFY_COMMAND = "release-manifest-verify"
RELEASE_MANIFEST_VERIFY_SCHEMA = "release-manifest-verify.v1"
_STATUS_TIMEOUT_SECONDS = 10.0
# The runtime walk is bounded at 30 seconds and hashing at 2 GiB.
_VERIFY_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 64 * 1024
_RESPONSE_FIELDS = ("status", "reason_code", "version", "build_id", "installer_identity", "signature_state")


@dataclass(frozen=True, slots=True)
class ManifestVerification:
    status: str
    reason_code: str
    version: str | None = None
    build_id: str | None = None
    installer_identity: str | None = None
    signature_state: str = "unverified"

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"

    def to_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reasonCode": self.reason_code,
            "version": self.version,
            "buildId": self.build_id,
            "installerIdentity": self.installer_identity,
            "signatureState": self.signature_state,
        }


_INVALID = ManifestVerification("tampered", "release_manifest_invalid")


def _verification_from_native(response: object) -> ManifestVerification:
    if not isinstance(response, dict) or set(response) != set(_RESPONSE_FIELDS):
        return _INVALID
    status, reason_code, signature_state = (response[key] for key in ("status", "reason_code", "signature_state"))
    identity = tuple(response[key] for key in ("version", "build_id", "installer_identity"))
    if not all(isinstance(value, str) for value in (status, reason_code, signature_state)):
        return _INVALID
    if not all(value is None or isinstance(value, str) for value in identity):
        return _INVALID
    version, build_id, installer_identity = identity
    return ManifestVerification(status, reason_code, version, build_id, installer_identity, signature_state)


def verify_release_manifest(
    manifest_path: Path,
    runtime_root: Path,
    *,
    trusted_keys: Mapping[str, bytes] | None = None,
    require_signature: bool = True,
    expected_platform: str | None = None,
    expected_architecture: str | None = None,
    expected_owner_uid: int | None = None,
    expected_installer_identity: str | None = None,
    expected_native_version: str | None = None,
    minimum_version: str | None = None,
) -> ManifestVerification:
    """Verify manifest identity, signature, complete runtime coverage, and every file hash.

    A runtime that cannot answer leaves the manifest unverified, which is
    reported as an invalid manifest.
    """

    from ..native_runtime import _run_native_process, native_runtime_status

    status = native_runtime_status(deadline_monotonic=time.monotonic() + _STATUS_TIMEOUT_SECONDS)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or RELEASE_MANIFEST_VERIFY_FEATURE not in status.capabilities.features
    ):
        return _INVALID
    request = {
        "schema": RELEASE_MANIFEST_VERIFY_SCHEMA,
        "manifest_path": str(manifest_path),
        "runtime_root": str(runtime_root),
        "trusted_keys": {key_id: bytes(key).hex() for key_id, key in (trusted_keys or {}).items()},
        "require_signature": require_signature,
        "expected_platform": expected_platform,
        "expected_architecture": expected_architecture,
        "expected_owner_uid": expected_owner_uid,
        "expected_installer_identity": expected_installer_identity,
        "expected_native_version": expected_native_version,
        "minimum_version": minimum_version,
    }
    try:
        input_text = json.dumps(request, sort_keys=True)
    except (TypeError, ValueError):
        return _INVALID
    output = _run_native_process(
        status.identity.path,
        (RELEASE_MANIFEST_VERIFY_COMMAND, "--stdin"),
        input_text=input_text,
        timeout_seconds=_VERIFY_TIMEOUT_SECONDS,
        output_limit=_OUTPUT_LIMIT_BYTES,
    )
    if output is None:
        return _INVALID
    try:
        return _verification_from_native(json.loads(output))
    except ValueError:
        return _INVALID


__all__ = ["ManifestVerification", "verify_release_manifest"]

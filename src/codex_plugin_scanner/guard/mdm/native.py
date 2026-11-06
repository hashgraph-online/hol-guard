"""Native package identity and publisher-signature verification.

The native runtime runs the pinned platform probes and decides the verdict;
this module only names the platform and the configured pins. Without the
runtime the install never reports health.
"""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .runtime_request import runtime_answer

NATIVE_INSTALL_FEATURE = "native-install-verdict-v1"
NATIVE_INSTALL_COMMAND = "native-install-verdict"
NATIVE_INSTALL_SCHEMA = "native-install-verdict.v1"
_COMMAND_TIMEOUT_SECONDS = 40.0
_MAX_OUTPUT_BYTES = 64 * 1024
_PLATFORMS = {"Darwin": "macos", "Windows": "windows"}


@dataclass(frozen=True, slots=True)
class NativeInstallVerification:
    status: str
    reason_code: str
    package_identity: str
    signature_state: str
    version: str | None = None

    @property
    def healthy(self) -> bool:
        return self.status == "healthy"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reasonCode": self.reason_code,
            "packageIdentity": self.package_identity,
            "signatureState": self.signature_state,
            "version": self.version,
        }


_PROBE_FAILED = NativeInstallVerification("unknown", "native_install_probe_failed", "unknown", "unknown")


def verify_native_install(
    runtime_root: Path,
    *,
    macos_team_id: str | None = None,
    windows_signer_thumbprints: tuple[str, ...] = (),
) -> NativeInstallVerification:
    """Verify a HOL Guard Machine MDM install identity.

    Windows thumbprints belong to the managed machine package, not Desktop
    Artifact Signing. Do not pin a rotating Azure Public Trust leaf here.
    """
    system = _PLATFORMS.get(platform.system())
    if system is None:
        return NativeInstallVerification("unsupported", "native_platform_unsupported", "unknown", "unsupported")
    request: dict[str, object] = {"platform": system, "runtime_root": str(runtime_root)}
    if system == "macos":
        request["macos_team_id"] = macos_team_id
    else:
        request["windows_signer_thumbprints"] = list(windows_signer_thumbprints)
    answer = _native_answer(request)
    if answer is None:
        return _PROBE_FAILED
    fields = tuple(answer.get(name) for name in ("status", "reason_code", "package_identity", "signature_state"))
    version = answer.get("version")
    if not all(isinstance(field, str) for field in fields) or not (version is None or isinstance(version, str)):
        return _PROBE_FAILED
    status, reason_code, package_identity, signature_state = cast(tuple[str, str, str, str], fields)
    return NativeInstallVerification(status, reason_code, package_identity, signature_state, version)


def _native_answer(request: dict[str, object]) -> dict[str, object] | None:
    """The runtime's verdict for one install, or ``None`` when it cannot answer."""

    answer = runtime_answer(
        NATIVE_INSTALL_FEATURE,
        NATIVE_INSTALL_COMMAND,
        {"schema": NATIVE_INSTALL_SCHEMA, **request},
        deadline=time.monotonic() + _COMMAND_TIMEOUT_SECONDS,
        # A freshly installed runtime may need most of the budget for its first status probe.
        status_timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
        output_limit=_MAX_OUTPUT_BYTES,
    )
    return answer if answer is not None and answer.get("ok") is True else None


__all__ = ["NativeInstallVerification", "verify_native_install"]

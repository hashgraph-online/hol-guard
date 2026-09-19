"""Native runtime selection with the control plane's current lookup hooks."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from .native_runtime_capabilities import NativeRuntimeCapabilities

if TYPE_CHECKING:
    from .native_runtime import NativeRuntimeIdentity, NativeRuntimeManifest, NativeRuntimeStatus


def select_native_runtime(
    *,
    check_continuation: Callable[[], None] | None = None,
    capability_provider: Callable[[NativeRuntimeIdentity], NativeRuntimeCapabilities | None] | None = None,
) -> NativeRuntimeStatus:
    from . import native_runtime as api

    if check_continuation is not None:
        check_continuation()
    mode = api.native_mode()
    if mode == "off":
        from .native_runtime import NativeRuntimeStatus

        return NativeRuntimeStatus(
            mode=mode,
            available=False,
            compatible=False,
            reason="native_disabled",
        )
    for candidate in api._runtime_candidates():
        if check_continuation is not None:
            check_continuation()
        api._restore_bundled_runtime_execute_bit(candidate)
        identity = (
            api._validate_binary(candidate)
            if check_continuation is None
            else api._validate_binary(candidate, check_continuation=check_continuation)
        )
        if check_continuation is not None:
            check_continuation()
        if identity is None:
            continue
        manifest: NativeRuntimeManifest | None = None
        if api._is_bundled_candidate(candidate):
            manifest, manifest_error = api._manifest_for_bundled_identity(identity)
            if manifest_error is not None:
                from .native_runtime import NativeRuntimeStatus

                return NativeRuntimeStatus(
                    mode=mode,
                    available=True,
                    compatible=False,
                    reason=manifest_error,
                    identity=identity,
                )
        if check_continuation is not None:
            check_continuation()
        capabilities = (
            api._capabilities_for_identity(str(identity.path), identity.size, identity.mtime_ns, identity.sha256)
            if capability_provider is None
            else capability_provider(identity)
        )
        if check_continuation is not None:
            check_continuation()
        if capabilities is None:
            continue
        if capabilities.protocol_version != api._NATIVE_PROTOCOL_VERSION:
            from .native_runtime import NativeRuntimeStatus

            return NativeRuntimeStatus(
                mode=mode,
                available=True,
                compatible=False,
                reason="native_protocol_mismatch",
                identity=identity,
                capabilities=capabilities,
            )
        if manifest is not None:
            if capabilities.protocol_version != manifest.protocol_version:
                reason = "native_manifest_protocol_mismatch"
            elif capabilities.runtime_version != manifest.package_version:
                reason = "native_manifest_version_mismatch"
            elif capabilities.rule_digest != manifest.rule_digest:
                reason = "native_manifest_rule_mismatch"
            elif capabilities.build_sha != manifest.source_sha:
                reason = "native_manifest_build_mismatch"
            else:
                reason = None
            if reason is not None:
                from .native_runtime import NativeRuntimeStatus

                return NativeRuntimeStatus(
                    mode=mode,
                    available=True,
                    compatible=False,
                    reason=reason,
                    identity=identity,
                    capabilities=capabilities,
                )
        if check_continuation is not None:
            check_continuation()
        expected_version = api._python_package_version()
        version_compatible = expected_version is None or capabilities.runtime_version == expected_version
        compatible = version_compatible or mode in {"shadow", "force"}
        from .native_runtime import NativeRuntimeStatus

        return NativeRuntimeStatus(
            mode=mode,
            available=True,
            compatible=compatible,
            reason="native_ready" if compatible else "native_version_mismatch",
            identity=identity,
            capabilities=capabilities,
        )
    from .native_runtime import NativeRuntimeStatus

    return NativeRuntimeStatus(
        mode=mode,
        available=False,
        compatible=False,
        reason="native_unavailable",
    )

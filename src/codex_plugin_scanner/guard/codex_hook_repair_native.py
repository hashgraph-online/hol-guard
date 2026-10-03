"""Read-only, deadline-owned native inspection for an exact repair plan."""

from __future__ import annotations

import json
import math
import time

from . import native_runtime as native
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime import NativeRuntimeIdentity
from .runtime_transition import TransitionError, inverse_recovery_budget
from .runtime_transition_prepare import _pin_executable


def inspect_codex_repair_native_runtime(*, deadline_monotonic: float) -> NativeRuntimeIdentity:
    """Inspect existing selection without chmod, installation or launch override.

    Production auto mode retains bundled manifest/version admission. Force
    mode remains the explicit developer fixture path. Shadow/off cannot prove
    protection. The capabilities probe keeps its existing one-second stage cap
    within the parent's original deadline and process containment.
    """

    def check_deadline() -> None:
        if (
            isinstance(deadline_monotonic, bool)
            or not math.isfinite(deadline_monotonic)
            or time.monotonic() >= deadline_monotonic
        ):
            raise TransitionError("deadline_exceeded")

    check_deadline()
    mode = native.native_mode()
    if mode not in {"auto", "force"}:
        raise TransitionError("authority_repair_native_mode_invalid")
    with inverse_recovery_budget(deadline_monotonic), hook_validation_deadline(deadline_monotonic):
        for candidate in native._runtime_candidates():
            check_deadline()
            if not candidate.exists() and not candidate.is_symlink():
                continue
            path = candidate.expanduser()
            # Deliberately do not call native_runtime_status: its compatibility
            # behavior includes repairing a bundled executable's mode.
            dependency = _pin_executable(path, deadline=deadline_monotonic)
            artifact = dependency.artifact_identity
            assert artifact is not None and dependency.expected_digest is not None
            metadata = path.stat()
            identity = NativeRuntimeIdentity(
                path.resolve(strict=True), metadata.st_size, metadata.st_mtime_ns, dependency.expected_digest
            )
            manifest = None
            if native._is_bundled_candidate(path):
                manifest, reason = native._manifest_for_bundled_identity(identity)
                check_deadline()
                if reason is not None:
                    raise TransitionError(reason)
            result = run_isolated_hook_process(
                (str(identity.path), "capabilities", "--json"),
                input_text="",
                cwd=identity.path.parent,
                environment=native._isolated_environment(),
                output_limit=64 * 1024,
                deadline_monotonic=min(deadline_monotonic, time.monotonic() + 1.0),
            )
            check_deadline()
            if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
                raise TransitionError("authority_repair_native_inspection_failed")
            try:
                capabilities = native._decode_capabilities(json.loads(result.stdout))
            except (json.JSONDecodeError, RecursionError) as exc:
                raise TransitionError("authority_repair_native_inspection_failed") from exc
            if capabilities is None or capabilities.protocol_version != native._NATIVE_PROTOCOL_VERSION:
                raise TransitionError("native_protocol_mismatch")
            if manifest is not None and (
                capabilities.runtime_version != manifest.package_version
                or capabilities.rule_digest != manifest.rule_digest
                or capabilities.build_sha != manifest.source_sha
            ):
                raise TransitionError("native_manifest_capabilities_mismatch")
            version = native._python_package_version()
            check_deadline()
            if mode == "auto" and version is not None and capabilities.runtime_version != version:
                raise TransitionError("native_version_mismatch")
            _pin_executable(
                path,
                deadline=deadline_monotonic,
                expected={
                    "size": identity.size,
                    "mtime_ns": identity.mtime_ns,
                    "sha256": identity.sha256,
                },
            )
            check_deadline()
            return identity
    raise TransitionError("authority_repair_native_unavailable")

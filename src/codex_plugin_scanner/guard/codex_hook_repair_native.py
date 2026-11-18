"""Read-only, deadline-owned native inspection for an exact repair plan."""

from __future__ import annotations

import json
import time

from . import native_runtime as native
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import require_deadline, runtime_compare
from .runtime_transition import TransitionError, inverse_recovery_budget
from .runtime_transition_prepare import _pin_executable


def inspect_codex_repair_native_runtime(*, deadline_monotonic: float) -> NativeRuntimeIdentity:
    """Inspect existing selection without chmod, installation or launch override.

    Production auto mode retains bundled manifest/version admission. Force
    mode remains the explicit developer fixture path. Legacy shadow/off values
    resolve to auto. The capabilities probe keeps its existing one-second stage cap
    within the parent's original deadline and process containment.
    """

    require_deadline(deadline_monotonic)
    mode = native.native_mode()
    with inverse_recovery_budget(deadline_monotonic), hook_validation_deadline(deadline_monotonic):
        for candidate in native._runtime_candidates():
            require_deadline(deadline_monotonic)
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
                require_deadline(deadline_monotonic)
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
            require_deadline(deadline_monotonic)
            runtime_compare(
                "probe",
                returncode=result.returncode,
                timed_out=result.timed_out,
                containment_failed=result.containment_failed,
                output_limit_exceeded=result.output_limit_exceeded,
            )
            try:
                capabilities = native._decode_capabilities(json.loads(result.stdout))
            except (json.JSONDecodeError, RecursionError) as exc:
                raise TransitionError("authority_repair_native_inspection_failed") from exc
            runtime_compare(
                "capabilities",
                capabilities=None
                if capabilities is None
                else {
                    "protocol_version": capabilities.protocol_version,
                    "runtime_version": capabilities.runtime_version,
                    "rule_digest": capabilities.rule_digest,
                    "build_sha": capabilities.build_sha,
                },
                protocol=native._NATIVE_PROTOCOL_VERSION,
                manifest=None
                if manifest is None
                else {
                    "package_version": manifest.package_version,
                    "rule_digest": manifest.rule_digest,
                    "source_sha": manifest.source_sha,
                },
            )
            assert capabilities is not None  # the runtime refused a missing one
            version = native._python_package_version()
            require_deadline(deadline_monotonic)
            runtime_compare(
                "version",
                mode=mode,
                version=version,
                runtime_version=capabilities.runtime_version,
            )
            # A replaced runtime cannot vouch for itself, so a changed
            # generation is refused before the runtime is asked to re-pin it.
            try:
                current = path.stat()
                after: list[int] | None = [current.st_size, current.st_mtime_ns, current.st_ino]
            except OSError:
                after = None
            runtime_compare("generation", before=[metadata.st_size, metadata.st_mtime_ns, metadata.st_ino], after=after)
            _pin_executable(
                path,
                deadline=deadline_monotonic,
                expected={
                    "size": identity.size,
                    "mtime_ns": identity.mtime_ns,
                    "sha256": identity.sha256,
                },
            )
            require_deadline(deadline_monotonic)
            return identity
    raise TransitionError("authority_repair_native_unavailable")

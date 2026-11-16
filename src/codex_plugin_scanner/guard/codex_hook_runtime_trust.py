"""Runtime enforcement for authenticated managed Codex hook launchers.

The native runtime authenticates the private manifest and checks every launch
identity and contract. This module only names the facts the runtime cannot
see — its own path and the frozen executable — and carries the verified launch
context to the child process runner.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .codex_hook_file_integrity import (
    CodexHookIntegrityError,
    _native,
    active_hook_validation_deadline,
    check_hook_validation_deadline,
)
from .codex_hook_integrity import manifest_refusal
from .codex_hook_launch_runtime import (
    isolated_hook_environment,
    private_hook_runtime_cwd,
    run_isolated_hook_process,
)

_LAUNCH_INVALID = "codex_hook_launch_invalid"


@dataclass(frozen=True, slots=True)
class TrustedCodexHookLaunch:
    """A live authenticated launch context safe for child execution."""

    cwd: Path
    environment: Mapping[str, str]
    deadline_monotonic: float | None = None

    def _launch_deadline(self, timeout_seconds: float) -> float | None:
        if self.deadline_monotonic is None:
            return None
        return min(self.deadline_monotonic, time.monotonic() + max(0.0, timeout_seconds))

    def run_start(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
        failure_kind: str = "transport-failure",
    ) -> bool:
        if failure_kind not in {
            "authenticated-control-plane-failure",
            "overload",
            "transport-failure",
        }:
            failure_kind = "transport-failure"
        environment = dict(self.environment)
        environment["HOL_GUARD_HOOK_FAILURE_KIND"] = failure_kind
        result = run_isolated_hook_process(
            command,
            input_text="",
            cwd=self.cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            deadline_monotonic=self._launch_deadline(timeout_seconds),
            allow_windows_breakaway=True,
        )
        return (
            result.returncode == 0
            and not result.output_limit_exceeded
            and not result.timed_out
            and not result.containment_failed
        )

    def run_fallback(
        self,
        command: Sequence[str],
        *,
        data: str,
        timeout_seconds: float,
    ) -> str | None:
        result = run_isolated_hook_process(
            command,
            input_text=data,
            cwd=self.cwd,
            environment=self.environment,
            timeout_seconds=timeout_seconds,
            deadline_monotonic=self._launch_deadline(timeout_seconds),
        )
        if result.returncode != 0 or result.output_limit_exceeded or result.timed_out or result.containment_failed:
            return None
        return result.stdout


def _checked(op: str, **fields: object) -> dict[str, object]:
    try:
        return _native(op, **fields)
    except CodexHookIntegrityError as exc:
        if exc.reason == _LAUNCH_INVALID:
            raise ValueError(exc.message) from exc
        if exc.message == exc.reason:
            # The runtime names a manifest refusal by its reason alone.
            raise manifest_refusal(exc.reason) from exc
        raise


def authenticate_codex_hook_launch(
    *,
    manifest_path: str | Path,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
    frozen: Mapping[str, object] | None = None,
) -> TrustedCodexHookLaunch:
    """Have the native runtime authenticate one launch, then carry its context."""

    _checked(
        "launch",
        manifest_path=str(manifest_path),
        state_path=str(state_path),
        fallback_command=list(fallback_command),
        start_command=list(start_command),
        config_json=config_json,
        runtime_path=str(Path(__file__)),
        frozen=None if frozen is None else dict(frozen),
    )
    return TrustedCodexHookLaunch(
        cwd=private_hook_runtime_cwd(Path(manifest_path)),
        environment=isolated_hook_environment(),
        deadline_monotonic=active_hook_validation_deadline(),
    )


def validate_codex_hook_launch(
    *,
    manifest_path: str | Path,
    state_path: str | Path,
    fallback_command: Sequence[str],
    start_command: Sequence[str],
    config_json: str,
) -> TrustedCodexHookLaunch:
    """Authenticate the complete current bridge config and child identities."""

    return authenticate_codex_hook_launch(
        manifest_path=manifest_path,
        state_path=state_path,
        fallback_command=fallback_command,
        start_command=start_command,
        config_json=config_json,
    )


def verify_captured_launch_generation(
    manifest: Mapping[str, object],
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Validate an authenticated captured layout without selecting or spawning it.

    The caller must authenticate the enclosing manifest and retained argv
    membership first. Normal launch verification still binds this module's
    own physical path; this read-only check binds the recorded package root.
    """
    check_hook_validation_deadline()
    _checked("captured", manifest=dict(manifest))
    check_hook_validation_deadline()
    interpreter = manifest.get("interpreter")
    files = manifest.get("packaged_files")
    if not isinstance(interpreter, dict) or not isinstance(files, list):
        raise ValueError("managed Codex hook captured layout is invalid")
    packaged = {
        str(item["role"]): item for item in files if isinstance(item, dict) and isinstance(item.get("role"), str)
    }
    return interpreter, packaged

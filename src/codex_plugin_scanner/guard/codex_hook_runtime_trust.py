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
from typing import Any

from .codex_hook_file_integrity import (
    CodexHookIntegrityError,
    _native,
    active_hook_validation_deadline,
)
from .codex_hook_integrity import manifest_refusal
from .codex_hook_launch_runtime import (
    BoundedHookProcessResult,
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
        environment = dict(self.environment)
        environment["HOL_GUARD_HOOK_FAILURE_KIND"] = _answer(
            _native("launch_failure_kind", deadline_bound=False, failure_kind=failure_kind), "failure_kind", str
        )
        result = run_isolated_hook_process(
            command,
            input_text="",
            cwd=self.cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            deadline_monotonic=self._launch_deadline(timeout_seconds),
            allow_windows_breakaway=True,
        )
        return _succeeded(result)

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
        return result.stdout if _succeeded(result) else None


def _answer(answer: dict[str, object], key: str, kind: type) -> Any:
    identity = answer.get("identity")
    value = identity.get(key) if isinstance(identity, dict) else None
    if not isinstance(value, kind):
        raise CodexHookIntegrityError("codex_hook_integrity_io_error", "Guard could not verify the Codex hook launch.")
    return value


def _succeeded(result: BoundedHookProcessResult) -> bool:
    """The runtime's verdict on a child's result; the child already ran under its own limits."""

    return bool(
        _answer(
            _native(
                "launch_result",
                deadline_bound=False,
                returncode=result.returncode,
                output_limit_exceeded=bool(result.output_limit_exceeded),
                timed_out=bool(result.timed_out),
                containment_failed=bool(result.containment_failed),
            ),
            "succeeded",
            bool,
        )
    )


def _checked(op: str, **fields: Any) -> dict[str, object]:
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

"""Observe fresh decisions from an authenticated, configured Codex hook.

The native ``publication_observe`` op owns the observation: it authenticates the
installed pre-tool launch, runs that exact argv twice (a command the policy
allows and one it denies), checks the hook's output and receipt for each, and
rechecks the signed config and manifest around the launches. This module sends
it the facts only this process knows (the transaction owner it holds, its
environment, the receipt store a legacy package reports to) and seals the
admission it answers.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

from . import codex_hook_command_line as _command_line
from . import codex_hook_runtime_trust
from .codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline
from .codex_hook_integrity import manifest_refusal
from .native_daemon_peer import DaemonArtifactBinding
from .native_owned import _OWNER, _bound
from .native_process_stop_scope import native_process_stop_requested
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import publication
from .runtime_transition import TransitionError
from .runtime_transition_admission import (
    NativeProtectionAdmission,
    _seal_verified_admission,
)

if TYPE_CHECKING:
    from .store import GuardStore

# The call carries the native op's own deadline back to this process.
_CALL_MARGIN_SECONDS = 10.0
_INVALID = "native_transition_invalid"


def _frozen(artifact_binding: DaemonArtifactBinding | None) -> dict[str, object] | None:
    if artifact_binding is None:
        return None
    executable = str(artifact_binding.executable)
    return {
        "executable": executable,
        "artifact": {
            "executable": executable,
            "sha256": artifact_binding.executable_sha256,
            "package_version": artifact_binding.package_version,
        },
    }


def _legacy_store(receipt_store: GuardStore | None) -> dict[str, object] | None:
    if receipt_store is None:
        return None
    return {
        "home": str(receipt_store.guard_home.resolve()),
        "path": str(receipt_store.path),
        "source": receipt_store._guard_source,  # pyright: ignore[reportPrivateUsage]
    }


def observe_configured_codex_hook(
    *,
    operation_id: str,
    artifact_generation: str,
    expected_runtime: NativeRuntimeIdentity,
    guard_home: Path,
    config_path: Path,
    workspace: Path,
    deadline_monotonic: float,
    artifact_binding: DaemonArtifactBinding | None = None,
    receipt_store: GuardStore | None = None,
) -> NativeProtectionAdmission:
    """Require two bounded exact-argv launches and unchanged signed bindings.

    The transition owner must already hold the home-wide publication lock. The
    daemon driver separately verifies its authenticated live identity around
    this observation. The native op checks the original deadline throughout;
    blocking filesystem calls themselves are not yet interruptible.
    """
    try:
        with hook_validation_deadline(deadline_monotonic):
            return _observe(
                operation_id=operation_id,
                artifact_generation=artifact_generation,
                expected_runtime=expected_runtime,
                guard_home=guard_home,
                config_path=config_path,
                workspace=workspace,
                deadline_monotonic=deadline_monotonic,
                artifact_binding=artifact_binding,
                receipt_store=receipt_store,
            )
    except CodexHookIntegrityError as exc:
        if exc.reason == "codex_hook_validation_deadline_expired":
            raise TransitionError("admission_deadline_expired") from exc
        raise


def _observe(
    *,
    operation_id: str,
    artifact_generation: str,
    expected_runtime: NativeRuntimeIdentity,
    guard_home: Path,
    config_path: Path,
    workspace: Path,
    deadline_monotonic: float,
    artifact_binding: DaemonArtifactBinding | None,
    receipt_store: GuardStore | None,
) -> NativeProtectionAdmission:
    if native_process_stop_requested():
        # A launch under a set stop scope was always refused; the native
        # launch no longer sees the event, so refuse before it starts.
        raise TransitionError("admission_hook_launch_failed")
    remaining = max(0.0, deadline_monotonic - time.monotonic())
    request: dict[str, object] = {
        "operation_id": operation_id,
        "artifact_generation": artifact_generation,
        "runtime_sha256": expected_runtime.sha256,
        "owned": _bound(_OWNER.get(), guard_home),
        "workspace": str(workspace.resolve()),
        "environ": dict(os.environ),
        "deadline_ms": int(remaining * 1000),
        "legacy_store": _legacy_store(receipt_store),
        "config": str(config_path),
        "windows": _command_line.hook_commands_use_windows_syntax(),
        "long_paths": {},
        "runtime_path": str(Path(codex_hook_runtime_trust.__file__)),
        "frozen": _frozen(artifact_binding),
    }
    try:
        answer = publication(
            "observe",
            guard_home,
            timeout_seconds=min(remaining, 600.0) + _CALL_MARGIN_SECONDS,
            **request,
        )
    except CodexHookIntegrityError as exc:
        if exc.message == exc.reason and exc.reason != "codex_hook_transaction_owner_missing":
            # The runtime names a manifest refusal by its reason alone.
            raise manifest_refusal(exc.reason) from exc
        raise
    except OSError as exc:
        raise TransitionError("admission_hook_binding_invalid") from exc
    if not isinstance(answer, dict):
        raise TransitionError(_INVALID)
    allow, deny = answer.get("allow"), answer.get("deny")
    generation, policy_digest = answer.get("generation"), answer.get("policy_digest")
    evidence = answer.get("evidence")
    if (
        not isinstance(allow, dict)
        or not isinstance(deny, dict)
        or type(generation) is not int
        or not isinstance(policy_digest, str)
        or not isinstance(evidence, dict)
    ):
        raise TransitionError(_INVALID)
    return _seal_verified_admission(
        NativeProtectionAdmission(
            operation_id,
            artifact_generation,
            expected_runtime,
            generation,
            policy_digest,
            cast("dict[str, object]", allow),
            cast("dict[str, object]", deny),
            guard_home.resolve(),
            time.monotonic(),
            cast("dict[str, object]", evidence),
        )
    )

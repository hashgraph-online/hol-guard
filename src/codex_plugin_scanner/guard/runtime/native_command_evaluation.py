"""Native-backed command diagnostics with explicit unavailability.

This bridge never generates matcher observations in Python. It projects a
request-bound resident response using the authenticated control snapshot that
the caller already holds. It does not initialize or repair control authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..native_command_model import _canonical_command_from_native
from ..native_pretool import review_pre_tool_native
from .command_evaluation import CompositeCommandEvaluation, evaluate_command
from .extension_control_runtime import ExtensionControlRuntimeSnapshot, current_extension_control_snapshot
from .github_workflow_authorization import GitHubWorkflowAuthorization
from .native_command_extension_evidence import NativeCommandExtensionEvidenceError


@dataclass(frozen=True, slots=True, repr=False)
class NativeCommandEvaluation:
    evaluation: CompositeCommandEvaluation
    payload: dict[str, object]
    snapshot: ExtensionControlRuntimeSnapshot

    @property
    def native_minimum_action(self) -> str:
        """Native classification before authenticated host policy proofs."""
        return str(self.payload["minimum_action"])


def review_command_native(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    workflow_authorization: GitHubWorkflowAuthorization | None = None,
) -> NativeCommandEvaluation | None:
    """Return a bound native projection, or None without a usable native result."""
    snapshot = extension_control_snapshot or current_extension_control_snapshot()
    if snapshot is None or snapshot.authority_failure is not None:
        return None
    native = review_pre_tool_native(command, guard_home=guard_home, cwd=cwd, home_dir=home_dir)
    if native is None:
        return None
    model = native.get("command_model")
    if not isinstance(model, dict):
        return None
    canonical = _canonical_command_from_native(command, model)
    if canonical is None:
        return None
    try:
        result = evaluate_command(
            command,
            canonical_command=canonical,
            cwd=cwd,
            home_dir=home_dir,
            compatibility_action_class=compatibility_action_class,
            compatibility_reason=compatibility_reason,
            workflow_authorization=workflow_authorization,
            extension_control_snapshot=snapshot,
            native_extension_evidence=native,
        )
    except NativeCommandExtensionEvidenceError:
        return None
    # Native classification and host policy resolution are distinct stages:
    # an authenticated permission/workflow proof can authorize a review-class
    # command. Preserve the original classification separately and never let
    # such a proof relax a native hard block. Actual execution still requires
    # the authoritative native pre-execution decision and receipt.
    if native.get("minimum_action") == "block" and result.minimum_action != "block":
        return None
    return NativeCommandEvaluation(result, native, snapshot)


def evaluate_command_native(
    command: str,
    *,
    guard_home: Path,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    extension_control_snapshot: ExtensionControlRuntimeSnapshot | None = None,
    compatibility_action_class: str | None = None,
    compatibility_reason: str | None = None,
    workflow_authorization: GitHubWorkflowAuthorization | None = None,
) -> CompositeCommandEvaluation | None:
    reviewed = review_command_native(
        command,
        guard_home=guard_home,
        cwd=cwd,
        home_dir=home_dir,
        extension_control_snapshot=extension_control_snapshot,
        compatibility_action_class=compatibility_action_class,
        compatibility_reason=compatibility_reason,
        workflow_authorization=workflow_authorization,
    )
    return reviewed.evaluation if reviewed is not None else None

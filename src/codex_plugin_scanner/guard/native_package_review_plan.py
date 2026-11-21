"""Transport for the resident's package review planner and settlement.

The resident plans how a package review settles: it reads the command the
hook named (Copilot's ``toolArgs`` included), checks it is one plain JS
package-manager install or exec, parses its intent, proves the npm a plain npm
install runs, and builds the request artifact the package evaluator reads. The
caller forwards the payload and supplies registry and saved-policy evidence
using the existing store and registry clients.

An unavailable or malformed native answer raises
:class:`NativePackageReviewPlanError`. There is no Python fallback, so a
resident that cannot answer leaves the review queued rather than settled.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast

from .hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from .models import GuardArtifact
from .native_context import _canonical_request_sha256, ensure_resident_prerequisite
from .native_hook_render import native_render_cli
from .native_package_authority import (
    _EXTRACT_MAX_REQUEST_BYTES,
    _REQUEST_SCHEMA,
    _RESULT_SCHEMA,
    NativePackageArtifactUnavailableError,
    _artifact_from_wire,
    _request_id,
    _resident_request,
)
from .native_supply_chain_registry_cache import RegistryDeadlineError, registry_wait_deadline

if TYPE_CHECKING:
    from .runtime.package_request_evaluation import PackageRequestEvaluation
    from .store import GuardStore

_LOGGER = logging.getLogger(__name__)
PACKAGE_REVIEW_REASON = "native_package_review"
LAUNCH_REVIEW_REASON = "native_command_review_required"
_PACKAGE_REVIEW_PLAN_FEATURE = "package-review-plan-v1"
_TIMEOUT_SECONDS = 2.0
# The hook payload rides in the request whole, so it takes the bound of the
# other op that carries a whole tool call. A payload the default bound refused
# would leave a blocked package's review approvable.
_MAX_REQUEST_BYTES = _EXTRACT_MAX_REQUEST_BYTES


class NativePackageReviewPlanError(RuntimeError):
    """No authoritative native package review plan was available."""


class PackageReviewPlan(NamedTuple):
    """What the resident planned for one package review."""

    artifact: GuardArtifact | None
    may_allow: bool
    # The directory a leading ``cd`` moved the command into, or the workspace.
    workspace: Path
    # Whether the install's package key stands for the whole command: every
    # program its output is piped through runs from outside the workspace.
    keyed: bool
    registry_retry: dict[str, object] | None = None


def package_review_plan(
    payload: Mapping[str, object],
    *,
    harness: str,
    workspace: Path,
    guard_home: Path,
    review_reason: str,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> PackageReviewPlan:
    """The artifact the evaluator reads, whether its verdict may allow, and where it runs.

    A ``None`` artifact means the command is not one the evaluator reads, which
    is an answer, not a failure: the caller keeps the review queued. ``False``
    means only a block verdict applies. A command that starts with ``cd`` runs
    in the directory the resident resolved, which is always inside
    ``workspace``. ``keyed`` says whether a saved package approval may stand
    for the command.
    """

    request: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": _request_id(),
        "guard_home": str(guard_home),
        "workspace": str(workspace),
        "harness": harness,
        "payload": dict(payload),
        "home_dir": None if home_dir is None else str(home_dir),
        "review_reason": review_reason,
        "include_registry_retry": True,
    }
    try:
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
    except (TypeError, ValueError) as error:
        raise NativePackageReviewPlanError("Native package review plan request invalid") from error
    if not ensure_resident_prerequisite(guard_home):
        raise NativePackageReviewPlanError("Native package review plan unavailable")
    response = _resident_request(
        operation="package_review_plan",
        request=request,
        guard_home=guard_home,
        timeout_seconds=_TIMEOUT_SECONDS,
        deadline_monotonic=deadline,
        required_features=(_PACKAGE_REVIEW_PLAN_FEATURE,),
        max_request_bytes=_MAX_REQUEST_BYTES,
    )
    if (
        not isinstance(response, dict)
        or response.get("schema") != _RESULT_SCHEMA
        or response.get("request_id") != request["request_id"]
        or response.get("request_sha256") != request_sha256
        or response.get("status") != "ok"
        or response.get("code") != "ok"
    ):
        raise NativePackageReviewPlanError("Native package review plan unavailable or invalid")
    answer = response.get("payload")
    fields = {"artifact", "may_allow", "workspace", "keyed"}
    if not isinstance(answer, dict) or set(answer) not in (fields, fields | {"registry_retry"}):
        raise NativePackageReviewPlanError("Native package review plan invalid")
    may_allow = answer["may_allow"]
    moved = answer["workspace"]
    keyed = answer["keyed"]
    registry_retry = answer.get("registry_retry")
    if (
        not isinstance(may_allow, bool)
        or not isinstance(keyed, bool)
        or (may_allow and not isinstance(registry_retry, dict))
        or (not may_allow and "registry_retry" in answer)
        or (answer["artifact"] is None and (may_allow or keyed or moved is not None))
        or (moved is not None and (not isinstance(moved, str) or not Path(moved).is_absolute()))
    ):
        raise NativePackageReviewPlanError("Native package review plan invalid")
    if answer["artifact"] is None:
        return PackageReviewPlan(None, False, workspace, False)
    try:
        artifact = _artifact_from_wire(answer["artifact"])
    except NativePackageArtifactUnavailableError as error:
        raise NativePackageReviewPlanError("Native package review plan invalid") from error
    return PackageReviewPlan(artifact, may_allow, workspace if moved is None else Path(moved), keyed, registry_retry)


class PackageReviewOutcome(NamedTuple):
    """A rendered response or the package key for a review that stays queued."""

    response: dict[str, object] | None
    package_approval: dict[str, str] | None = None


_UNSETTLED = PackageReviewOutcome(None)


def native_package_review_response(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> PackageReviewOutcome:
    """Send the evaluated package review to the resident for settlement."""

    review_reason = native_result.get("reason_code")
    if (
        workspace is None
        or review_reason not in (PACKAGE_REVIEW_REASON, LAUNCH_REVIEW_REASON)
        or native_result.get("minimum_action") != "review"
    ):
        return _UNSETTLED
    try:
        plan = package_review_plan(
            payload,
            harness=harness,
            workspace=workspace,
            guard_home=guard_home,
            review_reason=str(review_reason),
            home_dir=home_dir,
            deadline=deadline,
        )
    except NativePackageReviewPlanError:
        _LOGGER.warning("Native package review plan unavailable", exc_info=True)
        return _UNSETTLED
    artifact = plan.artifact
    if artifact is None:
        return _UNSETTLED
    try:
        with registry_wait_deadline(deadline):
            evaluation = _evaluate(store, artifact=artifact, workspace=plan.workspace)
    except RegistryDeadlineError:
        # The registry fetch continues. The plan carries the response to use
        # here because the deadline has already expired.
        return PackageReviewOutcome(plan.registry_retry)
    except Exception:
        _LOGGER.warning("Package evaluation failed for a native package review", exc_info=True)
        return _UNSETTLED

    action, reason = evaluation.review_settlement
    request: dict[str, object] = {
        "verdict": dict(native_result),
        "settlement": {"action": action, "reason": reason},
        "may_allow": plan.may_allow,
        "keyed": plan.keyed,
        "execution_environment": payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY),
        "package": {
            "harness": artifact.harness,
            "artifact_id": artifact.artifact_id,
            "command": artifact.metadata.get("redacted_command"),
        },
    }
    fallback_approval: dict[str, str] | None = None
    settled = _settle(harness, request, guard_home, deadline)
    if settled is not None and isinstance(lookup := settled.get("lookup"), dict):
        argv = lookup.get("argv")
        environment = lookup.get("environment")
        if (
            isinstance(argv, list)
            and argv
            and all(isinstance(token, str) for token in argv)
            and isinstance(environment, dict)
            and all(isinstance(name, str) and isinstance(value, str) for name, value in environment.items())
        ):
            reuse = _package_reuse_evidence(store, artifact, evaluation, plan.workspace, argv, environment)
            request["reuse"] = reuse
            if reuse is not None and isinstance(artifact_hash := reuse.get("artifact_hash"), str):
                # The resident requested this key and the package authority
                # supplied its hash. Keep it if the reply to the lookup is lost.
                fallback_approval = {
                    "harness": artifact.harness,
                    "artifact_id": artifact.artifact_id,
                    "artifact_hash": artifact_hash,
                }
            settled = _settle(harness, request, guard_home, deadline)
    if settled is not None and settled.get("lookup") is None:
        response = settled.get("response")
        approval = settled.get("package_approval")
        if (response is None or isinstance(response, dict)) and (
            approval is None
            or (
                isinstance(approval, dict)
                and set(approval) == {"harness", "artifact_id", "artifact_hash"}
                and all(isinstance(value, str) for value in approval.values())
            )
        ):
            return PackageReviewOutcome(response, approval)

    # Keep the original review queued when settlement is unavailable.
    # An explicit evaluator block must still stop without a review card.
    if action != "block":
        return PackageReviewOutcome(None, fallback_approval)

    from .hook_review.hook_fail_closed import fail_closed_pre_tool

    response = (
        fail_closed_pre_tool(harness, reason=reason, reason_code=str(review_reason))
        if reason
        else fail_closed_pre_tool(harness)
    )
    response["prompted"] = False
    return PackageReviewOutcome(response)


def _settle(
    harness: str, request: dict[str, object], guard_home: Path, deadline: float | None
) -> dict[str, object] | None:
    reply = native_render_cli("package_review_settle", harness, request, guard_home=guard_home, deadline=deadline)
    if reply is None or reply[0] != "document":
        return None
    answer = reply[1]
    if answer is None or set(answer) != {"response", "package_approval", "lookup"}:
        return None
    return answer


def _evaluate(store: object, *, artifact: GuardArtifact, workspace: Path) -> PackageRequestEvaluation:
    from .local_supply_chain import evaluate_package_request_artifact

    return evaluate_package_request_artifact(
        artifact=artifact, store=cast("GuardStore", store), workspace_dir=workspace
    )


def _package_reuse_evidence(
    store: object,
    artifact: GuardArtifact,
    evaluation: PackageRequestEvaluation,
    install_dir: Path,
    argv: list[str],
    environment: Mapping[str, str],
) -> dict[str, object] | None:
    """Look up the saved policy through the package firewall's existing transport."""

    from .local_supply_chain import _resolve_stored_package_policy_override, package_current_action_and_hash
    from .package_execution_context import build_package_execution_context

    try:
        execution_context = build_package_execution_context(
            workspace_dir=install_dir,
            artifact=artifact,
            executable=argv[0],
            executable_args=argv[1:],
            environment=environment,
        )
        _action, artifact_hash = package_current_action_and_hash(
            artifact,
            workspace_dir=install_dir,
            store=store,
            evaluation=evaluation,
            execution_context=execution_context,
        )
        resolution = _resolve_stored_package_policy_override(
            evaluation,
            store=store,
            artifact=artifact,
            artifact_hash=artifact_hash,
            workspace_dir=install_dir,
            now=datetime.now(tz=timezone.utc).isoformat(),
            execution_context=execution_context,
            current_action="review",
        )
    except Exception:
        _LOGGER.warning("Package approval key unavailable for a native package review", exc_info=True)
        return None
    return {
        "artifact_hash": artifact_hash,
        "found": resolution.approval_reuse_decision is not None,
        "policy_action": getattr(resolution.evaluation, "policy_action", None),
    }

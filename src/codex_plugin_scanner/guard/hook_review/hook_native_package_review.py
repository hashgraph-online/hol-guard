"""Settle a JS package review from the package evaluator's verdict.

The native edge sends every package install and exec to review because it
cannot see what the command will fetch. The package evaluator can, so before
the review is queued the resident plans it (``package_review_plan``): it reads
the command, builds the request artifact the evaluator reads, and says whether
the verdict may let the command continue. This module evaluates that artifact
and applies the verdict.

The resident also says how the verdict settles the review. A block always
applies: stopping a command runs nothing. Every other settlement applies only
to an npm install whose npm the resident proved: it continues on an allow, or
on a watch that holds only because no package code runs, and stops with the
evaluator's guidance when only lifecycle scripts kept it in review.

An install is also keyed the way the package firewall keys a package request:
by the repository, dependency graph and launch, not the checkout path or the
command text. When every program the output is piped through runs from
outside the workspace, a saved package Always allow under that key lets the
install continue, and a review that stays queued carries the key, so an Always allow on
it is saved under the key as well. The identical install in a linked worktree
of the same repository then reuses it; one that runs lifecycle scripts has
another key.
"""

from __future__ import annotations

import logging
import shlex
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, cast

from ..native_package_review_plan import NativePackageReviewPlanError, package_review_plan
from ..native_supply_chain_registry_cache import RegistryDeadlineError, registry_wait_deadline
from .hook_fail_closed import render_pre_tool

if TYPE_CHECKING:
    from ..models import GuardArtifact
    from ..runtime.package_request_evaluation import PackageRequestEvaluation
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

PACKAGE_REVIEW_REASON = "native_package_review"
# The edge reviews an `npx` or `bunx` launch as a command; the resident plans
# it for a block verdict only.
LAUNCH_REVIEW_REASON = "native_command_review_required"
REGISTRY_STILL_LOADING_REASON = (
    "HOL Guard is still fetching registry metadata for this install. Run the same command again."
)


class PackageReviewOutcome(NamedTuple):
    """How a package review settled, and the package key a queued one carries."""

    # The settled hook response, or ``None`` to keep reviewing.
    response: dict[str, object] | None
    # ``{"harness", "artifact_id", "artifact_hash"}`` for a review left queued.
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
    """The settled response for a package review, or the key a queued review carries."""

    if (
        workspace is None
        or native_result.get("reason_code") not in {PACKAGE_REVIEW_REASON, LAUNCH_REVIEW_REASON}
        or native_result.get("minimum_action") != "review"
    ):
        return _UNSETTLED
    try:
        artifact, may_allow, install_dir, keyed = package_review_plan(
            payload,
            harness=harness,
            workspace=workspace,
            guard_home=guard_home,
            review_reason=str(native_result["reason_code"]),
            home_dir=home_dir,
            deadline=deadline,
        )
    except NativePackageReviewPlanError:
        # Nothing was planned, so the native review stands.
        _LOGGER.warning("Native package review plan unavailable", exc_info=True)
        return _UNSETTLED
    if artifact is None:
        return _UNSETTLED
    try:
        with registry_wait_deadline(deadline):
            evaluation = _evaluate(store, artifact=artifact, workspace=install_dir)
    except RegistryDeadlineError:
        # The download continues in the background and the next attempt reads
        # it from the cache. Nothing ran, so stopping quietly costs one retry;
        # a review that could only ever block stays queued instead.
        if not may_allow:
            return _UNSETTLED
        return PackageReviewOutcome(
            _blocked(native_result, REGISTRY_STILL_LOADING_REASON, harness, guard_home, deadline)
        )
    except Exception:
        _LOGGER.warning("Package evaluation failed for a native package review", exc_info=True)
        return _UNSETTLED
    action, reason = evaluation.review_settlement
    if action == "block" and reason:
        return PackageReviewOutcome(_blocked(native_result, reason, harness, guard_home, deadline))
    package_approval: dict[str, str] | None = None
    # A key stands for the command only when nothing it pipes into could be a
    # program the workspace planted.
    if keyed and native_result.get("reason_code") == PACKAGE_REVIEW_REASON:
        package_approval, reused = _saved_package_approval(
            store,
            artifact=artifact,
            evaluation=evaluation,
            install_dir=install_dir,
            environment=_stamped_environment(payload),
        )
        if reused:
            allowed = dict(native_result)
            allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
            return PackageReviewOutcome(render_pre_tool(harness, allowed, guard_home=guard_home, deadline=deadline))
    if not may_allow:
        return PackageReviewOutcome(None, package_approval)
    if action == "allow":
        allowed = dict(native_result)
        allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
        # The evaluator settled this; no saved approval was reused.
        return PackageReviewOutcome(render_pre_tool(harness, allowed, guard_home=guard_home, deadline=deadline))
    if action == "guide" and reason:
        return PackageReviewOutcome(_blocked(native_result, reason, harness, guard_home, deadline))
    return PackageReviewOutcome(None, package_approval)


def _stamped_environment(payload: Mapping[str, object]) -> dict[str, str]:
    """The ``PATH`` and ``HOME`` the hook stamped, which locate the npm the install runs.

    The resident keys an install only when no other exported variable can
    change what npm runs, so these two are the whole environment the key needs.
    """

    from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY

    stamp = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    if not isinstance(stamp, Mapping):
        return {}
    return {
        name: value
        for name, value in (("PATH", stamp.get("path")), ("HOME", stamp.get("home")))
        if isinstance(value, str) and value
    }


def _saved_package_approval(
    store: object,
    *,
    artifact: GuardArtifact,
    evaluation: PackageRequestEvaluation,
    install_dir: Path,
    environment: Mapping[str, str],
) -> tuple[dict[str, str] | None, bool]:
    """The install's package key, and whether a saved package Always allow covers it.

    The key is derived as the package firewall derives a package request's key,
    for this harness's request, with the npm the agent's ``PATH`` resolves. An
    install whose key cannot be derived is reviewed by its exact command alone.
    """

    from ..local_supply_chain import _resolve_stored_package_policy_override, package_current_action_and_hash
    from ..package_execution_context import build_package_execution_context

    try:
        redacted = artifact.metadata.get("redacted_command")
        tokens = shlex.split(redacted) if isinstance(redacted, str) else []
        if not tokens:
            return None, False
        execution_context = build_package_execution_context(
            workspace_dir=install_dir,
            artifact=artifact,
            executable=tokens[0],
            executable_args=tokens[1:],
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
            # The hook route reviews the install whatever the evaluator rates
            # it, so a saved Always allow is reused the way it is for a review.
            current_action="review",
        )
    except Exception:
        _LOGGER.warning("Package approval key unavailable for a native package review", exc_info=True)
        return None, False
    key = {"harness": artifact.harness, "artifact_id": artifact.artifact_id, "artifact_hash": artifact_hash}
    reused = (
        resolution.approval_reuse_decision is not None
        and getattr(resolution.evaluation, "policy_action", None) == "allow"
    )
    return key, reused


def _blocked(
    native_result: Mapping[str, object], reason: str, harness: str, guard_home: Path, deadline: float | None
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(decision="deny", minimum_action="block", policy_action="block", reason=reason)
    response = render_pre_tool(harness, blocked, guard_home=guard_home, deadline=deadline)
    response["prompted"] = False
    return response


def _evaluate(store: object, *, artifact: GuardArtifact, workspace: Path) -> PackageRequestEvaluation:
    from ..local_supply_chain import evaluate_package_request_artifact

    return evaluate_package_request_artifact(
        artifact=artifact, store=cast("GuardStore", store), workspace_dir=workspace
    )

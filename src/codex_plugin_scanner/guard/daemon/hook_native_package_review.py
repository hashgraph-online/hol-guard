"""Settle a JS package review from the package evaluator's verdict.

The native edge sends every package install and exec to review because it
cannot see what the command will fetch. The package evaluator can, so before
the review is queued the resident plans it (``package_review_plan``): it reads
the command, builds the request artifact the evaluator reads, and says whether
the verdict may let the command continue. This module evaluates that artifact
and applies the verdict.

A block verdict always applies: stopping a command runs nothing. Only an npm
install whose npm the resident proved continues on an allow, or on a watch
that holds only because no package code runs. An npm 11.9+ install with
``--ignore-scripts --allow-git=none``, or an older npm install with
``--ignore-scripts`` whose dependency tree registry metadata proves free of git
dependencies, only writes registry package files.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, cast

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
LIFECYCLE_SCRIPTS_ENABLED_CODE = "package_lifecycle_scripts_enabled"
REGISTRY_STILL_LOADING_REASON = (
    "HOL Guard is still fetching registry metadata for this install. Run the same command again."
)


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
) -> dict[str, object] | None:
    """The settled response for a package review, or ``None`` to keep reviewing."""

    if (
        workspace is None
        or native_result.get("reason_code") not in {PACKAGE_REVIEW_REASON, LAUNCH_REVIEW_REASON}
        or native_result.get("minimum_action") != "review"
    ):
        return None
    try:
        artifact, may_allow = package_review_plan(
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
        return None
    if artifact is None:
        return None
    try:
        with registry_wait_deadline(deadline):
            evaluation = _evaluate(store, artifact=artifact, workspace=workspace)
    except RegistryDeadlineError:
        # The download continues in the background and the next attempt reads
        # it from the cache. Nothing ran, so stopping quietly costs one retry;
        # a review that could only ever block stays queued instead.
        if not may_allow:
            return None
        return _blocked(native_result, REGISTRY_STILL_LOADING_REASON, harness, guard_home, deadline)
    except Exception:
        _LOGGER.warning("Package evaluation failed for a native package review", exc_info=True)
        return None
    if evaluation.decision == "block":
        reason = _first_message(evaluation.reasons) or "HOL Guard blocked this package install."
        return _blocked(native_result, reason, harness, guard_home, deadline)
    if not may_allow:
        return None
    if evaluation.decision == "allow" or _script_free_watch(evaluation):
        allowed = dict(native_result)
        allowed.update(decision="allow", minimum_action="allow", policy_action="allow")
        # The evaluator settled this; no saved approval was reused.
        return render_pre_tool(harness, allowed, guard_home=guard_home, deadline=deadline)
    guidance = next(
        (
            str(reason.get("message"))
            for reason in evaluation.reasons
            if reason.get("code") == LIFECYCLE_SCRIPTS_ENABLED_CODE and reason.get("message")
        ),
        None,
    )
    if evaluation.decision == "ask" and guidance is not None:
        return _blocked(native_result, guidance, harness, guard_home, deadline)
    return None


def _blocked(
    native_result: Mapping[str, object], reason: str, harness: str, guard_home: Path, deadline: float | None
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(decision="deny", minimum_action="block", policy_action="block", reason=reason)
    response = render_pre_tool(harness, blocked, guard_home=guard_home, deadline=deadline)
    response["prompted"] = False
    return response


def _script_free_watch(evaluation: PackageRequestEvaluation) -> bool:
    """Whether every package is watched only because no package code runs."""
    return (
        evaluation.decision == "monitor"
        and bool(evaluation.packages)
        and all(package.get("scriptFreeRegistryInstall") is True for package in evaluation.packages)
    )


def _evaluate(store: object, *, artifact: GuardArtifact, workspace: Path) -> PackageRequestEvaluation:
    from ..local_supply_chain import evaluate_package_request_artifact

    return evaluate_package_request_artifact(
        artifact=artifact, store=cast("GuardStore", store), workspace_dir=workspace
    )


def _first_message(reasons: tuple[dict[str, object], ...]) -> str | None:
    return next((str(reason["message"]) for reason in reasons if reason.get("message")), None)

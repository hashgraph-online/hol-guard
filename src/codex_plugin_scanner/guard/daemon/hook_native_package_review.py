"""Let a script-free npm registry install continue without review.

The native edge sends every package install to review because it cannot see
what the install will run. The package evaluator can: an npm 11.9+ install
with ``--ignore-scripts --allow-git=none``, or an older npm install with
``--ignore-scripts`` whose dependency tree registry metadata proves free of git
dependencies, only writes registry package files, and a target that resolves
on the public registry is identified well enough to continue. The resident
proves which npm the agent will run; this module hands the request to the
evaluator and settles the review from its verdict.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from ..native_supply_chain_registry_cache import RegistryDeadlineError, registry_wait_deadline
from ..native_verified_npm import NativeVerifiedNpmError, verified_npm_proof
from .hook_fail_closed import render_pre_tool
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..runtime.package_request_evaluation import PackageRequestEvaluation
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)

PACKAGE_REVIEW_REASON = "native_package_review"
LIFECYCLE_SCRIPTS_ENABLED_CODE = "package_lifecycle_scripts_enabled"
VERIFIED_NPM_VERSION_KEY = "verified_npm_version"
REGISTRY_STILL_LOADING_REASON = (
    "HOL Guard is still fetching registry metadata for this install. Run the same command again."
)

# One plain command: no expansion, quoting, globbing, redirection or chaining.
# A word may not start with `~` or `=`, which shells expand to paths.
_WORD = r"[A-Za-z0-9@/._^:+,-][A-Za-z0-9@/._~^:=+,-]*"
_SIMPLE_COMMAND = re.compile(rf"{_WORD}(?: +{_WORD})*")
# Agents trim install output with `2>&1 | tail -3`. These filters read only
# the pipe: none takes a file operand, and a grep pattern may not start with
# `-`, so it cannot name a pattern file.
_PATTERN = r"[A-Za-z0-9@/._^:+,][A-Za-z0-9@/._~^:=+,-]*"
_OUTPUT_FILTER = rf"(?:tail|head)(?: +-[0-9]+| +-n *[0-9]+)?|grep(?: +-[iEFvcnw]+)* +{_PATTERN}"
_FILTERED_COMMAND = re.compile(
    rf"(?P<command>{_SIMPLE_COMMAND.pattern})(?: +2>&1)?(?P<filters>(?: *\| *(?:{_OUTPUT_FILTER}))*)"
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
        os.name == "nt"
        or workspace is None
        or native_result.get("reason_code") != PACKAGE_REVIEW_REASON
        or native_result.get("minimum_action") != "review"
    ):
        return None
    command = pre_tool_command(payload)
    shape = _FILTERED_COMMAND.fullmatch(command.strip()) if command else None
    if shape is None:
        return None
    tokens = shape.group("command").split()
    if tokens[0] != "npm":
        return None
    environment = payload.get(HOOK_EXECUTION_ENVIRONMENT_KEY)
    try:
        version, filters_outside = npm_install_proof(
            environment,
            workspace=workspace,
            guard_home=guard_home,
            filters=shape.group("filters"),
            deadline=deadline,
        )
    except NativeVerifiedNpmError:
        # Nothing was proven, so the native review stands.
        _LOGGER.warning("Native npm proof unavailable for a package review", exc_info=True)
        return None
    if version is None or not filters_outside:
        return None
    try:
        with registry_wait_deadline(deadline):
            evaluation = _evaluate(
                store,
                harness=harness,
                tokens=tokens,
                version=version,
                workspace=workspace,
                guard_home=guard_home,
                home_dir=home_dir,
                deadline=deadline,
            )
    except RegistryDeadlineError:
        # The download continues in the background and the next attempt reads
        # it from the cache. Nothing ran, so stopping quietly costs one retry.
        return _blocked(native_result, REGISTRY_STILL_LOADING_REASON, harness, guard_home, deadline)
    except Exception:
        _LOGGER.warning("Package evaluation failed for a native package review", exc_info=True)
        return None
    if evaluation is None:
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
    if evaluation.decision == "block":
        reason = _first_message(evaluation.reasons) or "HOL Guard blocked this package install."
    elif evaluation.decision == "ask" and guidance is not None:
        reason = guidance
    else:
        return None
    return _blocked(native_result, reason, harness, guard_home, deadline)


def _blocked(
    native_result: Mapping[str, object], reason: str, harness: str, guard_home: Path, deadline: float | None
) -> dict[str, object]:
    blocked = dict(native_result)
    blocked.update(decision="deny", minimum_action="block", policy_action="block", reason=reason)
    response = render_pre_tool(harness, blocked, guard_home=guard_home, deadline=deadline)
    response["prompted"] = False
    return response


def _filter_programs(filters: str) -> list[str]:
    """The programs an install pipes its output through, in first-seen order."""

    programs: list[str] = []
    for segment in filters.split("|"):
        words = segment.split()
        if words and words[0] not in programs:
            programs.append(words[0])
    return programs


def npm_install_proof(
    environment: object,
    *,
    workspace: Path,
    guard_home: Path,
    filters: str,
    deadline: float | None,
) -> tuple[str | None, bool]:
    """The resident's npm proof for this install, applied without re-deriving it."""

    return verified_npm_proof(
        environment,
        workspace=workspace,
        guard_home=guard_home,
        filter_programs=_filter_programs(filters),
        deadline=deadline,
    )


def _script_free_watch(evaluation: PackageRequestEvaluation) -> bool:
    """Whether every package is watched only because no package code runs."""
    return (
        evaluation.decision == "monitor"
        and bool(evaluation.packages)
        and all(package.get("scriptFreeRegistryInstall") is True for package in evaluation.packages)
    )


def _evaluate(
    store: object,
    *,
    harness: str,
    tokens: list[str],
    version: str,
    workspace: Path,
    guard_home: Path,
    home_dir: Path | None,
    deadline: float | None,
) -> PackageRequestEvaluation | None:
    from ..local_supply_chain import evaluate_package_request_artifact
    from ..runtime.package_intent_common import build_package_request_artifact
    from ..runtime.package_intent_parser import parse_package_intent

    intent = parse_package_intent(
        shlex.join(tokens),
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        deadline=deadline,
    )
    # The evaluator reads the redacted command, so it must be the command
    # that runs, token for token.
    if (
        intent is None
        or intent.package_manager != "npm"
        or intent.intent_kind != "install"
        or intent.local_executions
        or list(intent.command_tokens) != tokens
        or shlex.split(intent.redacted_command) != tokens
    ):
        return None
    artifact = build_package_request_artifact(
        harness,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
        guard_home=guard_home,
        deadline_monotonic=deadline,
    )
    artifact = replace(artifact, metadata={**artifact.metadata, VERIFIED_NPM_VERSION_KEY: version})
    return evaluate_package_request_artifact(
        artifact=artifact, store=cast("GuardStore", store), workspace_dir=workspace
    )


def _first_message(reasons: tuple[dict[str, object], ...]) -> str | None:
    return next((str(reason["message"]) for reason in reasons if reason.get("message")), None)

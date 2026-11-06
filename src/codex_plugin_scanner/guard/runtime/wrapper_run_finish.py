"""Final authority check and launch for Guard wrapper-mode runs."""

from __future__ import annotations

import subprocess
from typing import Any

from ..adapters.base import HarnessContext
from ..models import HarnessDetection
from ..store import GuardStore
from . import runner_native_authority as _authority
from .decisions import AUTHORITATIVE_DECISION_INCONSISTENT
from .guard_run_evaluation import _guard_run_config_paths
from .guard_run_launch import (
    _HERMES_GUARD_TOKEN_ENV_KEY,
    _guard_run_finalize_authorized_launch_plan,
    _guard_run_launch_previews,
    _GuardRunLaunchPlan,
    _resolve_hermes_guard_access_token,
)


def finish_guard_run(
    evaluation: dict[str, Any],
    *,
    detection: HarnessDetection,
    harness: str,
    context: HarnessContext,
    store: GuardStore,
    passthrough_args: list[str],
    dry_run: bool,
    launch_plan: _GuardRunLaunchPlan | None,
) -> dict[str, Any]:
    """Refuse contradictory decisions, then launch only an authorized, path-pinned command."""

    if "config_paths" not in evaluation:
        evaluation["config_paths"] = list(detection.config_paths) or _guard_run_config_paths(
            detection=detection,
            context=context,
            passthrough_args=passthrough_args,
        )
    authority_error = _authority.authority_error(
        evaluation,
        require_launch_permitted=not dry_run and evaluation.get("blocked") is False,
    )
    if authority_error is not None:
        evaluation["blocked"] = True
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        evaluation["authority_error"] = AUTHORITATIVE_DECISION_INCONSISTENT
        evaluation["authority_error_message"] = (
            "Guard detected contradictory decision fields and refused to launch. "
            "Re-run the Guard scan or repair the local Guard installation before retrying."
        )
        return evaluation
    if evaluation["blocked"] or dry_run:
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        return evaluation

    if launch_plan is None:
        try:
            launch_previews = _guard_run_launch_previews(harness, context, passthrough_args)
            launch_plan = (
                _guard_run_finalize_authorized_launch_plan(
                    harness,
                    context,
                    passthrough_args,
                    launch_previews,
                )
                if launch_previews and all(plan.reusable for plan in launch_previews)
                else None
            )
        except Exception as error:
            evaluation["launched"] = False
            evaluation["launch_command"] = []
            evaluation["return_code"] = 127
            evaluation["launch_error"] = str(error)
            return evaluation
    if launch_plan is None or not launch_plan.reusable:
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        evaluation["return_code"] = 127
        evaluation["launch_error"] = "Guard could not resolve a stable, path-pinned harness launch command."
        return evaluation
    command = list(launch_plan.execution_command)
    evaluation["launch_command"] = command
    environment = dict(launch_plan.environment)
    if harness == "hermes":
        _hermes_token = _resolve_hermes_guard_access_token(store)
        if _hermes_token is not None:
            # This is the sole intentional environment addition after the
            # prepared environment was authority-hashed. It is a short-lived
            # Guard credential resolved only at the execution boundary, not
            # user-controlled launch configuration. It must NOT leak to
            # user-configured MCP subprocesses; the proxy layer scrubs it
            # before launch (see proxy._build_scrubbed_env).
            environment[_HERMES_GUARD_TOKEN_ENV_KEY] = _hermes_token
    try:
        result = subprocess.run(command, cwd=launch_plan.launch_cwd, check=False, env=environment)
    except FileNotFoundError as error:
        evaluation["launched"] = False
        evaluation["return_code"] = 127
        evaluation["launch_error"] = str(error)
        return evaluation
    evaluation["launched"] = True
    evaluation["return_code"] = result.returncode
    return evaluation

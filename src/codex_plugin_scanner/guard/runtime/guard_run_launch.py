"""Launch-plan binding for Guard wrapper-mode runs."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..adapters.base import HarnessAdapter, HarnessContext
from ..store import GuardStore
from .local_runtime_fallbacks import best_effort_access_token


def get_adapter(harness: str) -> HarnessAdapter:
    from ..adapters import get_adapter as _get_adapter

    return _get_adapter(harness)


# Every prepared launch-environment entry is authority-hashed except this
# explicit execution-boundary credential. Inherited values are removed before
# hashing; only Guard's freshly resolved Hermes credential may be added later.
_HERMES_GUARD_TOKEN_ENV_KEY = "HERMES_GUARD_TOKEN"
_GUARD_RUN_LATE_CREDENTIAL_ENV_KEYS = frozenset({_HERMES_GUARD_TOKEN_ENV_KEY})


@dataclass(frozen=True, slots=True)
class _GuardRunLaunchPlan:
    """The exact adapter launch vector resolved at an authority boundary."""

    adapter_command: tuple[str, ...]
    execution_command: tuple[str, ...]
    environment: Mapping[str, str]
    environment_sha256: str
    identity: Mapping[str, object]
    launch_cwd: Path
    reusable: bool


def _guard_run_launch_environment(
    adapter: HarnessAdapter,
    context: HarnessContext,
) -> tuple[dict[str, str], Path]:
    environment = os.environ.copy()
    environment["HOME"] = str(context.home_dir)
    if os.name == "nt":
        environment["USERPROFILE"] = str(context.home_dir)
    environment = adapter.prepare_launch_environment(context, environment)
    for credential_key in _GUARD_RUN_LATE_CREDENTIAL_ENV_KEYS:
        environment.pop(credential_key, None)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items()):
        raise ValueError("Harness launch environment must contain only string keys and values.")
    launch_cwd = (context.workspace_dir or Path.cwd()).expanduser().resolve(strict=True)
    if not launch_cwd.is_dir():
        raise NotADirectoryError(f"Harness launch cwd is not a directory: {launch_cwd}")
    return dict(environment), launch_cwd


def _guard_run_plan_from_native(
    plan: Mapping[str, object],
    *,
    environment: Mapping[str, str],
) -> _GuardRunLaunchPlan:
    """Project one native launch plan into the DTO guard-run already consumes."""

    identity = plan["identity"]
    if not isinstance(identity, Mapping):
        raise ValueError("Native guard-run launch plan must carry a launch identity.")
    return _GuardRunLaunchPlan(
        adapter_command=tuple(cast("Sequence[str]", plan["adapter_command"])),
        execution_command=tuple(cast("Sequence[str]", plan["execution_command"])),
        environment=dict(environment),
        environment_sha256=str(plan["environment_sha256"]),
        identity=dict(identity),
        launch_cwd=Path(str(plan["launch_cwd"])),
        reusable=bool(plan["reusable"]),
    )


def _guard_run_launch_previews(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
) -> tuple[_GuardRunLaunchPlan, ...]:
    """Content-bind every launch argv without performing adapter setup."""

    from ..native_context import bound_context_digest_home, context_guard_run_launch_plans

    with bound_context_digest_home(context.guard_home):
        adapter = get_adapter(harness)
        raw_commands: Sequence[Sequence[str]] = adapter.preview_launch_commands(context, passthrough_args)
        environment, launch_cwd = _guard_run_launch_environment(adapter, context)
        native_plans = context_guard_run_launch_plans(
            [list(raw_command) for raw_command in raw_commands],
            environment=environment,
            launch_cwd=launch_cwd,
        )
        return tuple(_guard_run_plan_from_native(plan, environment=environment) for plan in native_plans)


def _guard_run_finalize_authorized_launch_plan(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
    authorized_plans: Sequence[_GuardRunLaunchPlan],
) -> _GuardRunLaunchPlan | None:
    """Run authorized setup without re-resolving previewed launch identity."""

    from ..native_context import bound_context_digest_home, context_guard_run_authorized_prefixes

    if not authorized_plans:
        return None
    environment = authorized_plans[0].environment
    if any(dict(plan.environment) != dict(environment) for plan in authorized_plans[1:]):
        return None
    with bound_context_digest_home(context.guard_home):
        prefixes = context_guard_run_authorized_prefixes(
            [
                {
                    "adapter_command": plan.adapter_command,
                    "execution_command": plan.execution_command,
                    "environment_sha256": plan.environment_sha256,
                    "reusable": plan.reusable,
                }
                for plan in authorized_plans
            ]
        )
    if prefixes is None:
        return None
    adapter = get_adapter(harness)
    actual_command = adapter.launch_command_from_authorized_plan(
        context,
        passthrough_args,
        authorized_executable_prefixes=prefixes,
        launch_environment=dict(environment),
    )
    normalized_actual = tuple(actual_command)
    for plan in authorized_plans:
        if normalized_actual in {plan.adapter_command, plan.execution_command}:
            return plan
    return None


def _resolve_hermes_guard_access_token(store: GuardStore) -> str | None:
    from .runner import _resolve_guard_sync_auth_context

    return best_effort_access_token(lambda: _resolve_guard_sync_auth_context(store))

"""Launch-plan binding for Guard wrapper-mode runs."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ..adapters.base import HarnessAdapter, HarnessContext
from ..store import GuardStore
from .approval_context import (
    build_runtime_launch_identity,
    resolved_runtime_launch_argv,
    runtime_launch_identity_is_reusable,
)
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


def _guard_run_launch_environment_hash(environment: Mapping[str, str]) -> str:
    """Return a canonical, non-reversible digest of the full prepared environment."""

    material = json.dumps(
        sorted(environment.items()),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(b"hol.guard.guard-run-launch-environment:v1\x00" + material).hexdigest()


def _guard_run_plan_for_command(
    adapter_command: Sequence[str],
    *,
    environment: Mapping[str, str],
    launch_cwd: Path,
) -> _GuardRunLaunchPlan | None:
    normalized_command = tuple(adapter_command)
    if not normalized_command or any(not isinstance(part, str) or not part for part in normalized_command):
        return None
    identity = build_runtime_launch_identity(
        normalized_command[0],
        args=normalized_command[1:],
        structured_command=True,
        direct_executable=True,
        search_path=environment.get("PATH"),
        cwd=launch_cwd,
        launch_env=environment,
    )
    pinned_command = resolved_runtime_launch_argv(identity, args=normalized_command[1:])
    reusable = pinned_command is not None and runtime_launch_identity_is_reusable(identity)
    return _GuardRunLaunchPlan(
        adapter_command=normalized_command,
        execution_command=pinned_command if reusable and pinned_command is not None else normalized_command,
        environment=dict(environment),
        environment_sha256=_guard_run_launch_environment_hash(environment),
        identity=identity,
        launch_cwd=launch_cwd,
        reusable=reusable,
    )


def _guard_run_launch_previews(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
) -> tuple[_GuardRunLaunchPlan, ...]:
    """Content-bind every launch argv without performing adapter setup."""

    from ..native_context import bound_context_digest_home

    with bound_context_digest_home(context.guard_home):
        adapter = get_adapter(harness)
        raw_commands: Sequence[Sequence[str]] = adapter.preview_launch_commands(context, passthrough_args)
        environment, launch_cwd = _guard_run_launch_environment(adapter, context)
        plans: list[_GuardRunLaunchPlan] = []
        seen_commands: set[tuple[str, ...]] = set()
        for raw_command in raw_commands:
            plan = _guard_run_plan_for_command(
                raw_command,
                environment=environment,
                launch_cwd=launch_cwd,
            )
            if plan is None or plan.adapter_command in seen_commands:
                continue
            seen_commands.add(plan.adapter_command)
            plans.append(plan)
        return tuple(plans)


def _guard_run_executable_prefix(launch_plan: _GuardRunLaunchPlan) -> tuple[str, ...] | None:
    """Recover the canonical prefix prepended while pinning a preview argv."""

    adapter_arguments = launch_plan.adapter_command[1:]
    prefix_length = len(launch_plan.execution_command) - len(adapter_arguments)
    if prefix_length < 1:
        return None
    if adapter_arguments and launch_plan.execution_command[prefix_length:] != adapter_arguments:
        return None
    return launch_plan.execution_command[:prefix_length]


def _guard_run_finalize_authorized_launch_plan(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
    authorized_plans: Sequence[_GuardRunLaunchPlan],
) -> _GuardRunLaunchPlan | None:
    """Run authorized setup without re-resolving previewed launch identity."""

    if not authorized_plans or not all(plan.reusable for plan in authorized_plans):
        return None
    environment = authorized_plans[0].environment
    environment_sha256 = authorized_plans[0].environment_sha256
    if any(
        plan.environment_sha256 != environment_sha256 or dict(plan.environment) != dict(environment)
        for plan in authorized_plans[1:]
    ):
        return None
    resolved_prefixes = [_guard_run_executable_prefix(plan) for plan in authorized_plans]
    if any(prefix is None for prefix in resolved_prefixes):
        return None
    prefixes = tuple(dict.fromkeys(cast(tuple[str, ...], prefix) for prefix in resolved_prefixes))
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

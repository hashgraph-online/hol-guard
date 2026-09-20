"""Launch.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner
from .runner_dependencies import dataclass


@dataclass(frozen=True, slots=True)
class _GuardRunLaunchPlan:
    """The exact adapter launch vector resolved at an authority boundary."""

    adapter_command: tuple[str, ...]
    execution_command: tuple[str, ...]
    environment: runner.Mapping[str, str]
    environment_sha256: str
    identity: runner.Mapping[str, object]
    launch_cwd: runner.Path
    reusable: bool


def _guard_run_launch_environment(
    adapter: runner.HarnessAdapter,
    context: runner.HarnessContext,
) -> tuple[dict[str, str], runner.Path]:
    environment = runner.os.environ.copy()
    environment["HOME"] = str(context.home_dir)
    if runner.os.name == "nt":
        environment["USERPROFILE"] = str(context.home_dir)
    environment = adapter.prepare_launch_environment(context, environment)
    for credential_key in runner._GUARD_RUN_LATE_CREDENTIAL_ENV_KEYS:
        environment.pop(credential_key, None)
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items()):
        raise ValueError("Harness launch environment must contain only string keys and values.")
    launch_cwd = (context.workspace_dir or runner.Path.cwd()).expanduser().resolve(strict=True)
    if not launch_cwd.is_dir():
        raise NotADirectoryError(f"Harness launch cwd is not a directory: {launch_cwd}")
    return dict(environment), launch_cwd


def _guard_run_launch_environment_hash(environment: runner.Mapping[str, str]) -> str:
    """Return a canonical, non-reversible digest of the full prepared environment."""

    material = runner.json.dumps(
        sorted(environment.items()),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return runner.hashlib.sha256(b"hol.guard.guard-run-launch-environment:v1\x00" + material).hexdigest()


def _guard_run_plan_for_command(
    adapter_command: runner.Sequence[str],
    *,
    environment: runner.Mapping[str, str],
    launch_cwd: runner.Path,
) -> runner._GuardRunLaunchPlan | None:
    normalized_command = tuple(adapter_command)
    if not normalized_command or any(not isinstance(part, str) or not part for part in normalized_command):
        return None
    identity = runner.build_runtime_launch_identity(
        normalized_command[0],
        args=normalized_command[1:],
        structured_command=True,
        direct_executable=True,
        search_path=environment.get("PATH"),
        cwd=launch_cwd,
        launch_env=environment,
    )
    pinned_command = runner.resolved_runtime_launch_argv(identity, args=normalized_command[1:])
    reusable = pinned_command is not None and runner.runtime_launch_identity_is_reusable(identity)
    return runner._GuardRunLaunchPlan(
        adapter_command=normalized_command,
        execution_command=pinned_command if reusable and pinned_command is not None else normalized_command,
        environment=dict(environment),
        environment_sha256=runner._guard_run_launch_environment_hash(environment),
        identity=identity,
        launch_cwd=launch_cwd,
        reusable=reusable,
    )


def _guard_run_launch_previews(
    harness: str,
    context: runner.HarnessContext,
    passthrough_args: list[str],
) -> tuple[runner._GuardRunLaunchPlan, ...]:
    """Content-bind every launch argv without performing adapter setup."""

    adapter = runner.get_adapter(harness)
    raw_commands: runner.Sequence[runner.Sequence[str]] = adapter.preview_launch_commands(context, passthrough_args)
    environment, launch_cwd = runner._guard_run_launch_environment(adapter, context)
    plans: list[runner._GuardRunLaunchPlan] = []
    seen_commands: set[tuple[str, ...]] = set()
    for raw_command in raw_commands:
        plan = runner._guard_run_plan_for_command(
            raw_command,
            environment=environment,
            launch_cwd=launch_cwd,
        )
        if plan is None or plan.adapter_command in seen_commands:
            continue
        seen_commands.add(plan.adapter_command)
        plans.append(plan)
    return tuple(plans)


def _guard_run_executable_prefix(launch_plan: runner._GuardRunLaunchPlan) -> tuple[str, ...] | None:
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
    context: runner.HarnessContext,
    passthrough_args: list[str],
    authorized_plans: runner.Sequence[runner._GuardRunLaunchPlan],
) -> runner._GuardRunLaunchPlan | None:
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
    resolved_prefixes = [runner._guard_run_executable_prefix(plan) for plan in authorized_plans]
    if any(prefix is None for prefix in resolved_prefixes):
        return None
    prefixes = tuple(dict.fromkeys(runner.cast(tuple[str, ...], prefix) for prefix in resolved_prefixes))
    adapter = runner.get_adapter(harness)
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


def _guard_run_launch_plan_signature(launch_plan: runner._GuardRunLaunchPlan) -> str | None:
    if not launch_plan.reusable:
        return None
    return runner.json.dumps(
        {
            "adapter_command": list(launch_plan.adapter_command),
            "environment_sha256": launch_plan.environment_sha256,
            "identity": launch_plan.identity,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _guard_run_authority_signature(
    detection: runner.HarnessDetection,
    evaluation: runner.Mapping[str, object],
    launch_previews: runner.Sequence[runner._GuardRunLaunchPlan] = (),
) -> tuple[object, ...] | None:
    """Return the exact launch authority checked on both sides of a claim."""

    raw_artifacts = evaluation.get("artifacts")
    if not isinstance(raw_artifacts, list):
        return None
    contexts: dict[str, tuple[str, str]] = {}
    for item in raw_artifacts:
        if not isinstance(item, runner.Mapping):
            return None
        artifact_id = item.get("artifact_id")
        approval_context_hash = item.get("approval_context_hash")
        policy_action = item.get("policy_action")
        if (
            not isinstance(artifact_id, str)
            or not artifact_id
            or artifact_id in contexts
            or not isinstance(approval_context_hash, str)
            or runner.parse_approval_context_token(approval_context_hash) is None
            or not runner.is_guard_action(policy_action)
        ):
            return None
        contexts[artifact_id] = (approval_context_hash, policy_action)
    detector_payload = runner._runtime_detector_context(evaluation)
    return (
        detection.harness,
        detection.installed,
        detection.command_available,
        tuple(detection.config_paths),
        tuple(sorted(contexts.items())),
        runner.json.dumps(detector_payload, sort_keys=True, separators=(",", ":"), default=str),
        tuple(runner._guard_run_launch_plan_signature(plan) for plan in launch_previews),
    )


def _resolve_hermes_guard_access_token(store: runner.GuardStore) -> str | None:
    return runner.best_effort_access_token(lambda: runner._resolve_guard_sync_auth_context(store))


def _complete_guard_run_launch(
    *,
    harness: str,
    context: runner.HarnessContext,
    store: runner.GuardStore,
    dry_run: bool,
    passthrough_args: list[str],
    detection: runner.HarnessDetection,
    evaluation: dict[str, runner.Any],
    launch_plan: runner._GuardRunLaunchPlan | None,
) -> dict[str, runner.Any]:
    if "config_paths" not in evaluation:
        evaluation["config_paths"] = list(detection.config_paths) or runner._guard_run_config_paths(
            detection=detection,
            context=context,
            passthrough_args=passthrough_args,
        )
    authority_error = runner.evaluation_authority_error(
        evaluation,
        require_launch_permitted=not dry_run and evaluation.get("blocked") is False,
    )
    if authority_error is not None:
        evaluation["blocked"] = True
        evaluation["launched"] = False
        evaluation["launch_command"] = []
        evaluation["authority_error"] = runner.AUTHORITATIVE_DECISION_INCONSISTENT
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
            launch_previews = runner._guard_run_launch_previews(harness, context, passthrough_args)
            launch_plan = (
                runner._guard_run_finalize_authorized_launch_plan(
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
        _hermes_token = runner._resolve_hermes_guard_access_token(store)
        if _hermes_token is not None:
            # This is the sole intentional environment addition after the
            # prepared environment was authority-hashed. It is a short-lived
            # Guard credential resolved only at the execution boundary, not
            # user-controlled launch configuration. It must NOT leak to
            # user-configured MCP subprocesses; the proxy layer scrubs it
            # before launch (see proxy._build_scrubbed_env).
            environment[runner._HERMES_GUARD_TOKEN_ENV_KEY] = _hermes_token
    try:
        result = runner.subprocess.run(command, cwd=launch_plan.launch_cwd, check=False, env=environment)
    except FileNotFoundError as error:
        evaluation["launched"] = False
        evaluation["return_code"] = 127
        evaluation["launch_error"] = str(error)
        return evaluation
    evaluation["launched"] = True
    evaluation["return_code"] = result.returncode
    return evaluation

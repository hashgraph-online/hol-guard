"""One function per harness operation, answered by the native ``harness_adapter`` runtime.

Every function takes the harness name (or one of its aliases) first. The runtime owns each harness's paths,
detection, command lookup, install and uninstall plans, manifests, launch environment, runtime probe fields and
approval flow; these functions send the context only this process knows and return what the runtime answers. A
mutation takes the owner fields its caller already holds (see ``cli/native_managed_install.py``), so nothing here
reaches into the install transaction.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .harness_context import HarnessContext
from .models import HarnessDetection
from .native_harness_client import (
    HARNESS_ORDER,
    NATIVE_HARNESSES,
    _description,
    _native_context,
    _text,
    canonical_harness,
    run_op,
)
from .native_harness_steps import detection_from
from .setup_contract_models import HarnessSetupContract, HarnessSetupStep
from .setup_contracts import setup_contract_for

# Room for every CLI probe one harness runs, each bounded at five seconds.
_PROBE_RUNTIME_TIMEOUT_SECONDS = 60.0


def list_harnesses() -> tuple[str, ...]:
    """Every harness this Guard manages, in the order the product names them."""
    return HARNESS_ORDER


def aliases_of(harness: str) -> tuple[str, ...]:
    """The other names ``harness`` answers to."""
    name = canonical_harness(harness)
    return next(aliases for known, aliases, _launcher in NATIVE_HARNESSES if known == name)


def launcher_name_of(harness: str) -> str:
    """The name of the launcher Guard writes for ``harness``, or an empty string when it writes none."""
    name = canonical_harness(harness)
    return next(launcher for known, _aliases, launcher in NATIVE_HARNESSES if known == name)


def executable_of(harness: str) -> str:
    """The command that starts ``harness``."""
    name = canonical_harness(harness)
    return launcher_name_of(name) or name


def legacy_launcher_names(harness: str) -> tuple[str, ...]:
    """Older launcher names an uninstall also removes."""
    return tuple(str(name) for name in _description(canonical_harness(harness)).get("legacy_launchers", ()))


def command_absence_proves_uninstalled(harness: str) -> bool:
    """Whether an unavailable command is enough to conclude the tool itself is gone."""
    return _description(canonical_harness(harness)).get("absence_proves_uninstalled") is not False


def display_name_of(harness: str) -> str | None:
    """The name the runtime shows for ``harness``."""
    value = _description(canonical_harness(harness)).get("display_name")
    return value if isinstance(value, str) else None


def run(harness: str, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
    """One named op of ``harness``, with the replies only this process can give answered."""
    return run_op(canonical_harness(harness), op, context, **fields)


def detect(harness: str, context: HarnessContext) -> HarnessDetection:
    """What the runtime finds of ``harness`` on this host, with the workspace AIBOM merged in."""
    from .aibom_detection import _AIBOM_DISCOVERY_TIMEOUT_SECONDS, NativeAibomError
    from .native_runner_authority import NativeRunnerAuthorityError

    name = canonical_harness(harness)
    fields: dict[str, object] = {}
    if name == "codex":
        from .native_codex_ops import detect_fields

        fields = detect_fields(context)
    # Discovery walks the workspace, so it keeps the longer AIBOM deadline.
    try:
        answer = run_op(name, "detect_merged", context, timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS, **fields)
    except NativeRunnerAuthorityError as error:
        raise NativeAibomError(str(error)) from error
    if name == "codex" and "untrusted" in answer:
        from .codex_harness_client import raise_untrusted

        raise_untrusted(answer["untrusted"])
    return detection_from(name, answer)


def policy_path(harness: str, context: HarnessContext) -> Path:
    """The MCP policy file ``harness`` reads for this context."""
    return Path(_text(run(harness, "policy_path", context), "path"))


def resolved_executable(harness: str, context: HarnessContext) -> str | None:
    """The command path the runtime resolves for ``harness``, if any."""
    path = run(harness, "resolved_executable", context).get("path")
    return path if isinstance(path, str) else None


def launch_command(harness: str, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
    """The argv that launches ``harness`` with the caller's arguments."""
    name = canonical_harness(harness)
    if name == "codex":
        from .native_codex_ops import codex_launch_command

        return codex_launch_command(context, passthrough_args)
    spec = _description(name)
    if spec.get("launch_runner"):
        from .native_harness_steps import runner_launch_argv

        return runner_launch_argv(spec["launch_runner"], context, passthrough_args)
    op = spec.get("launch_op") or ("launch_command" if spec.get("trusted_launcher") else "default_launch")
    return [str(part) for part in run_op(name, op, context, args=passthrough_args)["argv"]]


def preview_launch_commands(
    harness: str, context: HarnessContext, passthrough_args: list[str]
) -> tuple[list[str], ...]:
    """Every command the next launch preparation may select, without side effects."""
    name = canonical_harness(harness)
    if name == "codex":
        from .native_codex_ops import codex_preview_launch_commands

        return codex_preview_launch_commands(context, passthrough_args)
    spec = _description(name)
    if spec.get("launch_op") or not spec.get("trusted_launcher"):
        return (launch_command(name, context, passthrough_args),)
    # Resolves without registering an explicit path.
    return ([str(part) for part in run_op(name, "preview_launch", context, args=passthrough_args)["argv"]],)


def launch_command_from_authorized_plan(
    harness: str,
    context: HarnessContext,
    passthrough_args: list[str],
    *,
    authorized_executable_prefixes: Sequence[Sequence[str]],
    launch_environment: Mapping[str, str],
) -> list[str]:
    """Finalize a command only after its preview plans were authorized."""
    if canonical_harness(harness) == "codex":
        from .native_codex_ops import codex_launch_command_from_prefixes

        return codex_launch_command_from_prefixes(
            context,
            passthrough_args,
            authorized_executable_prefixes=authorized_executable_prefixes,
            launch_environment=launch_environment,
        )
    return launch_command(harness, context, passthrough_args)


def launch_environment(harness: str, context: HarnessContext) -> dict[str, str]:
    """The variables ``harness`` adds to its own launch environment."""
    name = canonical_harness(harness)
    spec = _description(name)
    if name != "codex":
        if spec.get("launch_runner"):
            from .native_harness_steps import runner_launch_environment

            return runner_launch_environment(spec["launch_runner"], context)
        if not spec.get("dynamic"):
            return {}
    environment = run_op(name, "launch_env", context).get("env")
    return {str(key): str(value) for key, value in environment.items()} if isinstance(environment, dict) else {}


def prepare_launch_environment(harness: str, context: HarnessContext, inherited: Mapping[str, str]) -> dict[str, str]:
    """The environment ``harness`` is launched with."""
    name = canonical_harness(harness)
    if not _description(name).get("trusted_launcher"):
        environment = dict(inherited)
        environment.update(launch_environment(name, context))
        return environment
    answer = run_op(
        name,
        "sanitize_env",
        context,
        path_value=inherited.get("PATH"),
        grok_home=inherited.get("GROK_HOME"),
        env_keys=sorted(inherited),
    )
    dropped = {str(key) for key in answer["drop"]}
    environment = {key: value for key, value in inherited.items() if key not in dropped}
    environment["PATH"] = _text(answer, "path")
    environment.update(launch_environment(name, context))
    return environment


def runtime_probe(harness: str, context: HarnessContext) -> dict[str, object] | None:
    """The runtime's CLI probe of ``harness``."""
    probe = run(harness, "probe_runtime", context, timeout_seconds=_PROBE_RUNTIME_TIMEOUT_SECONDS)["probe"]
    return probe if isinstance(probe, dict) else None


def approval_flow(harness: str, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
    """How ``harness`` routes an approval."""
    from .native_harness_client import _KIND

    name = canonical_harness(harness)
    spec = _description(name)
    if not spec.get("dynamic"):
        return dict(spec["approval"])
    from .native_runner_authority import native_runner_authority

    # The flow reads only the managed install record, never the filesystem.
    request = {
        "op": "approval_flow",
        "harness": name,
        "context": {"home": "", "guard_home": "", "user_home": ""},
        "managed_install": json.loads(json.dumps(managed_install, default=lambda _: None)),
    }
    return native_runner_authority(_KIND, request)


def start_operation(
    harness: str, context: HarnessContext, *, session_id: str, operation_type: str
) -> dict[str, object]:
    """The record a session starts for one launch."""
    return {
        "harness": canonical_harness(harness),
        "session_id": session_id,
        "operation_type": operation_type,
        "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
    }


def _own_warnings(harness: str, detection: HarnessDetection, probe: dict[str, object] | None) -> list[str] | None:
    """The final warnings a harness words itself, or ``None`` for the ones Guard words."""
    if not _description(harness).get("warnings_op"):
        return None
    from .native_harness_steps import native_warnings

    return native_warnings(harness, detection, probe)


def diagnostic_warnings(harness: str, detection: HarnessDetection, probe: dict[str, object] | None) -> list[str]:
    """The doctor warnings for one detection."""
    from .diagnostics_bridge import guard_warnings

    name = canonical_harness(harness)
    own = _own_warnings(name, detection, probe)
    if own is not None:
        return own
    return guard_warnings(name, executable_of(name), command_absence_proves_uninstalled(name), detection, probe)


def diagnostics(harness: str, context: HarnessContext) -> dict[str, object]:
    """The doctor report for ``harness``."""
    from .diagnostics_bridge import native_diagnostics

    name = canonical_harness(harness)
    detection = detect(name, context)
    probe = runtime_probe(name, context)
    payload = native_diagnostics(
        harness=name,
        executable=executable_of(name),
        command_absence_proves_uninstalled=command_absence_proves_uninstalled(name),
        guard_home=context.guard_home,
        launcher_names=[launcher_name_of(name) or name, *legacy_launcher_names(name)],
        detection=detection,
        runtime_probe=probe,
        warnings=_own_warnings(name, detection, probe),
    )
    spec = _description(name)
    if spec.get("diagnostics"):
        found = bool(payload.get("installed") or payload.get("config_paths"))
        answer = run_op(
            name,
            "diagnostics",
            context,
            found=found,
            setup_status=payload.get("setup_status"),
            warnings=json.loads(json.dumps(payload.get("warnings", []), default=str)),
            **delegate_fields(name, context),
        )
        payload.update(json.loads(_text(answer, "update")))
    if name == "codex":
        from .native_codex_ops import codex_diagnostics

        return codex_diagnostics(context, payload)
    return payload


def delegate_fields(harness: str, context: HarnessContext) -> dict[str, object]:
    """Which native runtimes a delegating harness (Paseo) could hand a session to on this host."""
    spec = _description(canonical_harness(harness))
    if spec.get("install") != "delegated":
        return {}
    native = _native_context(context)
    return {
        "delegates": {
            str(name): resolved_executable(str(name), native) is not None for name in spec.get("delegates", ())
        }
    }


def delegated_targets(harness: str, context: HarnessContext) -> dict[str, Any]:
    """The delegated install targets Paseo's install plan names."""
    return run(harness, "prepare_install", context, **delegate_fields(harness, context))


def hook_argv(harness: str, context: HarnessContext) -> list[str]:
    """The hook argv an install writes for ``harness``."""
    return [str(part) for part in run(harness, "hook_spec", context)["hook_argv"]]


def current_hook_command(harness: str, context: HarnessContext) -> str:
    """The hook command an install would write now, as the harness config spells it."""
    return _text(run(harness, "hook_candidates", context, hook_argv=hook_argv(harness, context)), "hook_command")


def setup_contract(harness: str) -> HarnessSetupContract:
    """The guided setup contract the runtime renders for ``harness``."""
    name = canonical_harness(harness)
    contract = setup_contract_for(name)
    if contract is None:
        raise ValueError(f"Unsupported harness setup contract: {name}")
    return contract


def setup_steps(harness: str) -> tuple[HarnessSetupStep, ...]:
    return setup_contract(harness).setup_steps


def verify_steps(harness: str) -> tuple[HarnessSetupStep, ...]:
    return setup_contract(harness).verify_steps


def repair_steps(harness: str) -> tuple[HarnessSetupStep, ...]:
    return setup_contract(harness).repair_steps

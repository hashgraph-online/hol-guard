"""Harness adapters the native runtime answers: Devin, Antigravity, Gemini, Kimi, OpenClaw, Paseo, Muse,
Grok, ZCode, Pi, Oh My Pi, OpenCode, Cline, Copilot, Cursor, Claude Code, Hermes and Codex.

The ``harness_adapter`` runner-authority kind owns their paths, detection, command lookup, install and
uninstall plans, manifests, launch environment, runtime probe fields, approval flow, Paseo's delegated
install steps and the Pi-family extension. Install and uninstall run whole in the runtime (``adapter_install``,
``adapter_uninstall``), which publishes the launcher and the plan and journals every write under the owner this
process holds. This class keeps what must run in the Guard process: the ownership the base class wraps around
install and uninstall, the facts only this process knows, and the probe subprocess.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import replace
from functools import cache
from pathlib import Path
from typing import Any

from ..harness.diagnostic_probes import command_probes_enabled
from ..models import HarnessDetection
from ..native_caller import caller_identity
from .base import HarnessAdapter, HarnessContext, PreparedHarnessInstall
from .native_harness_steps import detection_from, planned_files

_KIND = "harness_adapter"
# Room for every CLI probe one harness runs, each bounded at five seconds.
_PROBE_RUNTIME_TIMEOUT_SECONDS = 60.0

#: ``(harness, aliases, launcher_name)`` in registry order. The runtime's
#: ``describe`` answer carries the same identity; a test keeps them in step,
#: so building the registry never needs a resident call.
NATIVE_HARNESSES: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("devin", ("devin", "devin-cli", "cognition-devin"), "devin"),
    ("antigravity", (), ""),
    ("gemini", (), ""),
    ("kimi", ("kimi", "kimi-code", "kimi-cli"), "kimi"),
    ("openclaw", (), ""),
    ("paseo", (), ""),
    ("muse", ("muse", "muse-code"), "muse"),
    ("grok", ("grok-build", "grok-build-cli", "xai-grok"), "grok"),
    ("zcode", ("zcode", "zai", "z-code", "zai-zcode"), "zcode"),
    ("pi", ("pi", "pi-agent", "pi-coding-agent"), "pi"),
    ("omp", ("omp", "oh-my-pi"), "omp"),
    ("opencode", (), ""),
    ("cline", ("cline-cli", "cline-vscode"), "cline"),
    ("copilot", (), ""),
    ("cursor", (), "cursor-agent"),
    ("claude-code", ("claude",), "claude"),
    ("hermes", (), ""),
    ("codex", (), ""),
)

#: Ops that render a Pi-family extension, so they carry this process's facts.
_EXTENSION_OPS = frozenset(
    {
        "apply_install",
        "prepare_install",
        "prepare_uninstall",
        "apply_uninstall",
        "extension_source",
        "extension_current",
        "legacy_omp_verified",
    }
)


@cache
def describe() -> dict[str, Any]:
    """The runtime's description of every adapter it answers."""
    from ..native_runner_authority import native_runner_authority

    answer = native_runner_authority(_KIND, {"op": "describe"})
    if not isinstance(answer.get("adapters"), list):
        raise ValueError("Harness adapter description is malformed")
    return answer


def _description(harness: str) -> dict[str, Any]:
    for adapter in describe()["adapters"]:
        if isinstance(adapter, dict) and adapter.get("harness") == harness:
            return adapter
    raise ValueError(f"Unsupported harness: {harness}")


def request_environment() -> dict[str, str]:
    """The variables the runtime reads, and nothing else from this process."""
    description = describe()
    names = set(description.get("env_names", ()))
    prefixes = tuple(description.get("env_prefixes", ()))
    return {name: value for name, value in os.environ.items() if name in names or name.startswith(prefixes)}


def wire_context(context: HarnessContext) -> dict[str, object]:
    """The context a ``harness_adapter`` request carries."""
    try:
        cwd: str | None = os.getcwd()
    except OSError:
        paths = (context.home_dir, context.guard_home, context.workspace_dir)
        if any(path is not None and not path.is_absolute() for path in paths):
            raise
        cwd = None
    return {
        "home": str(context.home_dir),
        "workspace": None if context.workspace_dir is None else str(context.workspace_dir),
        "guard_home": str(context.guard_home),
        "home_override_explicit": bool(getattr(context, "home_override_explicit", False)),
        "cwd": cwd,
        "user_home": str(Path.home()),
        "env": request_environment(),
        "executable_overrides": dict(getattr(context, "executable_overrides", {}) or {}),
        "caller": caller_identity(),
        "probes": command_probes_enabled(),
    }


def ask(
    op: str,
    context: HarnessContext,
    *,
    harness: str | None = None,
    timeout_seconds: float | None = None,
    **fields: object,
) -> dict[str, Any]:
    """Run one op and raise the error the Python adapter raised for a refusal."""
    from ..native_runner_authority import native_runner_authority

    request: dict[str, object] = {"op": op, "context": wire_context(context), **fields}
    if harness is not None:
        request["harness"] = harness
    answer = native_runner_authority(_KIND, request, timeout_seconds=timeout_seconds)
    if answer.get("ok") is False and "failure" in answer:
        # An install op that ran as the owner of the Guard home answers its failure in the owned shape.
        from ..native_owned import _failure

        raise _failure(answer)
    if len(answer) == 1:
        raise_failure(answer)
    return answer


def _surface(surface: str | None) -> dict[str, object]:
    """The surface field, left out so the runtime applies the harness default."""
    return {} if surface is None else {"surface": surface}


def raise_failure(answer: dict[str, Any]) -> None:
    """Raise the error a one-key failure answer names; return for any other answer."""
    if "refusal" in answer:
        raise ValueError(str(answer["refusal"]))
    if "os_error" in answer:
        raise OSError(str(answer["os_error"]))
    if "not_found" in answer:
        raise FileNotFoundError(str(answer["not_found"]))
    if "runtime_error" in answer:
        raise RuntimeError(str(answer["runtime_error"]))
    if "integrity" in answer:
        from ..codex_hook_recovery import _error

        raise _error(str(answer["integrity"]))


def _text(answer: dict[str, Any], key: str) -> str:
    value = answer.get(key)
    if not isinstance(value, str):
        raise ValueError("Harness adapter answer is malformed")
    return value


def _native_context(context: HarnessContext) -> HarnessContext:
    """Paseo installs for the daemon user, not the caller's current worktree."""
    return replace(context, workspace_dir=None, workspace_override_explicit=False)


class NativeHarnessAdapter(HarnessAdapter):
    """One harness the ``harness_adapter`` kind answers."""

    #: Install and uninstall run whole in the runtime, which holds the locks for the op's own duration.
    native_owned_mutation = True

    def __init__(self, harness: str, aliases: tuple[str, ...], launcher_name: str) -> None:
        self.harness = harness
        self.aliases = aliases
        self.executable = launcher_name or harness
        self.launcher_name = launcher_name

    @property
    def _spec(self) -> dict[str, Any]:
        return _description(self.harness)

    @property
    def legacy_launcher_names(self) -> tuple[str, ...]:
        return tuple(str(name) for name in self._spec.get("legacy_launchers", ()))

    @property
    def command_absence_proves_uninstalled(self) -> bool:
        return self._spec.get("absence_proves_uninstalled") is not False

    def run_op(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        """One op of this harness, with the replies only this process can give answered."""
        return self._ask(op, context, **fields)

    def _ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        if op in _EXTENSION_OPS and self._spec.get("extension"):
            from ..harness.extension_runtime import extension_runtime

            fields["runtime"] = extension_runtime()
        answer = self._owned_ask(op, context, **fields)
        if answer == {"reply": {"facts": None}} and "facts" not in fields:
            # The daemon URL the hooks reach is only known to this process.
            from ..claude_hook_entry import claude_facts

            fields["facts"] = claude_facts(context.guard_home)
            answer = self._owned_ask(op, context, **fields)
        if answer == {"reply": {"workspace_skills": None}} and "workspace_skills" not in fields:
            # Only a Windows walk in this process finds the workspace skills.
            from ..aibom_detection import portable_workspace_skills

            fields["workspace_skills"] = portable_workspace_skills(self.harness, context.workspace_dir)
            answer = self._owned_ask(op, context, **fields)
        return answer

    def _owned_ask(self, op: str, context: HarnessContext, **fields: Any) -> dict[str, Any]:
        from .native_harness_steps import owned_ask

        return owned_ask(self.harness, self._spec.get("hook_ownership"), op, context, **fields)

    def _shim_names(self) -> dict[str, Any]:
        return {"launcher_name": self.launcher_name or None, "display_name": self._spec.get("display_name")}

    def policy_path(self, context: HarnessContext) -> Path:
        return Path(_text(self._ask("policy_path", context), "path"))

    def resolved_executable(self, context: HarnessContext) -> str | None:
        path = self._ask("resolved_executable", context).get("path")
        return path if isinstance(path, str) else None

    def _detect_fields(self, context: HarnessContext) -> dict[str, object]:
        """What the runtime's detection asks of this process; none by default."""
        return {}

    def _check_detected(self, answer: dict[str, Any]) -> None:
        """Refuse a detection answer that names a refusal; none by default."""

    def detect(self, context: HarnessContext) -> HarnessDetection:
        from ..aibom_detection import _AIBOM_DISCOVERY_TIMEOUT_SECONDS, NativeAibomError
        from ..native_runner_authority import NativeRunnerAuthorityError

        # Discovery walks the workspace, so it keeps the longer AIBOM deadline.
        try:
            answer = self._ask(
                "detect", context, timeout_seconds=_AIBOM_DISCOVERY_TIMEOUT_SECONDS, **self._detect_fields(context)
            )
        except NativeRunnerAuthorityError as error:
            raise NativeAibomError(str(error)) from error
        self._check_detected(answer)
        return detection_from(self.harness, context, answer)

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        if self._spec.get("launch_runner"):
            from .native_harness_steps import runner_launch_argv

            return runner_launch_argv(self._spec["launch_runner"], context, passthrough_args)
        op = self._spec.get("launch_op") or (
            "launch_command" if self._spec.get("trusted_launcher") else "default_launch"
        )
        return [str(part) for part in self._ask(op, context, args=passthrough_args)["argv"]]

    def preview_launch_commands(self, context: HarnessContext, passthrough_args: list[str]) -> tuple[list[str], ...]:
        if self._spec.get("launch_op"):
            return (self.launch_command(context, passthrough_args),)
        if not self._spec.get("trusted_launcher"):
            return super().preview_launch_commands(context, passthrough_args)
        # Resolves without registering an explicit path.
        return ([str(part) for part in self._ask("preview_launch", context, args=passthrough_args)["argv"]],)

    def prepare_launch_environment(self, context: HarnessContext, inherited: Mapping[str, str]) -> dict[str, str]:
        if not self._spec.get("trusted_launcher"):
            return super().prepare_launch_environment(context, inherited)
        answer = self._ask(
            "sanitize_env",
            context,
            path_value=inherited.get("PATH"),
            grok_home=inherited.get("GROK_HOME"),
            env_keys=sorted(inherited),
        )
        dropped = {str(key) for key in answer["drop"]}
        environment = {key: value for key, value in inherited.items() if key not in dropped}
        environment["PATH"] = _text(answer, "path")
        environment.update(self.launch_environment(context))
        return environment

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        if self._spec.get("launch_runner"):
            from .native_harness_steps import runner_launch_environment

            return runner_launch_environment(self._spec["launch_runner"], context)
        if not self._spec.get("dynamic"):
            return {}
        environment = self._ask("launch_env", context).get("env")
        return {str(key): str(value) for key, value in environment.items()} if isinstance(environment, dict) else {}

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        # The native runtime runs every CLI probe the harness names.
        probe = self._ask("probe_runtime", context, timeout_seconds=_PROBE_RUNTIME_TIMEOUT_SECONDS)["probe"]
        return probe if isinstance(probe, dict) else None

    def approval_flow(self, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
        if not self._spec.get("dynamic"):
            return dict(self._spec["approval"])
        from ..native_runner_authority import native_runner_authority

        # The flow reads only the managed install record, never the filesystem.
        request = {
            "op": "approval_flow",
            "harness": self.harness,
            "context": {"home": "", "guard_home": "", "user_home": ""},
            "managed_install": json.loads(json.dumps(managed_install, default=lambda _: None)),
        }
        return native_runner_authority(_KIND, request)

    def _hook_argv(self, context: HarnessContext) -> list[str]:
        return [str(part) for part in self._ask("hook_spec", context)["hook_argv"]]

    def prepare_install(self, context: HarnessContext, *, surface: str | None = None) -> PreparedHarnessInstall:
        from ..runtime_transition import TransitionError
        from ..shims import prepare_guard_shim

        mode = self._spec.get("install")
        if mode == "delegated" or self._spec.get("prepare") == "unavailable":
            raise TransitionError("adapter_preparation_unavailable")
        if self._spec.get("prepare") == "detected":
            from .native_harness_steps import prepared_from_detection

            return prepared_from_detection(self, context, create_key=False)
        if self._spec.get("prepare") == "surfaces":
            from .native_harness_steps import prepared_surfaces

            return prepared_surfaces(self, context, **_surface(surface))
        shim = prepare_guard_shim(self.harness, context, **self._shim_names())
        if mode == "shim":
            manifest = {"harness": self.harness, "active": True, "config_path": shim.manifest["shim_path"]}
            return PreparedHarnessInstall(shim.files, {**manifest, **shim.manifest})
        fields: dict[str, object] = {"shim": json.dumps(shim.manifest)}
        if self._spec.get("hook") is not None:
            fields["hook_argv"] = self._hook_argv(context)
        answer = self._ask("prepare_install", context, **fields)
        files = planned_files(answer)
        return PreparedHarnessInstall((*shim.files, *files), json.loads(_text(answer, "manifest")))

    def current_hook_command(self, context: HarnessContext) -> str:
        """The hook command an install would write now, as the harness config spells it."""

        return _text(self._ask("hook_candidates", context, hook_argv=self._hook_argv(context)), "hook_command")

    def preflight_management(self, context: HarnessContext, *, operation: str) -> None:
        if operation == "install" and self._spec.get("install") == "delegated":
            self._delegated_targets(context)

    def install(self, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
        from ..native_transition_files import PUBLISH_TIMEOUT_SECONDS

        providers = len(self._spec.get("delegates", ())) if self._spec.get("install") == "delegated" else 0
        return self._native_mutation(
            "adapter_install",
            context,
            timeout_seconds=(self._spec.get("install_timeout") or PUBLISH_TIMEOUT_SECONDS) * (1 + providers),
            **_surface(surface),
        )

    def uninstall(self, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
        from ..native_transition_files import PUBLISH_TIMEOUT_SECONDS

        return self._native_mutation(
            "adapter_uninstall",
            context,
            timeout_seconds=PUBLISH_TIMEOUT_SECONDS,
            **_surface(surface),
        )

    def _native_mutation(
        self, op: str, context: HarnessContext, *, timeout_seconds: float, **options: object
    ) -> dict[str, object]:
        """Prepare, publish and journal the install or uninstall in one native call.

        The owner this thread holds is named by its token, so the runtime journals every write under it.
        """
        from ..native_owned import owner_request
        from ..runtime_transition import assert_transition_mutation_allowed
        from .native_install_facts import adapter_manifest, install_facts

        assert_transition_mutation_allowed(context.guard_home)
        self.preflight_management(context, operation="install" if op == "adapter_install" else "uninstall")
        answer = self._owned_ask(
            op,
            context,
            timeout_seconds=timeout_seconds,
            **owner_request(context.guard_home, actor=f"adapter.{self.harness}.{op}"),
            **install_facts(context, (self.harness,), uninstall=op == "adapter_uninstall"),
            **options,
        )
        return adapter_manifest(answer)

    def _own_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str] | None:
        if not self._spec.get("warnings_op"):
            return None
        from .native_harness_steps import native_warnings

        return native_warnings(self, detection, runtime_probe)

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        if not self._spec.get("diagnostics"):
            return payload
        found = bool(payload.get("installed") or payload.get("config_paths"))
        answer = self._ask(
            "diagnostics",
            context,
            found=found,
            setup_status=payload.get("setup_status"),
            warnings=json.loads(json.dumps(payload.get("warnings", []), default=str)),
            **self._delegate_fields(context),
        )
        payload.update(json.loads(_text(answer, "update")))
        return payload

    def _delegate_fields(self, context: HarnessContext) -> dict[str, object]:
        """Which native runtimes Paseo could hand a session to on this host."""
        if self._spec.get("install") != "delegated":
            return {}
        from .registry import get_adapter

        native = _native_context(context)
        return {
            "delegates": {
                str(name): get_adapter(str(name)).resolved_executable(native) is not None
                for name in self._spec.get("delegates", ())
            }
        }

    def _delegated_targets(self, context: HarnessContext) -> dict[str, Any]:
        return self._ask("prepare_install", context, **self._delegate_fields(context))


__all__ = [
    "NATIVE_HARNESSES",
    "NativeHarnessAdapter",
    "ask",
    "describe",
    "detection_from",
    "planned_files",
    "wire_context",
]

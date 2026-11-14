"""Base harness adapter helpers."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from functools import cached_property, wraps
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from ...path_support import resolves_within_root
from ..models import GuardArtifact, HarnessDetection
from .contracts import HarnessCoverageSummary, HarnessSetupContract, HarnessSetupStep, setup_contract_for
from .diagnostic_probes import skipped_command_probe

if TYPE_CHECKING:
    from ..inventory_contract import GuardAgentInventorySnapshot
    from ..runtime_transition import TransitionFile


@dataclass(frozen=True, slots=True)
class HarnessContext:
    """Paths used by harness adapters."""

    home_dir: Path
    workspace_dir: Path | None
    guard_home: Path
    executable_overrides: Mapping[str, str] = field(default_factory=dict[str, str])
    home_override_explicit: bool = False
    workspace_override_explicit: bool = False


@dataclass(frozen=True)
class PreparedHarnessInstall:
    files: tuple[TransitionFile, ...]
    manifest: dict[str, object]

    def publish(
        self,
        guard_home: Path,
        *,
        removals: bool = False,
        rollback: bool = True,
        on_write: Callable[[TransitionFile], None] | None = None,
    ) -> dict[str, object]:
        """Publish an ordinary install under ownership; pending transitions use their signed plan.

        ``removals`` admits planned deletions, for a plan that retires files an
        older install left behind. Rollback still restores them. A caller that
        journals the plan itself passes ``rollback=False`` and recovers from its
        own record; ``on_write`` sees each file just after it is written.
        """
        from ..codex_install_transaction import require_codex_install_owner
        from ..runtime_transition import RuntimeTransition, TransitionError, assert_transition_mutation_allowed

        require_codex_install_owner(guard_home)
        assert_transition_mutation_allowed(guard_home)
        if any(
            change.kind != "binding" or (not removals and change.after is None and change.before != change.after)
            for change in self.files
        ):
            raise TransitionError("adapter_install_plan_invalid")
        changes: dict[str, object] = {"files": [change.payload() for change in self.files]}
        RuntimeTransition._compare(changes, "before")
        written: list[dict[str, object]] = []
        try:
            for change in self.files:
                payload = change.payload()
                RuntimeTransition._compare({"files": [payload]}, "before")
                RuntimeTransition._write_file(payload, "after")
                written.append(payload)
                if on_write is not None:
                    on_write(change)
            RuntimeTransition._compare(changes, "after")
        except Exception as error:
            if not rollback:
                raise
            restore_error: Exception | None = None
            for payload in reversed(written):
                try:
                    RuntimeTransition._compare({"files": [payload]}, "after")
                    RuntimeTransition._write_file(payload, "before")
                except Exception as failure:
                    restore_error = failure
            if restore_error is not None:
                raise restore_error from error
            raise
        return self.manifest


def _json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def detection_request(harness: str, context: HarnessContext) -> dict[str, object]:
    """The home and workspace a native detection kind reads, as Python holds them.

    The working directory always travels with the request: relative paths,
    including ones read from harness-written files, resolve against Python's
    cwd and never the resident's.
    """

    workspace = context.workspace_dir
    request: dict[str, object] = {
        "harness": harness,
        "home": str(context.home_dir),
        "workspace": None if workspace is None else str(workspace),
    }
    try:
        request["cwd"] = os.getcwd()
    except OSError:
        if not context.home_dir.is_absolute() or (workspace is not None and not workspace.is_absolute()):
            raise
    return request


def _shell_command(command: tuple[str, ...], *, windows: bool | None = None) -> str:
    """Return a shell-escaped command string appropriate for the target OS."""

    is_windows = os.name == "nt" if windows is None else windows
    if is_windows:
        return subprocess.list2cmdline(list(command))
    return shlex.join(command)


#: The caller environment a harness CLI probe runs with.
_PROBE_ENV_KEYS = (
    "PATH",
    "PATHEXT",
    "HOME",
    "USERPROFILE",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "LANG",
    "LC_ALL",
)


def _run_command_probe(
    command: list[str],
    timeout_seconds: int = 5,
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Run a harness CLI's ``--help`` or ``--version`` through the native ``command_probe`` kind."""

    skipped = skipped_command_probe(command)
    if skipped is not None:
        return skipped
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {
        "command": [str(part) for part in command],
        "cwd": str((cwd or Path.cwd()).absolute()),
        "env": {key: os.environ[key] for key in _PROBE_ENV_KEYS if key in os.environ} if env is None else dict(env),
        "timeout_seconds": timeout_seconds,
    }
    try:
        return native_runner_authority("command_probe", request, timeout_seconds=timeout_seconds + 10.0)
    except NativeRunnerAuthorityError:
        # A diagnostic probe never fails the doctor; it reports that nothing ran.
        return {"command": command, "ok": False, "return_code": None, "stdout": "", "stderr": "probe unavailable"}


def _ensure_path_within_root(root: Path, path: Path, *, label: str) -> None:
    if not resolves_within_root(root, path):
        raise ValueError(f"{label} settings path escapes the managed root")


_MutationResult = TypeVar("_MutationResult")
_T = TypeVar("_T")


def _owned_adapter_mutation(method: Callable[..., _MutationResult]) -> Callable[..., _MutationResult]:
    @wraps(method)
    def owned(self: HarnessAdapter, context: HarnessContext, *args: object, **kwargs: object) -> _MutationResult:
        from ..codex_install_transaction import _home_owner_lock, codex_install_transaction
        from ..runtime_transition import assert_transition_mutation_allowed

        with ExitStack() as ownership:
            if self.harness == "codex":
                from .codex_lifecycle_lock import codex_lifecycle_locks

                ownership.enter_context(codex_lifecycle_locks(context))
            ownership.enter_context(_home_owner_lock(context.guard_home))
            assert_transition_mutation_allowed(context.guard_home)
            self.preflight_management(context, operation=method.__name__)
            with codex_install_transaction(
                context.guard_home,
                context.guard_home / "managed",
                actor=f"adapter.{self.harness}.{method.__name__}",
            ):
                assert_transition_mutation_allowed(context.guard_home)
                return method(self, context, *args, **kwargs)

    owned.__dict__["_guard_mutation_owned"] = True
    return owned


class HarnessAdapter:
    """Common interface shared by harness adapters."""

    harness = ""
    aliases: tuple[str, ...] = ()
    executable = ""
    launcher_name = ""
    legacy_launcher_names: tuple[str, ...] = ()
    approval_tier = "approval-center"
    approval_summary = "Guard pauses the launch and routes approval through the local approval center."
    fallback_hint = "Use the Guard approval center or native harness prompt to resolve pending requests."
    approval_prompt_channel = "browser"
    approval_auto_open_browser = True
    #: Whether an unavailable command is enough to conclude the tool itself is gone.
    #: A harness whose Guard hooks keep running without its CLI sets this False, so
    #: leftover configuration is never mistaken for an absent tool.
    command_absence_proves_uninstalled = True

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Apply the shared mutation contract to overrides as well as defaults.
        # Direct adapter callers must not bypass CLI transition ownership.
        for name in ("install", "uninstall"):
            method = cls.__dict__.get(name)
            if method is not None:
                setattr(cls, name, _owned_adapter_mutation(method))

    def detect(self, context: HarnessContext) -> HarnessDetection:
        raise NotImplementedError

    def preflight_management(self, context: HarnessContext, *, operation: str) -> None:
        """Reject invalid targets without writes; mutation must recheck under ownership."""

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        """Prepare a complete default install; native overrides must supply their own plan."""
        from ..runtime_transition import TransitionError
        from ..shims import prepare_guard_shim

        if type(self).install is not HarnessAdapter.install:
            # Never pass a partial launcher plan off as a native hook install.
            raise TransitionError("adapter_preparation_unavailable")
        prepared = prepare_guard_shim(self.harness, context)
        return PreparedHarnessInstall(
            prepared.files,
            {
                "harness": self.harness,
                "active": True,
                "config_path": prepared.manifest["shim_path"],
                **prepared.manifest,
            },
        )

    def inventory_snapshot(
        self,
        context: HarnessContext,
        *,
        generated_at: str,
        cisco_mcp_scan: str = "off",
        cisco_skill_scan: str = "off",
        cisco_timeout_seconds: float | None = None,
    ) -> GuardAgentInventorySnapshot:
        """Build a normalized inventory snapshot from this adapter's detection."""

        from ..inventory_cisco import run_cisco_inventory_scans
        from ..inventory_contract import inventory_snapshot_from_detection
        from ..native_context import bound_context_digest_home

        detection = self.detect(context)
        cisco_runs = run_cisco_inventory_scans(
            harness=self.harness,
            context=context,
            detection=detection,
            mcp_mode=cisco_mcp_scan,
            skill_mode=cisco_skill_scan,
            timeout_seconds=cisco_timeout_seconds,
        )
        # Redaction asks the resident of this context's home.
        with bound_context_digest_home(getattr(context, "guard_home", None)):
            return inventory_snapshot_from_detection(
                detection,
                generated_at=generated_at,
                home_dir=context.home_dir,
                workspace_dir=context.workspace_dir,
                cisco_runs=cisco_runs,
            )

    @_owned_adapter_mutation
    def install(self, context: HarnessContext) -> dict[str, object]:
        from ..shims import install_guard_shim

        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": shim_manifest["shim_path"],
            **shim_manifest,
        }

    @_owned_adapter_mutation
    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        from ..shims import remove_guard_shim

        shim_manifest = remove_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": False,
            "config_path": shim_manifest["shim_path"],
            **shim_manifest,
        }

    @cached_property
    def _setup_contract(self) -> HarnessSetupContract:
        contract = setup_contract_for(self.harness)
        if contract is None:
            raise ValueError(f"Unsupported harness setup contract: {self.harness}")
        return contract

    def setup_contract(self) -> HarnessSetupContract:
        return self._setup_contract

    def setup_steps(self) -> tuple[HarnessSetupStep, ...]:
        return self.setup_contract().setup_steps

    def verify_steps(self) -> tuple[HarnessSetupStep, ...]:
        return self.setup_contract().verify_steps

    def repair_steps(self) -> tuple[HarnessSetupStep, ...]:
        return self.setup_contract().repair_steps

    def coverage_summary(self) -> HarnessCoverageSummary:
        return self.setup_contract().coverage

    def resolved_executable(self, context: HarnessContext) -> str | None:
        del context
        return None

    def guard_launcher_paths(self, context: HarnessContext) -> tuple[Path, ...]:
        shim_name = self.launcher_name or self.harness
        shim_dir = context.guard_home / "bin"
        names = (shim_name, *self.legacy_launcher_names)
        return tuple(shim_dir / f"guard-{name}{suffix}" for name in names for suffix in ("", ".cmd"))

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        return [self.resolved_executable(context) or self.executable, *passthrough_args]

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        """Return every command the next launch preparation may select.

        Implementations must be side-effect free. Adapters whose
        ``launch_command`` is a pure argv constructor can inherit this default;
        adapters that perform setup while selecting an argv must override it.
        """

        return (self.launch_command(context, passthrough_args),)

    def launch_command_from_authorized_plan(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        """Finalize a command only after its preview plans were authorized.

        The default is suitable for adapters whose launch selection has no
        setup-time subprocess side effects. Adapters that execute their
        harness while preparing a launch must use the supplied canonical,
        content-bound executable prefix instead of resolving the executable
        again. ``launch_environment`` is the exact prepared environment whose
        digest participated in the authority comparison.
        """

        del authorized_executable_prefixes, launch_environment
        return self.launch_command(context, passthrough_args)

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".mcp.json"
        return context.home_dir / ".mcp.json"

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        del context
        return {}

    def prepare_launch_environment(
        self,
        context: HarnessContext,
        inherited: Mapping[str, str],
    ) -> dict[str, str]:
        """Return the environment used to launch this harness."""

        environment = dict(inherited)
        environment.update(self.launch_environment(context))
        return environment

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        return None

    def start_operation(
        self,
        context: HarnessContext,
        *,
        session_id: str,
        operation_type: str,
    ) -> dict[str, object]:
        return {
            "harness": self.harness,
            "session_id": session_id,
            "operation_type": operation_type,
            "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
        }

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        added = _harness_diagnostics(
            "warnings",
            lambda value: isinstance(value, list) and all(isinstance(item, str) for item in value),
            harness=self.harness,
            executable=self.executable,
            command_absence_proves_uninstalled=self.command_absence_proves_uninstalled,
            runtime_probe=None
            if runtime_probe is None
            else {
                "timed_out": runtime_probe.get("timed_out") is True,
                "failed": runtime_probe.get("ok") is False,
                "reported_no_artifacts": runtime_probe.get("reported_artifacts") == 0,
                "managed_install_present": runtime_probe.get("managed_install_present") is True,
                "runtime_hook_registered": runtime_probe.get("runtime_hook_registered") is True,
            },
            detection=_detection_request(detection),
        )
        return [*detection.warnings, *added]

    def approval_flow(self, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
        del managed_install
        return {
            "tier": self.approval_tier,
            "summary": self.approval_summary,
            "fallback_hint": self.fallback_hint,
            "prompt_channel": self.approval_prompt_channel,
            "auto_open_browser": self.approval_auto_open_browser,
        }

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        detection = self._detection_with_guard_launcher(context, self.detect(context))
        runtime_probe = self.runtime_probe(context)
        warnings = self.diagnostic_warnings(detection, runtime_probe)
        return {
            "harness": self.harness,
            "installed": detection.installed,
            "setup_status": _diagnostic_setup_status(
                detection,
                warnings,
                command_absence_proves_uninstalled=self.command_absence_proves_uninstalled,
            ),
            "command_available": detection.command_available,
            "config_paths": list(detection.config_paths),
            "artifacts": [artifact.to_dict() for artifact in detection.artifacts],
            "runtime_probe": runtime_probe,
            "warnings": warnings,
        }

    def _detection_with_guard_launcher(
        self,
        context: HarnessContext,
        detection: HarnessDetection,
    ) -> HarnessDetection:
        paths = self.guard_launcher_paths(context)
        index = _harness_diagnostics(
            "launcher_shim",
            lambda value: value is None or (type(value) is int and 0 <= value < len(paths)),
            paths=[str(path.absolute()) for path in paths],
        )
        if index is None:
            return detection
        shim_path = paths[index]
        artifact = GuardArtifact(
            artifact_id=f"{self.harness}:guard-launcher-shim",
            name=shim_path.name,
            harness=self.harness,
            artifact_type="guard_launcher_shim",
            source_scope="guard",
            config_path=str(shim_path),
            command=str(shim_path),
            metadata={"shim_dir": str(shim_path.parent)},
        )
        return HarnessDetection(
            harness=detection.harness,
            installed=True,
            command_available=detection.command_available,
            config_paths=detection.config_paths,
            artifacts=(*detection.artifacts, artifact),
            warnings=detection.warnings,
        )


# The native request parser refuses any JSON array wider than 4096 entries, so
# every list crosses in chunks that the runtime joins back in order.
_NATIVE_JSON_WIDTH = 4096
_SETUP_STATUSES = ("active", "broken", "partial", "not_found")


def _chunks(items: Sequence[_T]) -> list[list[_T]]:
    return [list(items[start : start + _NATIVE_JSON_WIDTH]) for start in range(0, len(items), _NATIVE_JSON_WIDTH)]


def _artifacts_request(artifacts: Sequence[GuardArtifact]) -> list[list[dict[str, object]]]:
    return _chunks(
        [
            {
                "artifact_type": artifact.artifact_type,
                "command": artifact.command,
                "args": _chunks(artifact.args),
                "harness": artifact.harness,
            }
            for artifact in artifacts
        ]
    )


def _detection_request(detection: HarnessDetection) -> dict[str, object]:
    return {
        "config_paths": _chunks(detection.config_paths),
        "command_available": detection.command_available,
        "artifacts": _artifacts_request(detection.artifacts),
    }


def _harness_diagnostics(op: str, valid: Callable[[object], bool], **fields: object) -> Any:
    """The native ``harness_diagnostics`` answer to ``op``, which it returns under the op's own name."""

    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    value = native_runner_authority("harness_diagnostics", {"op": op, **fields}).get(op)
    if not valid(value):
        raise NativeRunnerAuthorityError("harness diagnostics answer is malformed")
    return value


def _diagnostic_setup_status(
    detection: HarnessDetection,
    warnings: list[str],
    *,
    command_absence_proves_uninstalled: bool = True,
) -> str:
    return _harness_diagnostics(
        "setup_status",
        lambda value: value in _SETUP_STATUSES,
        command_absence_proves_uninstalled=command_absence_proves_uninstalled,
        detection=_detection_request(detection),
        warnings=_chunks(warnings),
    )


def artifacts_use_guard(artifacts: Sequence[GuardArtifact]) -> bool:
    """Whether any artifact is Guard's launcher, Guard's command, or a command line naming Guard."""

    if not artifacts:
        return False
    return _harness_diagnostics(
        "uses_guard", lambda value: isinstance(value, bool), artifacts=_artifacts_request(artifacts)
    )


__all__ = [
    "GuardArtifact",
    "HarnessAdapter",
    "HarnessContext",
    "_ensure_path_within_root",
    "_json_payload",
    "_run_command_probe",
    "artifacts_use_guard",
]

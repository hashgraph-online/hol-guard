"""Base harness adapter helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

from ..command_probes import _run_command_probe
from ..diagnostics_bridge import artifacts_use_guard, guard_warnings, native_diagnostics
from ..diagnostics_bridge import shell_command as _shell_command
from ..harness_context import HarnessContext, PreparedHarnessInstall
from ..models import GuardArtifact, HarnessDetection
from ..native_owned import owned_adapter_mutation
from ..setup_contracts import HarnessCoverageSummary, HarnessSetupContract, HarnessSetupStep, setup_contract_for

if TYPE_CHECKING:
    from ..inventory_contract import GuardAgentInventorySnapshot


class HarnessAdapter:
    """Common interface shared by harness adapters."""

    harness = ""
    aliases: tuple[str, ...] = ()
    executable = ""
    launcher_name = ""
    approval_tier = "approval-center"
    approval_summary = "Guard pauses the launch and routes approval through the local approval center."
    fallback_hint = "Use the Guard approval center or native harness prompt to resolve pending requests."
    approval_prompt_channel = "browser"
    approval_auto_open_browser = True

    @property
    def legacy_launcher_names(self) -> tuple[str, ...]:
        """Older launcher names an uninstall also removes."""
        return ()

    @property
    def command_absence_proves_uninstalled(self) -> bool:
        """Whether an unavailable command is enough to conclude the tool itself is gone.

        A harness whose Guard hooks keep running without its CLI answers False, so
        leftover configuration is never mistaken for an absent tool.
        """
        return True

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        # Apply the shared mutation contract to overrides as well as defaults.
        # Direct adapter callers must not bypass CLI transition ownership.
        if cls.__dict__.get("native_owned_mutation"):
            # The native runtime takes the locks, journals and publishes inside the one op.
            return
        for name in ("install", "uninstall"):
            method = cls.__dict__.get(name)
            if method is not None:
                setattr(cls, name, owned_adapter_mutation(method))

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

    @owned_adapter_mutation
    def install(self, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
        from ..shims import install_guard_shim

        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": shim_manifest["shim_path"],
            **shim_manifest,
        }

    @owned_adapter_mutation
    def uninstall(self, context: HarnessContext, *, surface: str | None = None) -> dict[str, object]:
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

    def _own_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str] | None:
        """The final warnings a harness words itself, or ``None`` for the ones Guard words."""

        del detection, runtime_probe
        return None

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        own = self._own_warnings(detection, runtime_probe)
        if own is not None:
            return own
        return guard_warnings(
            self.harness,
            self.executable,
            self.command_absence_proves_uninstalled,
            detection,
            runtime_probe,
        )

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
        detection = self.detect(context)
        runtime_probe = self.runtime_probe(context)
        return native_diagnostics(
            harness=self.harness,
            executable=self.executable,
            command_absence_proves_uninstalled=self.command_absence_proves_uninstalled,
            guard_home=context.guard_home,
            launcher_names=[self.launcher_name or self.harness, *self.legacy_launcher_names],
            detection=detection,
            runtime_probe=runtime_probe,
            warnings=self._own_warnings(detection, runtime_probe),
        )


__all__ = [
    "GuardArtifact",
    "HarnessAdapter",
    "HarnessContext",
    "_run_command_probe",
    "_shell_command",
    "artifacts_use_guard",
]

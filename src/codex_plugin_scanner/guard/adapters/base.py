"""Base harness adapter helpers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from ...path_support import resolves_within_root
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .contracts import HarnessCoverageSummary, HarnessSetupContract, HarnessSetupStep, setup_contract_for


@dataclass(frozen=True, slots=True)
class HarnessContext:
    """Paths used by harness adapters."""

    home_dir: Path
    workspace_dir: Path | None
    guard_home: Path


def _json_payload(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _command_available(command: str) -> bool:
    return shutil.which(command) is not None


def _resolve_command(command: str, candidates: tuple[Path, ...] = ()) -> str | None:
    resolved = shutil.which(command)
    if resolved is not None:
        return resolved
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _run_command_probe(command: list[str], timeout_seconds: int = 5) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return {
            "command": command,
            "ok": False,
            "return_code": None,
            "stdout": "",
            "stderr": "command not found",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "ok": False,
            "return_code": None,
            "stdout": (exc.stdout or "").strip(),
            "stderr": (exc.stderr or "").strip(),
            "timed_out": True,
        }
    return {
        "command": command,
        "ok": result.returncode == 0,
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def _ensure_path_within_root(root: Path, path: Path, *, label: str) -> None:
    if not resolves_within_root(root, path):
        raise ValueError(f"{label} settings path escapes the managed root")


class HarnessAdapter:
    """Common interface shared by harness adapters."""

    harness = ""
    aliases: tuple[str, ...] = ()
    executable = ""
    launcher_name = ""
    approval_tier = "approval-center"
    approval_summary = "Guard pauses the launch and routes approval through the local approval center."
    fallback_hint = "Use `hol-guard approvals` if you want to resolve it from the terminal."
    approval_prompt_channel = "browser"
    approval_auto_open_browser = True

    def detect(self, context: HarnessContext) -> HarnessDetection:
        raise NotImplementedError

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(self.harness, context)
        return {
            "harness": self.harness,
            "active": True,
            "config_path": shim_manifest["shim_path"],
            **shim_manifest,
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
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

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return ()

    def resolved_executable(self, context: HarnessContext) -> str | None:
        return _resolve_command(self.executable, self.executable_candidates(context))

    def guard_launcher_paths(self, context: HarnessContext) -> tuple[Path, ...]:
        shim_name = self.launcher_name or self.harness
        shim_dir = context.guard_home / "bin"
        return (shim_dir / f"guard-{shim_name}", shim_dir / f"guard-{shim_name}.cmd")

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        command = [self.resolved_executable(context) or self.executable]
        if context.workspace_dir is not None and self.harness in {"opencode", "claude-code"}:
            command.append(str(context.workspace_dir))
        return [*command, *passthrough_args]

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".mcp.json"
        return context.home_dir / ".mcp.json"

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        del context
        return {}

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        return None

    def attach_session(
        self,
        context: HarnessContext,
        *,
        session_id: str,
        client_name: str,
    ) -> dict[str, object]:
        return {
            "harness": self.harness,
            "session_id": session_id,
            "client_name": client_name,
            "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
        }

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

    def request_approval(
        self,
        context: HarnessContext,
        *,
        request_ids: list[str],
    ) -> dict[str, object]:
        return {
            "harness": self.harness,
            "request_ids": request_ids,
            "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
        }

    def continue_after_approval(
        self,
        context: HarnessContext,
        *,
        operation_id: str,
        approved: bool,
    ) -> dict[str, object]:
        return {
            "harness": self.harness,
            "operation_id": operation_id,
            "status": "completed" if approved else "blocked",
            "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
        }

    def diagnostic_warnings(
        self,
        detection: HarnessDetection,
        runtime_probe: dict[str, object] | None,
    ) -> list[str]:
        warnings = list(detection.warnings)
        if detection.config_paths and not _detection_has_guard_management(detection):
            warnings.append(
                f"{self.harness} config was found, but Guard is not installed for this harness. "
                f"Run `hol-guard install {self.harness}` to enable protection."
            )
        if detection.config_paths and not detection.command_available:
            warnings.append(
                f"{self.harness} config was found, but the {self.executable} command is not available on PATH."
            )
        if runtime_probe is not None and runtime_probe.get("timed_out") is True:
            warnings.append(f"{self.executable} diagnostics timed out before Guard could confirm runtime state.")
        return warnings

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
            "setup_status": _diagnostic_setup_status(detection, warnings),
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
        shim_path = next((path for path in self.guard_launcher_paths(context) if _is_guard_launcher_shim(path)), None)
        if shim_path is None:
            return detection
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


def _diagnostic_setup_status(detection: HarnessDetection, warnings: list[str]) -> str:
    guard_managed = _detection_has_guard_management(detection)
    if guard_managed and _warnings_include_setup_failure(warnings):
        return "broken"
    if guard_managed:
        return "active"
    if detection.config_paths or detection.command_available:
        return "partial"
    return "not_found"


def _detection_has_guard_management(detection: HarnessDetection) -> bool:
    if any(_guard_managed_path(path) for path in detection.config_paths):
        return True
    return any(_artifact_uses_guard(artifact) for artifact in detection.artifacts)


def _guard_managed_path(path: str) -> bool:
    return Path(path).name.lower().startswith("hol-guard")


def _artifact_uses_guard(artifact: GuardArtifact) -> bool:
    if artifact.artifact_type == "guard_launcher_shim":
        return True
    if artifact.command is not None and _is_guard_command_name(artifact.command, artifact.harness):
        return True
    values = [artifact.command or "", *artifact.args]
    return any(_value_mentions_guard(value) for value in values)


def _is_guard_command_name(value: str, harness: str) -> bool:
    normalized = Path(value.replace("\\", "/")).name.lower()
    if normalized.endswith(".cmd"):
        normalized = normalized[:-4]
    return normalized == f"guard-{harness}"


def _value_mentions_guard(value: str) -> bool:
    normalized = value.lower()
    return "codex_plugin_scanner.cli" in normalized or "hol-guard" in normalized


def _is_guard_launcher_shim(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        contents = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return "codex_plugin_scanner.cli" in contents and "guard" in contents and "run" in contents


def _warnings_include_setup_failure(warnings: list[str]) -> bool:
    setup_markers = (
        "guard is not installed",
        "command is not available",
        "native hooks are disabled",
        "managed codex hooks are missing",
    )
    return any(any(marker in warning.lower() for marker in setup_markers) for warning in warnings)


__all__ = [
    "GuardArtifact",
    "HarnessAdapter",
    "HarnessContext",
    "_command_available",
    "_ensure_path_within_root",
    "_json_payload",
    "_resolve_command",
    "_run_command_probe",
]

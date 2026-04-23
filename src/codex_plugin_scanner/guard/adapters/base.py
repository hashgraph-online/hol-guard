"""Base harness adapter helpers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ...path_support import resolves_within_root
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim


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

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        del context
        return ()

    def resolved_executable(self, context: HarnessContext) -> str | None:
        return _resolve_command(self.executable, self.executable_candidates(context))

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
        detection = self.detect(context)
        runtime_probe = self.runtime_probe(context)
        return {
            "harness": self.harness,
            "installed": detection.installed,
            "command_available": detection.command_available,
            "config_paths": list(detection.config_paths),
            "artifacts": [artifact.to_dict() for artifact in detection.artifacts],
            "runtime_probe": runtime_probe,
            "warnings": self.diagnostic_warnings(detection, runtime_probe),
        }


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

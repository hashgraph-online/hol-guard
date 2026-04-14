"""Base harness adapter helpers."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

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


class HarnessAdapter:
    """Common interface shared by harness adapters."""

    harness = ""
    executable = ""
    approval_tier = "approval-center"
    approval_summary = "Guard pauses the launch and routes approval through the local approval center."
    fallback_hint = "Use `hol-guard approvals` if you want to resolve it from the terminal."

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

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        command = [self.executable]
        if context.workspace_dir is not None and self.harness in {"opencode", "claude-code"}:
            command.append(str(context.workspace_dir))
        return [*command, *passthrough_args]

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        del context
        return {}

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        return None

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

    def approval_flow(self) -> dict[str, str]:
        return {
            "tier": self.approval_tier,
            "summary": self.approval_summary,
            "fallback_hint": self.fallback_hint,
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
    "_json_payload",
    "_run_command_probe",
]

"""Gemini harness adapter."""

from __future__ import annotations

from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection_with_warnings
from ..models import HarnessDetection
from .base import HarnessAdapter, HarnessContext, _command_available, detection_request


class GeminiHarnessAdapter(HarnessAdapter):
    """Discover Gemini CLI settings, extensions, hooks, skills, and MCP definitions."""

    harness = "gemini"
    executable = "gemini"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Gemini settings, extensions, hooks, skills, and MCP registrations "
        "before launch and sends blocked changes to the local approval center."
    )
    fallback_hint = "Gemini gets preflight approval through Guard until it exposes a richer native approval surface."

    def policy_path(self, context: HarnessContext) -> Path:
        if context.workspace_dir is not None:
            return context.workspace_dir / ".gemini" / "settings.json"
        return context.home_dir / ".gemini" / "settings.json"

    def detect(self, context: HarnessContext) -> HarnessDetection:
        artifacts, found_paths, warnings = native_adapter_detection_with_warnings(
            "gemini_detect", detection_request(self.harness, context)
        )
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=warnings,
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

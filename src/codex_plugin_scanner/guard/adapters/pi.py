"""Pi harness adapter for HOL Guard."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom, native_adapter_detection_with_warnings
from ..models import HarnessDetection
from ..shims import prepare_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, PreparedHarnessInstall, _resolve_command
from .omp_code_mode import with_omp_code_mode_warnings
from .pi_extension_previous_source import previous_managed_extension_source
from .pi_support import (
    OMP_AGENT_DIR,
    OMP_DIR,
    PI_AGENT_DIR,
    PI_DIR,
    PI_MANAGED_EXTENSION_NAME,
    PI_SETTINGS_FILE,
    disable_managed_extension,
    json_payload,
    managed_extension_settings,
    managed_extension_source,
)


class _PiFamilyHarnessAdapter(HarnessAdapter):
    """Shared Pi-extension behavior for Pi and Oh My Pi."""

    config_dir = PI_DIR
    global_config_dir = PI_AGENT_DIR
    display_name = "Pi"

    def approval_flow(self, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
        if isinstance(managed_install, dict) and bool(managed_install.get("active")):
            return {
                "tier": "approval-center",
                "summary": self.approval_summary,
                "fallback_hint": self.fallback_hint,
                "prompt_channel": "native-fallback",
                "auto_open_browser": True,
            }
        return {
            "tier": "approval-center",
            "summary": f"Guard routes {self.display_name} approvals through the local approval center.",
            "fallback_hint": f"Resolve pending {self.display_name} requests from the Guard approval center.",
            "prompt_channel": "browser",
            "auto_open_browser": True,
        }

    def _global_root(self, context: HarnessContext) -> Path:
        return context.home_dir / self.global_config_dir

    def _project_root(self, context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / self.config_dir

    def resolved_executable(self, context: HarnessContext) -> str | None:
        return _resolve_command(self.executable, self.executable_candidates(context))

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        # Linux package installers commonly place user-owned CLIs in a
        # user-local bin directory without exporting it to GUI-launched apps.
        # Resolve that durable install directly so diagnostics and Guard's
        # launcher agree with the command the user can run from a terminal.
        return (context.home_dir / ".local" / "bin" / self.executable,)

    def policy_path(self, context: HarnessContext) -> Path:
        project_root = self._project_root(context)
        if project_root is not None:
            return project_root / PI_SETTINGS_FILE
        return self._global_root(context) / PI_SETTINGS_FILE

    def _managed_extension_path(self, context: HarnessContext) -> Path:
        return self._global_root(context) / "extensions" / PI_MANAGED_EXTENSION_NAME

    def _managed_settings_path(self, context: HarnessContext) -> Path:
        return self._global_root(context) / PI_SETTINGS_FILE

    def detect(self, context: HarnessContext) -> HarnessDetection:
        roots = [(self._global_root(context), "global")]
        project_root = self._project_root(context)
        if project_root is not None:
            roots.append((project_root, "project"))
        request: dict[str, object] = {
            "harness": self.harness,
            "home": os.path.expanduser("~"),
            "roots": [
                {"path": str(root), "scope": scope, "id_scope": f"{self.harness}-{scope}"} for root, scope in roots
            ],
        }
        if not all(root.is_absolute() for root, _ in roots):
            request["cwd"] = os.getcwd()
        artifacts, found_paths, warnings = native_adapter_detection_with_warnings("pi_detect", request)
        command_available = self.resolved_executable(context) is not None
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=found_paths,
            artifacts=artifacts,
            warnings=warnings,
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    def prepare_install(self, context: HarnessContext) -> PreparedHarnessInstall:
        from ..codex_hook_recovery import _snapshot
        from ..runtime_transition import TransitionFile

        prepared_shim = prepare_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name=self.display_name,
        )
        shim_manifest = prepared_shim.manifest
        extension_path = self._managed_extension_path(context)
        settings_path = self._managed_settings_path(context)
        extension_before = _snapshot(extension_path)
        settings_before = _snapshot(settings_path)
        settings = json.loads(settings_before.decode("utf-8")) if settings_before is not None else {}
        if not isinstance(settings, dict):
            raise ValueError(f"{self.display_name} settings must be a JSON object.")
        extension_after = managed_extension_source(
            guard_home=context.guard_home,
            home_dir=context.home_dir,
            settings_path=settings_path,
            harness=self.harness,
            display_name=self.display_name,
        ).encode("utf-8")
        settings_after = managed_extension_settings(
            settings, settings_path=settings_path, extension_path=extension_path
        )
        files = list(prepared_shim.files)
        for path, before, after in (
            (extension_path, extension_before, extension_after),
            (settings_path, settings_before, settings_after),
        ):
            mode = path.stat().st_mode & 0o777 if before is not None else 0o644
            change = TransitionFile(path.resolve(strict=False), before, after, before_mode=mode, after_mode=mode)
            change.payload()
            files.append(change)
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        manifest: dict[str, object] = {
            "harness": self.harness,
            "active": True,
            "config_path": str(extension_path),
            **shim_manifest,
            "notes": [
                f"Guard installed a managed {self.display_name} extension that reviews prompts and tool calls before "
                f"{self.display_name} executes them.",
                *shim_notes,
            ],
        }
        return PreparedHarnessInstall(tuple(files), manifest)

    def install(self, context: HarnessContext) -> dict[str, object]:
        return self.prepare_install(context).publish(context.guard_home)

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name=self.display_name,
        )
        extension_path = self._managed_extension_path(context)
        disable_managed_extension(settings_path=self._managed_settings_path(context), extension_path=extension_path)
        if extension_path.exists():
            extension_path.unlink()
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(extension_path),
            **shim_manifest,
            "notes": [
                f"Guard removed the managed {self.display_name} extension and left your "
                f"{self.display_name} resources unchanged.",
                *shim_notes,
            ],
        }


class PiHarnessAdapter(_PiFamilyHarnessAdapter):
    """Protect Pi, the coding agent from dev.pi."""

    harness = "pi"
    aliases = ("pi", "pi-agent", "pi-coding-agent")
    executable = "pi"
    launcher_name = "pi"
    approval_summary = (
        "Guard scans Pi packages, extensions, skills, prompts, and themes before launch "
        "and uses a managed Pi extension to review prompts and tool calls inline."
    )
    fallback_hint = "Pi keeps the blocked request in Guard and shows the reason inline before you retry."

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        """Remove the verified combined-install OMP extension during legacy cleanup."""

        manifest = super().uninstall(context)
        if remove_legacy_omp_managed_extension(context):
            notes = manifest.get("notes")
            if isinstance(notes, list):
                notes.append("Guard also removed the verified legacy Oh My Pi extension from the combined Pi install.")
        return manifest


class OmpHarnessAdapter(_PiFamilyHarnessAdapter):
    """Protect Oh My Pi independently from Pi."""

    harness = "omp"
    aliases = ("omp", "oh-my-pi")
    executable = "omp"
    launcher_name = "omp"
    config_dir = OMP_DIR
    global_config_dir = OMP_AGENT_DIR
    display_name = "Oh My Pi"
    approval_summary = (
        "Guard scans Oh My Pi packages, extensions, skills, prompts, and themes before launch "
        "and uses a managed Oh My Pi extension to review prompts and tool calls inline."
    )
    fallback_hint = "Oh My Pi keeps the blocked request in Guard and shows the reason inline before you retry."

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        return with_omp_code_mode_warnings(super().diagnostics(context), context)


def _legacy_omp_managed_extension_sources(
    context: HarnessContext,
    settings_path: Path,
) -> tuple[str, ...]:
    return (
        managed_extension_source(
            guard_home=context.guard_home,
            home_dir=context.home_dir,
            settings_path=settings_path,
            harness="pi",
            display_name="Pi",
        ),
        previous_managed_extension_source(
            guard_home=context.guard_home,
            home_dir=context.home_dir,
            settings_path=settings_path,
            harness="pi",
            display_name="Pi",
        ),
    )


def legacy_omp_managed_extension_is_verified(
    context: HarnessContext,
    pi_managed_install: dict[str, object],
) -> bool:
    """Identify only the exact OMP extension written by the former combined Pi install."""

    if not bool(pi_managed_install.get("active")):
        return False
    manifest = pi_managed_install.get("manifest")
    if not isinstance(manifest, dict):
        return False
    pi_path = context.home_dir / PI_AGENT_DIR / "extensions" / PI_MANAGED_EXTENSION_NAME
    if manifest.get("config_path") != str(pi_path):
        return False
    omp_settings_path = context.home_dir / OMP_AGENT_DIR / PI_SETTINGS_FILE
    omp_extension_path = omp_settings_path.parent / "extensions" / PI_MANAGED_EXTENSION_NAME
    settings = json_payload(omp_settings_path)
    extensions = settings.get("extensions")
    if not isinstance(extensions, list) or str(omp_extension_path) not in extensions:
        return False
    try:
        source = omp_extension_path.read_text(encoding="utf-8")
    except OSError:
        return False
    expected_sources = _legacy_omp_managed_extension_sources(context, omp_settings_path)
    return source in expected_sources


def remove_legacy_omp_managed_extension(context: HarnessContext) -> bool:
    """Remove only a byte-for-byte legacy OMP extension after Pi disconnects."""

    omp_settings_path = context.home_dir / OMP_AGENT_DIR / PI_SETTINGS_FILE
    omp_extension_path = omp_settings_path.parent / "extensions" / PI_MANAGED_EXTENSION_NAME
    try:
        source = omp_extension_path.read_text(encoding="utf-8")
    except OSError:
        return False
    expected_sources = _legacy_omp_managed_extension_sources(context, omp_settings_path)
    if source not in expected_sources:
        return False
    disable_managed_extension(settings_path=omp_settings_path, extension_path=omp_extension_path)
    omp_extension_path.unlink()
    return True


__all__ = [
    "OmpHarnessAdapter",
    "PiHarnessAdapter",
    "legacy_omp_managed_extension_is_verified",
    "remove_legacy_omp_managed_extension",
]

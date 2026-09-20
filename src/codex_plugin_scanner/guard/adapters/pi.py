"""Pi harness adapter for HOL Guard."""

from __future__ import annotations

from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from . import pi_settings_discovery as _settings_discovery
from .base import HarnessAdapter, HarnessContext, _resolve_command
from .pi_support import (
    EXTENSION_SUFFIXES,
    OMP_AGENT_DIR,
    OMP_DIR,
    PI_AGENT_DIR,
    PI_DIR,
    PI_MANAGED_EXTENSION_NAME,
    PI_SETTINGS_FILE,
    THEME_SUFFIXES,
    append_artifact,
    append_found_path,
    artifact,
    disable_managed_extension,
    enable_managed_extension,
    managed_extension_source,
)
from .pi_support import json_payload as json_payload
from .pi_support import resolve_configured_paths as resolve_configured_paths
from .pi_support import stable_suffix as stable_suffix


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

    @staticmethod
    def _relative_label(root: Path, path: Path) -> str:
        return path.relative_to(root).as_posix()

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
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        seen_keys: set[str] = set()
        roots = [(self._global_root(context), "global", f"{self.harness}-global")]
        project_root = self._project_root(context)
        if project_root is not None:
            roots.append((project_root, "project", f"{self.harness}-project"))
        for root, scope, id_scope in roots:
            self._append_settings_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                settings_path=root / PI_SETTINGS_FILE,
                scope=scope,
                id_scope=id_scope,
                extension_root=root / "extensions",
                skill_root=root / "skills",
                prompt_root=root / "prompts",
                theme_root=root / "themes",
            )
            self._append_extension_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                extension_root=root / "extensions",
                scope=scope,
                id_scope=id_scope,
                id_root=root / "extensions",
            )
            self._append_skill_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                skill_root=root / "skills",
                scope=scope,
                id_scope=id_scope,
                id_root=root / "skills",
            )
            self._append_prompt_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                prompt_root=root / "prompts",
                scope=scope,
                id_scope=id_scope,
                id_root=root / "prompts",
            )
            self._append_theme_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                theme_root=root / "themes",
                scope=scope,
                id_scope=id_scope,
                id_root=root / "themes",
            )
        command_available = self.resolved_executable(context) is not None
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
            warnings=(),
        )
        return extend_detection_with_workspace_aibom(
            detection,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
        )

    _append_settings_artifacts = _settings_discovery._append_settings_artifacts
    _append_package_setting_artifacts = _settings_discovery._append_package_setting_artifacts
    _append_configured_resource_setting_artifacts = _settings_discovery._append_configured_resource_setting_artifacts

    def _append_extension_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        extension_root: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        if not extension_root.is_dir():
            return
        for path in sorted(extension_root.rglob("*")):
            if path.is_file() and path.suffix in EXTENSION_SUFFIXES:
                self._append_extension_file(artifacts, found_paths, seen_keys, path, scope, id_scope, id_root)

    def _append_extension_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative = self._relative_label(id_root, path)
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                harness=self.harness,
                artifact_id=f"{self.harness}:{id_scope}:extension:{relative}",
                name=relative,
                artifact_type="extension",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"extension:{id_scope}:{path.resolve()}",
        )

    def _append_skill_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        skill_root: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        if not skill_root.is_dir():
            return
        for skill_path in sorted(skill_root.rglob("SKILL.md")):
            self._append_skill_file(artifacts, found_paths, seen_keys, skill_path, scope, id_scope, id_root)

    def _append_skill_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative_parent = path.parent.relative_to(id_root).as_posix()
        relative = "skills" if relative_parent == "." else f"skills/{relative_parent}"
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                harness=self.harness,
                artifact_id=f"{self.harness}:{id_scope}:skill:{relative}",
                name=relative,
                artifact_type="skill",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"skill:{id_scope}:{path.resolve()}",
        )

    def _append_prompt_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        prompt_root: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        if not prompt_root.is_dir():
            return
        for prompt_path in sorted(prompt_root.rglob("*.md")):
            self._append_prompt_file(artifacts, found_paths, seen_keys, prompt_path, scope, id_scope, id_root)

    def _append_prompt_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative = self._relative_label(id_root, path)
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                harness=self.harness,
                artifact_id=f"{self.harness}:{id_scope}:prompt:{relative}",
                name=relative,
                artifact_type="prompt",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"prompt:{id_scope}:{path.resolve()}",
        )

    def _append_theme_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        theme_root: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        if not theme_root.is_dir():
            return
        for theme_path in sorted(theme_root.rglob("*")):
            if theme_path.is_file() and theme_path.suffix in THEME_SUFFIXES:
                self._append_theme_file(
                    artifacts,
                    found_paths,
                    seen_keys,
                    theme_path,
                    scope,
                    id_scope,
                    id_root,
                )

    def _append_theme_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative = self._relative_label(id_root, path)
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                harness=self.harness,
                artifact_id=f"{self.harness}:{id_scope}:theme:{relative}",
                name=relative,
                artifact_type="theme",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"theme:{id_scope}:{path.resolve()}",
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name=self.display_name,
        )
        extension_path = self._managed_extension_path(context)
        extension_path.parent.mkdir(parents=True, exist_ok=True)
        extension_path.write_text(
            managed_extension_source(
                guard_home=context.guard_home,
                home_dir=context.home_dir,
                settings_path=self._managed_settings_path(context),
                harness=self.harness,
                display_name=self.display_name,
            ),
            encoding="utf-8",
        )
        enable_managed_extension(
            settings_path=self._managed_settings_path(context),
            extension_path=extension_path,
        )
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
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

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name=self.display_name,
        )
        extension_path = self._managed_extension_path(context)
        disable_managed_extension(
            settings_path=self._managed_settings_path(context),
            extension_path=extension_path,
        )
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


__all__ = [
    "OmpHarnessAdapter",
    "PiHarnessAdapter",
]

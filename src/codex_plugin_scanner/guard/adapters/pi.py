"""Pi harness adapter for HOL Guard."""

from __future__ import annotations

from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
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
    json_payload,
    managed_extension_source,
    resolve_configured_paths,
    stable_suffix,
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

    @staticmethod
    def _relative_label(root: Path, path: Path) -> str:
        return path.relative_to(root).as_posix()

    def resolved_executable(self, context: HarnessContext) -> str | None:
        return _resolve_command(self.executable, self.executable_candidates(context))

    def executable_candidates(self, context: HarnessContext) -> tuple[Path, ...]:
        # Linux package installers commonly place user-owned CLIs in
        # ~/.local/bin without exporting that directory to GUI-launched apps.
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

    def _append_settings_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        settings_path: Path,
        scope: str,
        id_scope: str,
        extension_root: Path,
        skill_root: Path,
        prompt_root: Path,
        theme_root: Path,
    ) -> None:
        if not settings_path.is_file():
            return
        append_found_path(found_paths, settings_path)
        payload = json_payload(settings_path)
        self._append_package_setting_artifacts(artifacts, seen_keys, settings_path, payload, scope, id_scope)
        self._append_configured_resource_setting_artifacts(
            artifacts,
            found_paths,
            seen_keys,
            settings_path=settings_path,
            payload=payload,
            scope=scope,
            id_scope=id_scope,
            key="extensions",
            artifact_type="extension",
            default_root=extension_root,
        )
        self._append_configured_resource_setting_artifacts(
            artifacts,
            found_paths,
            seen_keys,
            settings_path=settings_path,
            payload=payload,
            scope=scope,
            id_scope=id_scope,
            key="skills",
            artifact_type="skill",
            default_root=skill_root,
        )
        self._append_configured_resource_setting_artifacts(
            artifacts,
            found_paths,
            seen_keys,
            settings_path=settings_path,
            payload=payload,
            scope=scope,
            id_scope=id_scope,
            key="prompts",
            artifact_type="prompt",
            default_root=prompt_root,
        )
        self._append_configured_resource_setting_artifacts(
            artifacts,
            found_paths,
            seen_keys,
            settings_path=settings_path,
            payload=payload,
            scope=scope,
            id_scope=id_scope,
            key="themes",
            artifact_type="theme",
            default_root=theme_root,
        )

    def _append_package_setting_artifacts(
        self,
        artifacts: list[GuardArtifact],
        seen_keys: set[str],
        settings_path: Path,
        payload: dict[str, object],
        scope: str,
        id_scope: str,
    ) -> None:
        values = payload.get("packages")
        if not isinstance(values, list):
            return
        for value in values:
            if not isinstance(value, str) or not value.strip():
                continue
            artifact_id = f"{self.harness}:{id_scope}:package:{stable_suffix(value)}"
            append_artifact(
                artifacts,
                seen_keys,
                artifact(
                    harness=self.harness,
                    artifact_id=artifact_id,
                    name=value,
                    artifact_type="package",
                    scope=scope,
                    path=settings_path,
                    metadata={"source": "settings.json", "key": "packages", "value": value},
                ),
                dedupe_key=artifact_id,
            )

    def _append_configured_resource_setting_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        settings_path: Path,
        payload: dict[str, object],
        scope: str,
        id_scope: str,
        key: str,
        artifact_type: str,
        default_root: Path,
    ) -> None:
        values = payload.get(key)
        if not isinstance(values, list):
            return
        for value in values:
            if not isinstance(value, str) or not value.strip():
                continue
            matches = resolve_configured_paths(settings_path, value)
            if not matches:
                artifact_id = f"{self.harness}:{id_scope}:{artifact_type}:configured:{stable_suffix(value)}"
                append_artifact(
                    artifacts,
                    seen_keys,
                    artifact(
                        harness=self.harness,
                        artifact_id=artifact_id,
                        name=value,
                        artifact_type=artifact_type,
                        scope=scope,
                        path=settings_path,
                        metadata={"source": "settings.json", "key": key, "value": value},
                    ),
                    dedupe_key=artifact_id,
                )
                continue
            for match in matches:
                if match.is_relative_to(default_root):
                    id_root = default_root
                else:
                    id_root = match if match.is_dir() else match.parent
                if artifact_type == "extension":
                    if match.is_dir():
                        self._append_extension_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            extension_root=match,
                            scope=scope,
                            id_scope=id_scope,
                            id_root=id_root,
                        )
                    elif match.suffix in EXTENSION_SUFFIXES:
                        self._append_extension_file(artifacts, found_paths, seen_keys, match, scope, id_scope, id_root)
                elif artifact_type == "skill":
                    if match.is_dir():
                        self._append_skill_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            skill_root=match,
                            scope=scope,
                            id_scope=id_scope,
                            id_root=id_root,
                        )
                    elif match.name == "SKILL.md":
                        self._append_skill_file(artifacts, found_paths, seen_keys, match, scope, id_scope, id_root)
                elif artifact_type == "prompt":
                    if match.is_dir():
                        self._append_prompt_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            prompt_root=match,
                            scope=scope,
                            id_scope=id_scope,
                            id_root=id_root,
                        )
                    elif match.suffix == ".md":
                        self._append_prompt_file(artifacts, found_paths, seen_keys, match, scope, id_scope, id_root)
                elif artifact_type == "theme":
                    if match.is_dir():
                        self._append_theme_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            theme_root=match,
                            scope=scope,
                            id_scope=id_scope,
                            id_root=id_root,
                        )
                    elif match.suffix in THEME_SUFFIXES:
                        self._append_theme_file(artifacts, found_paths, seen_keys, match, scope, id_scope, id_root)

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
                self._append_theme_file(artifacts, found_paths, seen_keys, theme_path, scope, id_scope, id_root)

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
        enable_managed_extension(settings_path=self._managed_settings_path(context), extension_path=extension_path)
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
    return source == managed_extension_source(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        settings_path=omp_settings_path,
        harness="pi",
        display_name="Pi",
    )


def remove_legacy_omp_managed_extension(context: HarnessContext) -> bool:
    """Remove only a byte-for-byte legacy OMP extension after Pi disconnects."""

    omp_settings_path = context.home_dir / OMP_AGENT_DIR / PI_SETTINGS_FILE
    omp_extension_path = omp_settings_path.parent / "extensions" / PI_MANAGED_EXTENSION_NAME
    try:
        source = omp_extension_path.read_text(encoding="utf-8")
    except OSError:
        return False
    expected_source = managed_extension_source(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        settings_path=omp_settings_path,
        harness="pi",
        display_name="Pi",
    )
    if source != expected_source:
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

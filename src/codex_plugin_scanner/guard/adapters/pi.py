"""Pi harness adapter for HOL Guard."""

from __future__ import annotations

from pathlib import Path

from ..aibom_detection import extend_detection_with_workspace_aibom
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import HarnessAdapter, HarnessContext, _command_available
from .pi_support import (
    EXTENSION_SUFFIXES,
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


class PiHarnessAdapter(HarnessAdapter):
    """Discover Pi settings, packages, extensions, skills, prompts, and themes."""

    harness = "pi"
    aliases = ("pi", "pi-agent", "pi-coding-agent")
    executable = "pi"
    launcher_name = "pi"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard scans Pi packages, extensions, skills, prompts, and themes before launch "
        "and uses a managed Pi extension to review prompts and tool calls inline."
    )
    fallback_hint = "Pi keeps the blocked request in Guard and shows the reason inline before you retry."

    @staticmethod
    def _global_root(context: HarnessContext) -> Path:
        return context.home_dir / PI_AGENT_DIR

    @staticmethod
    def _project_root(context: HarnessContext) -> Path | None:
        if context.workspace_dir is None:
            return None
        return context.workspace_dir / PI_DIR

    @staticmethod
    def _relative_label(root: Path, path: Path) -> str:
        return path.relative_to(root).as_posix()

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
        roots = [(self._global_root(context), "global")]
        project_root = self._project_root(context)
        if project_root is not None:
            roots.append((project_root, "project"))
        for root, scope in roots:
            self._append_settings_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                settings_path=root / PI_SETTINGS_FILE,
                scope=scope,
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
                id_root=root / "extensions",
            )
            self._append_skill_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                skill_root=root / "skills",
                scope=scope,
                id_root=root / "skills",
            )
            self._append_prompt_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                prompt_root=root / "prompts",
                scope=scope,
                id_root=root / "prompts",
            )
            self._append_theme_artifacts(
                artifacts,
                found_paths,
                seen_keys,
                theme_root=root / "themes",
                scope=scope,
                id_root=root / "themes",
            )
        detection = HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
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
        extension_root: Path,
        skill_root: Path,
        prompt_root: Path,
        theme_root: Path,
    ) -> None:
        if not settings_path.is_file():
            return
        append_found_path(found_paths, settings_path)
        payload = json_payload(settings_path)
        self._append_package_setting_artifacts(artifacts, seen_keys, settings_path, payload, scope)
        self._append_configured_resource_setting_artifacts(
            artifacts,
            found_paths,
            seen_keys,
            settings_path=settings_path,
            payload=payload,
            scope=scope,
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
    ) -> None:
        values = payload.get("packages")
        if not isinstance(values, list):
            return
        for value in values:
            if not isinstance(value, str) or not value.strip():
                continue
            artifact_id = f"pi:{scope}:package:{stable_suffix(value)}"
            append_artifact(
                artifacts,
                seen_keys,
                artifact(
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
                artifact_id = f"pi:{scope}:{artifact_type}:configured:{stable_suffix(value)}"
                append_artifact(
                    artifacts,
                    seen_keys,
                    artifact(
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
                            id_root=id_root,
                        )
                    elif match.suffix in EXTENSION_SUFFIXES:
                        self._append_extension_file(artifacts, found_paths, seen_keys, match, scope, id_root)
                elif artifact_type == "skill":
                    if match.is_dir():
                        self._append_skill_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            skill_root=match,
                            scope=scope,
                            id_root=id_root,
                        )
                    elif match.name == "SKILL.md":
                        self._append_skill_file(artifacts, found_paths, seen_keys, match, scope, id_root)
                elif artifact_type == "prompt":
                    if match.is_dir():
                        self._append_prompt_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            prompt_root=match,
                            scope=scope,
                            id_root=id_root,
                        )
                    elif match.suffix == ".md":
                        self._append_prompt_file(artifacts, found_paths, seen_keys, match, scope, id_root)
                elif artifact_type == "theme":
                    if match.is_dir():
                        self._append_theme_artifacts(
                            artifacts,
                            found_paths,
                            seen_keys,
                            theme_root=match,
                            scope=scope,
                            id_root=id_root,
                        )
                    elif match.suffix in THEME_SUFFIXES:
                        self._append_theme_file(artifacts, found_paths, seen_keys, match, scope, id_root)

    def _append_extension_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        extension_root: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        if not extension_root.is_dir():
            return
        for path in sorted(extension_root.rglob("*")):
            if path.is_file() and path.suffix in EXTENSION_SUFFIXES:
                self._append_extension_file(artifacts, found_paths, seen_keys, path, scope, id_root)

    def _append_extension_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative = self._relative_label(id_root, path)
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                artifact_id=f"pi:{scope}:extension:{relative}",
                name=relative,
                artifact_type="extension",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"extension:{path.resolve()}",
        )

    def _append_skill_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        skill_root: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        if not skill_root.is_dir():
            return
        for skill_path in sorted(skill_root.rglob("SKILL.md")):
            self._append_skill_file(artifacts, found_paths, seen_keys, skill_path, scope, id_root)

    def _append_skill_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative_parent = path.parent.relative_to(id_root).as_posix()
        relative = "skills" if relative_parent == "." else f"skills/{relative_parent}"
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                artifact_id=f"pi:{scope}:skill:{relative}",
                name=relative,
                artifact_type="skill",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"skill:{path.resolve()}",
        )

    def _append_prompt_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        prompt_root: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        if not prompt_root.is_dir():
            return
        for prompt_path in sorted(prompt_root.rglob("*.md")):
            self._append_prompt_file(artifacts, found_paths, seen_keys, prompt_path, scope, id_root)

    def _append_prompt_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative = self._relative_label(id_root, path)
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                artifact_id=f"pi:{scope}:prompt:{relative}",
                name=relative,
                artifact_type="prompt",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"prompt:{path.resolve()}",
        )

    def _append_theme_artifacts(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        *,
        theme_root: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        if not theme_root.is_dir():
            return
        for theme_path in sorted(theme_root.rglob("*")):
            if theme_path.is_file() and theme_path.suffix in THEME_SUFFIXES:
                self._append_theme_file(artifacts, found_paths, seen_keys, theme_path, scope, id_root)

    def _append_theme_file(
        self,
        artifacts: list[GuardArtifact],
        found_paths: list[str],
        seen_keys: set[str],
        path: Path,
        scope: str,
        id_root: Path,
    ) -> None:
        append_found_path(found_paths, path)
        relative = self._relative_label(id_root, path)
        append_artifact(
            artifacts,
            seen_keys,
            artifact(
                artifact_id=f"pi:{scope}:theme:{relative}",
                name=relative,
                artifact_type="theme",
                scope=scope,
                path=path,
            ),
            dedupe_key=f"theme:{path.resolve()}",
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="pi",
        )
        extension_path = self._managed_extension_path(context)
        extension_path.parent.mkdir(parents=True, exist_ok=True)
        extension_path.write_text(
            managed_extension_source(guard_home=context.guard_home, home_dir=context.home_dir),
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
                "Guard installed a managed Pi extension that reviews prompts and tool calls before Pi executes them.",
                *shim_notes,
            ],
        }

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(
            self.harness,
            context,
            launcher_name=self.launcher_name,
            display_name="pi",
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
                "Guard removed the managed Pi extension and left your Pi resources unchanged.",
                *shim_notes,
            ],
        }


__all__ = ["PiHarnessAdapter"]

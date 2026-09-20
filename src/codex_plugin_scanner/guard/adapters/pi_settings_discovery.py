"""Settings-driven package and resource discovery for the Pi adapter family."""

from __future__ import annotations


def _append_settings_artifacts(
    self: _pi._PiFamilyHarnessAdapter,
    artifacts: list[_pi.GuardArtifact],
    found_paths: list[str],
    seen_keys: set[str],
    *,
    settings_path: _pi.Path,
    scope: str,
    id_scope: str,
    extension_root: _pi.Path,
    skill_root: _pi.Path,
    prompt_root: _pi.Path,
    theme_root: _pi.Path,
) -> None:
    if not settings_path.is_file():
        return
    _pi.append_found_path(found_paths, settings_path)
    payload = _pi.json_payload(settings_path)
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
    self: _pi._PiFamilyHarnessAdapter,
    artifacts: list[_pi.GuardArtifact],
    seen_keys: set[str],
    settings_path: _pi.Path,
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
        artifact_id = f"{self.harness}:{id_scope}:package:{_pi.stable_suffix(value)}"
        _pi.append_artifact(
            artifacts,
            seen_keys,
            _pi.artifact(
                harness=self.harness,
                artifact_id=artifact_id,
                name=value,
                artifact_type="package",
                scope=scope,
                path=settings_path,
                metadata={
                    "source": "settings.json",
                    "key": "packages",
                    "value": value,
                },
            ),
            dedupe_key=artifact_id,
        )


def _append_configured_resource_setting_artifacts(
    self: _pi._PiFamilyHarnessAdapter,
    artifacts: list[_pi.GuardArtifact],
    found_paths: list[str],
    seen_keys: set[str],
    *,
    settings_path: _pi.Path,
    payload: dict[str, object],
    scope: str,
    id_scope: str,
    key: str,
    artifact_type: str,
    default_root: _pi.Path,
) -> None:
    values = payload.get(key)
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        matches = _pi.resolve_configured_paths(settings_path, value)
        if not matches:
            artifact_id = f"{self.harness}:{id_scope}:{artifact_type}:configured:{_pi.stable_suffix(value)}"
            _pi.append_artifact(
                artifacts,
                seen_keys,
                _pi.artifact(
                    harness=self.harness,
                    artifact_id=artifact_id,
                    name=value,
                    artifact_type=artifact_type,
                    scope=scope,
                    path=settings_path,
                    metadata={
                        "source": "settings.json",
                        "key": key,
                        "value": value,
                    },
                ),
                dedupe_key=artifact_id,
            )
            continue
        for match in matches:
            if match.is_relative_to(default_root):
                id_root = default_root
            elif match.is_dir():
                id_root = match
            else:
                id_root = match.parent
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
                elif match.suffix in _pi.EXTENSION_SUFFIXES:
                    self._append_extension_file(
                        artifacts,
                        found_paths,
                        seen_keys,
                        match,
                        scope,
                        id_scope,
                        id_root,
                    )
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
                    self._append_skill_file(
                        artifacts,
                        found_paths,
                        seen_keys,
                        match,
                        scope,
                        id_scope,
                        id_root,
                    )
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
                    self._append_prompt_file(
                        artifacts,
                        found_paths,
                        seen_keys,
                        match,
                        scope,
                        id_scope,
                        id_root,
                    )
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
                elif match.suffix in _pi.THEME_SUFFIXES:
                    self._append_theme_file(
                        artifacts,
                        found_paths,
                        seen_keys,
                        match,
                        scope,
                        id_scope,
                        id_root,
                    )


# Resolve the original facade after these functions exist so either import order works.
from . import pi as _pi  # noqa: E402

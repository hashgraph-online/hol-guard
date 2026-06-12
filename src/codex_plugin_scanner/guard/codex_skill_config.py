"""Codex skill enablement rules from config.toml `[[skills.config]]` entries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:  # pragma: no cover - Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True, slots=True)
class CodexSkillConfigRule:
    enabled: bool
    name: str | None = None
    path: str | None = None


def _read_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
        return payload if isinstance(payload, dict) else {}
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _normalize_rule_entry(entry: object, *, base_dir: Path) -> CodexSkillConfigRule | None:
    if not isinstance(entry, dict):
        return None
    enabled_value = entry.get("enabled")
    if enabled_value is None:
        return None
    enabled = enabled_value is not False
    path_value = entry.get("path")
    name_value = entry.get("name")
    raw_path = path_value.strip() if isinstance(path_value, str) and path_value.strip() else None
    name = name_value.strip() if isinstance(name_value, str) and name_value.strip() else None
    path = _normalize_match_path(raw_path, base_dir=base_dir) if raw_path is not None else None
    if path is None and name is None:
        return None
    return CodexSkillConfigRule(enabled=enabled, name=name, path=path)


def _rules_from_payload(payload: dict[str, object], *, base_dir: Path) -> tuple[CodexSkillConfigRule, ...]:
    skills = payload.get("skills")
    if not isinstance(skills, dict):
        return ()
    config_entries = skills.get("config")
    if not isinstance(config_entries, list):
        return ()
    rules: list[CodexSkillConfigRule] = []
    for entry in config_entries:
        rule = _normalize_rule_entry(entry, base_dir=base_dir)
        if rule is not None:
            rules.append(rule)
    return tuple(rules)


def load_codex_skill_config_rules(
    *,
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[CodexSkillConfigRule, ...]:
    """Load merged Codex skill rules with later config layers overriding earlier ones."""

    merged: list[CodexSkillConfigRule] = []
    merged.extend(_rules_from_payload(_read_toml(home_dir / ".codex" / "config.toml"), base_dir=home_dir))
    if workspace_dir is not None:
        merged.extend(_rules_from_payload(_read_toml(workspace_dir / ".codex" / "config.toml"), base_dir=workspace_dir))
    return tuple(merged)


def _normalize_match_path(value: str, *, base_dir: Path) -> str:
    candidate = Path(value).expanduser()
    candidate = (base_dir / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    return candidate.as_posix()


def resolve_codex_skill_enabled(
    *,
    config_path: str,
    display_name: str,
    rules: tuple[CodexSkillConfigRule, ...],
    home_dir: Path,
) -> bool:
    if not rules:
        return True
    skill_path = Path(config_path).expanduser()
    skill_path = (home_dir / skill_path).resolve() if not skill_path.is_absolute() else skill_path.resolve()
    skill_dir_path = skill_path.parent.as_posix()
    normalized_skill_path = skill_path.as_posix()
    normalized_name = display_name.strip().lower()
    resolved: bool | None = None
    for rule in rules:
        if rule.path is not None and (
            normalized_skill_path == rule.path
            or skill_dir_path == rule.path
            or normalized_skill_path.endswith(rule.path)
            or skill_dir_path.endswith(rule.path)
        ):
            resolved = rule.enabled
            continue
        if rule.name is not None and rule.name.strip().lower() == normalized_name:
            resolved = rule.enabled
    return True if resolved is None else resolved

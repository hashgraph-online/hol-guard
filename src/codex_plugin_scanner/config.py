"""Configuration loading for the scanner."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    profile: str | None = None
    enabled_rules: frozenset[str] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    baseline_file: str | None = None
    severity_overrides: dict[str, str] | None = None
    ignore_paths: tuple[str, ...] = ()


DEFAULT_CONFIG_FILES = (".plugin-scanner.toml", ".codex-plugin-scanner.toml")


class ConfigError(ValueError):
    """Raised when config or baseline parsing fails."""


def load_scanner_config(plugin_dir: Path, config_path: str | None = None) -> ScannerConfig:
    if config_path:
        candidate = Path(config_path)
        if not candidate.is_absolute():
            candidate = plugin_dir / candidate
        if not candidate.exists():
            raise ConfigError(f"Config file '{candidate}' does not exist.")
    else:
        candidate = next((plugin_dir / name for name in DEFAULT_CONFIG_FILES if (plugin_dir / name).exists()), None)
        if candidate is None:
            return ScannerConfig()

    try:
        payload = tomllib.loads(candidate.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - parser-specific errors
        raise ConfigError(f"Failed to parse config '{candidate}': {exc}") from exc

    scanner = payload.get("scanner", {})
    rules = payload.get("rules", {})

    return ScannerConfig(
        profile=scanner.get("profile"),
        enabled_rules=frozenset(str(rule_id) for rule_id in rules.get("enabled", [])),
        disabled_rules=frozenset(str(rule_id) for rule_id in rules.get("disabled", [])),
        baseline_file=scanner.get("baseline_file"),
        severity_overrides={str(k): str(v) for k, v in rules.get("severity_overrides", {}).items()},
        ignore_paths=tuple(str(path) for path in scanner.get("ignore_paths", [])),
    )


def load_baseline_rule_ids(plugin_dir: Path, baseline_path: str | None) -> frozenset[str]:
    if not baseline_path:
        return frozenset()
    path = Path(baseline_path)
    if not path.is_absolute():
        path = plugin_dir / path
    if not path.exists():
        return frozenset()

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return frozenset()

    if content.startswith("["):
        import json

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Failed to parse baseline '{path}': {exc}") from exc
        return frozenset(str(rule_id) for rule_id in parsed)

    return frozenset(line.strip() for line in content.splitlines() if line.strip())

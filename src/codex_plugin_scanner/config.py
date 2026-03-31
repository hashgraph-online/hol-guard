"""Configuration loading for codex-plugin-scanner."""

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


DEFAULT_CONFIG_FILE = ".codex-plugin-scanner.toml"


def load_scanner_config(plugin_dir: Path, config_path: str | None = None) -> ScannerConfig:
    candidate = Path(config_path) if config_path else plugin_dir / DEFAULT_CONFIG_FILE
    if not candidate.exists():
        return ScannerConfig()

    payload = tomllib.loads(candidate.read_text(encoding="utf-8"))
    scanner = payload.get("scanner", {})
    rules = payload.get("rules", {})

    return ScannerConfig(
        profile=scanner.get("profile"),
        enabled_rules=frozenset(str(rule_id) for rule_id in rules.get("enabled", [])),
        disabled_rules=frozenset(str(rule_id) for rule_id in rules.get("disabled", [])),
        baseline_file=scanner.get("baseline_file"),
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

        parsed = json.loads(content)
        return frozenset(str(rule_id) for rule_id in parsed)

    return frozenset(line.strip() for line in content.splitlines() if line.strip())

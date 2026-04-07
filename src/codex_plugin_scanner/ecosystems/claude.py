"""Claude Code ecosystem adapter."""

from __future__ import annotations

import json
from pathlib import Path

from .types import Ecosystem, NormalizedPackage, PackageCandidate

IGNORED_DIRS = {"node_modules", ".git", ".venv", "venv", "dist", "__pycache__"}


def _iter_files(root: Path, pattern: str) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob(pattern):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            files.append(path)
    return files


def _load_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except (json.JSONDecodeError, OSError):
        pass
    return {}


class ClaudeAdapter:
    """Adapter for Claude Code plugins and marketplaces."""

    ecosystem_id = Ecosystem.CLAUDE

    def detect(self, root: Path) -> list[PackageCandidate]:
        candidates: list[PackageCandidate] = []
        for manifest_path in _iter_files(root, "plugin.json"):
            if manifest_path.parent.name != ".claude-plugin":
                continue
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.CLAUDE,
                    package_kind="single-plugin",
                    root_path=manifest_path.parent.parent,
                    manifest_path=manifest_path,
                    detection_reason="found .claude-plugin/plugin.json",
                )
            )
        for manifest_path in _iter_files(root, "marketplace.json"):
            if manifest_path.parent.name != ".claude-plugin":
                continue
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.CLAUDE,
                    package_kind="marketplace",
                    root_path=manifest_path.parent.parent,
                    manifest_path=manifest_path,
                    detection_reason="found .claude-plugin/marketplace.json",
                )
            )
        return candidates

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        manifest = _load_json(candidate.manifest_path) if candidate.manifest_path else {}
        root = candidate.root_path
        components: dict[str, tuple[str, ...]] = {}
        commands_dir = root / "commands"
        agents_dir = root / "agents"
        skills_dir = root / "skills"
        hooks_file = root / "hooks" / "hooks.json"
        mcp_file = root / ".mcp.json"
        if commands_dir.is_dir():
            components["commands"] = tuple(
                sorted(str(path.relative_to(root)) for path in commands_dir.rglob("*.md") if path.is_file())
            )
        if agents_dir.is_dir():
            components["agents"] = tuple(
                sorted(str(path.relative_to(root)) for path in agents_dir.rglob("*.md") if path.is_file())
            )
        if skills_dir.is_dir():
            components["skills"] = tuple(
                sorted(str(path.relative_to(root)) for path in skills_dir.rglob("SKILL.md") if path.is_file())
            )
        if hooks_file.is_file():
            components["hooks"] = (str(hooks_file.relative_to(root)),)
        if mcp_file.is_file():
            components["mcp_servers"] = (str(mcp_file.relative_to(root)),)

        strict_mode = manifest.get("strict")
        policies: dict[str, str] = {}
        if isinstance(strict_mode, bool):
            policies["strict"] = "true" if strict_mode else "false"

        return NormalizedPackage(
            ecosystem=Ecosystem.CLAUDE,
            package_kind=candidate.package_kind,
            root_path=root,
            manifest_path=candidate.manifest_path,
            name=manifest.get("name") if isinstance(manifest.get("name"), str) else None,
            version=manifest.get("version") if isinstance(manifest.get("version"), str) else None,
            metadata={
                key: value
                for key in ("description", "homepage", "repository", "license")
                if isinstance((value := manifest.get(key)), str)
            },
            components=components,
            policies=policies,
            raw_manifest=manifest,
        )

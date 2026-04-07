"""Codex ecosystem adapter."""

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


class CodexAdapter:
    """Adapter for Codex plugin repositories."""

    ecosystem_id = Ecosystem.CODEX

    def detect(self, root: Path) -> list[PackageCandidate]:
        candidates: list[PackageCandidate] = []
        for manifest_path in _iter_files(root, "plugin.json"):
            if manifest_path.parent.name != ".codex-plugin":
                continue
            package_root = manifest_path.parent.parent
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.CODEX,
                    package_kind="single-plugin",
                    root_path=package_root,
                    manifest_path=manifest_path,
                    detection_reason="found .codex-plugin/plugin.json",
                )
            )
        for marketplace_path in _iter_files(root, "marketplace.json"):
            package_root = None
            if marketplace_path.parent.name == "plugins" and marketplace_path.parent.parent.name == ".agents":
                package_root = marketplace_path.parent.parent.parent
            elif (
                marketplace_path.parent == root or (marketplace_path.parent / ".codex-plugin" / "plugin.json").exists()
            ):
                package_root = marketplace_path.parent
            if package_root is None:
                continue
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.CODEX,
                    package_kind="marketplace",
                    root_path=package_root,
                    manifest_path=marketplace_path,
                    detection_reason="found Codex marketplace manifest",
                )
            )
        return candidates

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        manifest = _load_json(candidate.manifest_path) if candidate.manifest_path else {}
        skills_path = manifest.get("skills")
        components: dict[str, tuple[str, ...]] = {}
        if isinstance(skills_path, str) and skills_path.strip():
            components["skills"] = (skills_path,)
        return NormalizedPackage(
            ecosystem=Ecosystem.CODEX,
            package_kind=candidate.package_kind,
            root_path=candidate.root_path,
            manifest_path=candidate.manifest_path,
            name=manifest.get("name") if isinstance(manifest.get("name"), str) else None,
            version=manifest.get("version") if isinstance(manifest.get("version"), str) else None,
            metadata={
                key: value
                for key in ("description", "license", "homepage", "repository")
                if isinstance((value := manifest.get(key)), str)
            },
            components=components,
            raw_manifest=manifest,
        )

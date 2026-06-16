"""Gemini CLI ecosystem adapter."""

from __future__ import annotations

import json
from pathlib import Path

from .base import iter_safe_recursive_files
from .types import Ecosystem, NormalizedPackage, PackageCandidate


def _load_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict):
            return payload
    except (json.JSONDecodeError, OSError):
        pass
    return {}


class GeminiAdapter:
    """Adapter for Gemini CLI extensions."""

    ecosystem_id = Ecosystem.GEMINI

    def detect(self, root: Path) -> list[PackageCandidate]:
        candidates: list[PackageCandidate] = []
        for manifest_path in iter_safe_recursive_files(root, root, "gemini-extension.json"):
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.GEMINI,
                    package_kind="extension",
                    root_path=manifest_path.parent,
                    manifest_path=manifest_path,
                    detection_reason="found gemini-extension.json",
                )
            )
        return candidates

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        manifest = _load_json(candidate.manifest_path) if candidate.manifest_path else {}
        root = candidate.root_path
        commands_dir = root / "commands"
        components: dict[str, tuple[str, ...]] = {}
        if commands_dir.is_dir():
            components["commands"] = tuple(
                str(path.relative_to(root)) for path in iter_safe_recursive_files(root, commands_dir, "*.toml")
            )
        mcp_servers = manifest.get("mcpServers")
        if isinstance(mcp_servers, dict):
            components["mcp_servers"] = tuple(sorted(str(key) for key in mcp_servers))
        context_file = manifest.get("contextFileName")
        if isinstance(context_file, str) and context_file.strip():
            components["context_files"] = (context_file,)
        raw_name = manifest.get("name")
        raw_version = manifest.get("version")

        return NormalizedPackage(
            ecosystem=Ecosystem.GEMINI,
            package_kind=candidate.package_kind,
            root_path=root,
            manifest_path=candidate.manifest_path,
            name=raw_name if isinstance(raw_name, str) else None,
            version=raw_version if isinstance(raw_version, str) else None,
            metadata={
                key: value for key in ("description", "publisher") if isinstance((value := manifest.get(key)), str)
            },
            components=components,
            raw_manifest=manifest,
        )

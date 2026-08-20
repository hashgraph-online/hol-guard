"""DeepSeek Harness (DSH/Cordis) ecosystem adapter."""

from __future__ import annotations

import json
from pathlib import Path

from .base import iter_safe_recursive_files
from .types import Ecosystem, NormalizedPackage, PackageCandidate


def _load_json(path: Path) -> tuple[dict[str, object], str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeError) as exc:
        return {}, str(exc)
    if not isinstance(payload, dict):
        return {}, "package.json must contain a JSON object"
    return payload, None


class DeepSeekHarnessAdapter:
    """Adapter for native DeepSeek Harness packages declared with ``package.json.dsh``."""

    ecosystem_id = Ecosystem.DEEPSEEK_HARNESS

    def detect(self, root: Path) -> list[PackageCandidate]:
        candidates: list[PackageCandidate] = []
        for manifest_path in iter_safe_recursive_files(root, root, "package.json"):
            manifest, error = _load_json(manifest_path)
            if error is not None:
                continue
            dsh = manifest.get("dsh")
            if not isinstance(dsh, dict) or not isinstance(dsh.get("bundle"), dict):
                continue
            candidates.append(
                PackageCandidate(
                    ecosystem=Ecosystem.DEEPSEEK_HARNESS,
                    package_kind="cordis-plugin",
                    root_path=manifest_path.parent,
                    manifest_path=manifest_path,
                    detection_reason="found package.json with dsh.bundle",
                )
            )
        return candidates

    def parse(self, candidate: PackageCandidate) -> NormalizedPackage:
        manifest, error = _load_json(candidate.manifest_path) if candidate.manifest_path else ({}, "missing manifest")
        dsh = manifest.get("dsh") if isinstance(manifest.get("dsh"), dict) else {}
        bundle = dsh.get("bundle") if isinstance(dsh, dict) and isinstance(dsh.get("bundle"), dict) else {}
        components: dict[str, tuple[str, ...]] = {}
        patch = bundle.get("patch") if isinstance(bundle, dict) else None
        if isinstance(patch, str) and patch.strip():
            components["bundle_patches"] = (patch,)
        client = dsh.get("client") if isinstance(dsh, dict) else None
        if isinstance(client, str) and client.strip():
            components["clients"] = (client,)
        return NormalizedPackage(
            ecosystem=Ecosystem.DEEPSEEK_HARNESS,
            package_kind=candidate.package_kind,
            root_path=candidate.root_path,
            manifest_path=candidate.manifest_path,
            name=manifest.get("name") if isinstance(manifest.get("name"), str) else None,
            version=manifest.get("version") if isinstance(manifest.get("version"), str) else None,
            metadata={
                key: value
                for key in ("description", "license", "homepage")
                if isinstance((value := manifest.get(key)), str)
            },
            components=components,
            raw_manifest=manifest,
            manifest_parse_error=error is not None,
            manifest_parse_error_reason=error,
        )

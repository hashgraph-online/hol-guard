"""Marketplace discovery and schema helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .path_support import is_dot_relative_path, is_remote_reference, is_safe_relative_path

PREFERRED_MARKETPLACE_PATH = Path(".agents/plugins/marketplace.json")
LEGACY_MARKETPLACE_PATH = Path("marketplace.json")


@dataclass(frozen=True, slots=True)
class MarketplaceContext:
    file_path: Path
    repo_root: Path
    marketplace_root: Path
    payload: dict
    legacy: bool


def find_marketplace_file(repo_root: Path) -> tuple[Path, bool] | None:
    preferred = repo_root / PREFERRED_MARKETPLACE_PATH
    if preferred.exists():
        return preferred, False
    legacy = repo_root / LEGACY_MARKETPLACE_PATH
    if legacy.exists():
        return legacy, True
    return None


def load_marketplace_context(repo_root: Path) -> MarketplaceContext | None:
    marketplace_file = find_marketplace_file(repo_root)
    if marketplace_file is None:
        return None
    file_path, legacy = marketplace_file
    resolved_repo_root = repo_root.resolve()
    resolved_file_path = file_path.resolve()
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("marketplace payload must be an object")
    return MarketplaceContext(
        file_path=resolved_file_path,
        repo_root=resolved_repo_root,
        marketplace_root=resolved_file_path.parent,
        payload=payload,
        legacy=legacy,
    )


def marketplace_label(context: MarketplaceContext) -> str:
    return str(context.file_path.relative_to(context.repo_root))


def extract_marketplace_source(plugin: dict) -> tuple[str | None, str | None]:
    source = plugin.get("source")
    if isinstance(source, str):
        return source, None
    if isinstance(source, dict):
        source_ref = source.get("source")
        source_path = source.get("path")
        normalized_source_ref = source_ref if isinstance(source_ref, str) and source_ref else None
        normalized_source_path = source_path if isinstance(source_path, str) and source_path else None
        return normalized_source_ref, normalized_source_path
    return None, None


def source_path_is_safe(context: MarketplaceContext, source_path: str) -> bool:
    return is_safe_relative_path(context.repo_root, source_path, require_prefix=True)


def source_reference_is_safe(context: MarketplaceContext, source_ref: str) -> bool:
    if source_ref == "local":
        return True
    if is_remote_reference(source_ref):
        return True
    if urlparse(source_ref).scheme:
        return False
    return is_safe_relative_path(context.repo_root, source_ref)


def validate_marketplace_path_requirements(context: MarketplaceContext, plugin: dict) -> str | None:
    source_ref, source_path = extract_marketplace_source(plugin)
    if source_ref is None:
        return 'missing "source.source"'
    if not source_reference_is_safe(context, source_ref):
        return f'"source.source" is unsafe: {source_ref}'
    if is_remote_reference(source_ref):
        if source_path is None:
            return None
    elif source_path is None:
        return 'missing "source.path"'
    if source_path is not None and not is_dot_relative_path(source_path):
        return f'"source.path" must start with "./": {source_path}'
    if source_path is not None and not source_path_is_safe(context, source_path):
        return f'"source.path" escapes the repository root: {source_path}'
    return None

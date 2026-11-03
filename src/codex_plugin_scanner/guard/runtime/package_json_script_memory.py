"""Remember package.json projects locally and redact paths on public payloads.

Which projects are remembered, their workspace packages, whether a listed item
is still shown, and the directory a paste is read in are decided by the native
``package_script_memory`` kind. Python keeps the store calls and the redaction.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .package_json_scripts import (
    PackageJsonScriptsDiscovery,
    looks_like_package_script_paste,
    recognize_package_json_scripts,
)

_SURFACE = "package-scripts"
_PUBLIC_SOURCE = "user-tool"
_PATH_CLASS_TOKENS = frozenset({"unknown", "package-store", "system-bin", "user-tool"})


def _ask(op: str, **fields: Any) -> dict[str, Any]:
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        return native_runner_authority("package_script_memory", {"op": op, "cwd": os.getcwd(), **fields})
    except NativeRunnerAuthorityError as exc:
        raise RuntimeError("Package script memory requires the HOL Guard native runtime") from exc


def _entries(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{key: item.get(key) for key in ("surface", "source_path", "state")} for item in items]


def operator_working_directory(payload: dict[str, object], *, home_dir: Path) -> Path:
    raw = payload.get("cwd")
    requested = None
    if isinstance(raw, str) and raw.strip():
        requested = os.path.join(os.getcwd(), os.path.expanduser(raw.strip()))
    chosen = _ask("operator_cwd", home=str(home_dir.absolute()), requested=requested).get("path")
    if not isinstance(chosen, str):
        raise RuntimeError("HOL Guard native runtime returned a malformed working directory")
    return Path(chosen)


def package_items_available(items: list[dict[str, object]]) -> list[bool]:
    """Whether each listed item is still shown; package scripts drop out once their manifest is gone."""

    available = _ask("available", entries=_entries(items)).get("available")
    if not isinstance(available, list) or len(available) != len(items):
        raise RuntimeError("HOL Guard native runtime returned a malformed availability list")
    return [value is True for value in available]


def public_local_cli_item(item: dict[str, object]) -> dict[str, object]:
    """Redact package paths and keep MCP overview payloads metadata-only."""

    if item.get("surface") == "mcp":
        public = dict(item)
        catalog = public.get("mcp_catalog")
        if isinstance(catalog, dict):
            public_catalog = {
                key: value for key, value in catalog.items() if key not in {"tools", "server_info", "capabilities"}
            }
            skills = public_catalog.get("skills_catalog")
            if isinstance(skills, dict):
                public_catalog["skills_catalog"] = {key: value for key, value in skills.items() if key != "entries"}
            public["mcp_catalog"] = public_catalog
        return public
    if item.get("surface") != _SURFACE:
        return item
    public = dict(item)
    raw = public.get("source_path")
    label = public.get("source_label")
    if not isinstance(label, str) or not label.strip():
        folder = _folder_label(raw if isinstance(raw, str) else None)
        if folder:
            public["source_label"] = folder
    public["source_path"] = _PUBLIC_SOURCE
    return public


def refresh_package_script_catalogs(store: object, *, home_dir: Path) -> list[dict[str, object]]:
    """Refresh remembered project catalogs and return path-redacted list items."""

    from ..local_cli_trust import utc_now

    items = _listed_items(store)
    known: dict[str, tuple[str | None, str | None]] = {}
    for item in items:
        cli_id = item.get("cli_id")
        if not isinstance(cli_id, str):
            continue
        raw_path = item.get("source_path")
        raw_hash = item.get("identity_hash")
        known[cli_id] = (
            raw_path if isinstance(raw_path, str) else None,
            raw_hash if isinstance(raw_hash, str) else None,
        )
    seen_at = utc_now()
    for root in _catalog_roots(items):
        try:
            _publish_root(store, root, home_dir=home_dir, seen_at=seen_at, known=known)
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, json.JSONDecodeError):
            continue
    refreshed = _listed_items(store)
    shown = package_items_available(refreshed)
    return [public_local_cli_item(item) for item, keep in zip(refreshed, shown, strict=True) if keep]


def recognize_operator_package_scripts(
    command_text: str,
    *,
    cwd: Path,
    home_dir: Path,
    store: object,
) -> PackageJsonScriptsDiscovery | None:
    """Return the cwd catalog, or the unique remembered project that matches this paste."""

    found = recognize_package_json_scripts(command_text, cwd=cwd, home_dir=home_dir)
    if found is not None or not looks_like_package_script_paste(command_text):
        return found
    hits: list[PackageJsonScriptsDiscovery] = []
    for root in _catalog_roots(_listed_items(store), include_cwd=False):
        remembered = recognize_package_json_scripts(command_text, cwd=root, home_dir=home_dir)
        if remembered is not None:
            hits.append(remembered)
    named = [
        hit
        for hit in hits
        if hit.focused_script and any(command.name == hit.focused_script for command in hit.commands)
    ]
    pool = named or hits
    if len({hit.identity.cli_id for hit in pool}) != 1:
        return None
    return pool[0]


def _listed_items(store: object) -> list[dict[str, object]]:
    lister = getattr(store, "list_local_cli_items", None)
    if not callable(lister):
        return []
    raw = lister()
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _publish_root(
    store: object,
    root: Path,
    *,
    home_dir: Path,
    seen_at: str,
    known: dict[str, tuple[str | None, str | None]],
) -> None:
    discovery = recognize_package_json_scripts("npm run", cwd=root, home_dir=home_dir)
    if discovery is None:
        return
    replace_commands = getattr(store, "replace_local_cli_commands", None)
    if callable(replace_commands):
        replace_commands(discovery.identity.cli_id, discovery.commands)
    stored = known.get(discovery.identity.cli_id)
    if (
        stored is not None
        and stored[0] not in {None, *_PATH_CLASS_TOKENS}
        and stored[1] == discovery.identity.identity_hash
    ):
        return
    recorder = getattr(store, "record_local_cli_observation", None)
    if not callable(recorder):
        return
    recorder(
        discovery.identity,
        seen_at=seen_at,
        source_path=discovery.identity.source_path,
        help_status="ok",
        surface=_SURFACE,
    )
    known[discovery.identity.cli_id] = (discovery.identity.source_path, discovery.identity.identity_hash)


def _catalog_roots(items: list[dict[str, object]], *, include_cwd: bool = True) -> list[Path]:
    roots = _ask("roots", include_cwd=include_cwd, entries=_entries(items)).get("roots")
    if not isinstance(roots, list) or not all(isinstance(root, str) for root in roots):
        raise RuntimeError("HOL Guard native runtime returned malformed package roots")
    return [Path(root) for root in roots]


def _folder_label(source_path: str | None) -> str | None:
    if not source_path or source_path in _PATH_CLASS_TOKENS:
        return None
    path = Path(source_path)
    folder = path.parent if path.name == "package.json" else path
    name = folder.name.strip()
    return name[:120] if name else None

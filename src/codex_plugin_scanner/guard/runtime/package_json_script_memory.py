"""Remember package.json projects locally and redact paths on public payloads."""

from __future__ import annotations

import json
from pathlib import Path

from .package_json_scripts import (
    PackageJsonScriptsDiscovery,
    find_nearest_package_json,
    looks_like_package_script_paste,
    recognize_package_json_scripts,
)

_SURFACE = "package-scripts"
_PUBLIC_SOURCE = "user-tool"
_MAX_REMEMBERED = 16
_MAX_WORKSPACES = 8
_PATH_CLASS_TOKENS = frozenset({"unknown", "package-store", "system-bin", "user-tool"})


def operator_working_directory(payload: dict[str, object], *, home_dir: Path) -> Path:
    raw = payload.get("cwd")
    if isinstance(raw, str) and raw.strip():
        try:
            resolved = Path(raw.strip()).expanduser().resolve()
        except OSError:
            resolved = None
        if resolved is not None and resolved.is_dir():
            return resolved
    process_cwd = Path.cwd()
    if process_cwd.is_dir() and find_nearest_package_json(process_cwd, home_dir=home_dir) is not None:
        return process_cwd
    return home_dir


def public_local_cli_item(item: dict[str, object]) -> dict[str, object]:
    """Redact package.json paths from public list/recognize payloads."""

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
    return [public_local_cli_item(item) for item in refreshed if _package_item_available(item)]


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


def _package_item_available(item: dict[str, object]) -> bool:
    if item.get("state") in {"allowed", "blocked"}:
        return True
    if item.get("surface") != _SURFACE:
        return True
    raw = item.get("source_path")
    if not isinstance(raw, str) or raw in _PATH_CLASS_TOKENS:
        return True
    path = Path(raw)
    manifest = path if path.name == "package.json" else path / "package.json"
    try:
        return manifest.is_file()
    except OSError:
        return False


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
    candidates: list[Path] = []
    if include_cwd:
        cwd = Path.cwd()
        if cwd.is_dir():
            candidates.append(cwd)
    for item in items:
        if item.get("surface") != _SURFACE:
            continue
        raw = item.get("source_path")
        if not isinstance(raw, str) or raw in _PATH_CLASS_TOKENS:
            continue
        path = Path(raw)
        candidates.append(path.parent if path.name == "package.json" else path)
    roots: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        manifest = resolved if resolved.name == "package.json" else resolved / "package.json"
        if not manifest.is_file():
            continue
        root = manifest.parent
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        roots.append(root)
        for child in _workspace_package_roots(root):
            child_key = str(child)
            if child_key in seen:
                continue
            seen.add(child_key)
            roots.append(child)
        if len(roots) >= _MAX_REMEMBERED:
            break
    return roots


def _workspace_package_roots(root: Path) -> list[Path]:
    try:
        payload = json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []
    raw = payload.get("workspaces")
    patterns: list[str] = []
    if isinstance(raw, list):
        patterns = [item for item in raw if isinstance(item, str)]
    elif isinstance(raw, dict):
        packages = raw.get("packages")
        if isinstance(packages, list):
            patterns = [item for item in packages if isinstance(item, str)]
    found: list[Path] = []
    for pattern in patterns[:6]:
        if ".." in pattern or pattern.startswith("/") or "**" in pattern:
            continue
        try:
            matches = sorted(root.glob(pattern))
        except (OSError, ValueError):
            continue
        for match in matches:
            if match.is_dir() and (match / "package.json").is_file():
                found.append(match)
            if len(found) >= _MAX_WORKSPACES:
                return found
    return found


def _folder_label(source_path: str | None) -> str | None:
    if not source_path or source_path in _PATH_CLASS_TOKENS:
        return None
    path = Path(source_path)
    folder = path.parent if path.name == "package.json" else path
    name = folder.name.strip()
    return name[:120] if name else None

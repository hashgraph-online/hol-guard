"""Cline MCP discovery, Guard proxying, and conservative restoration."""

from __future__ import annotations

import json
import os
from contextlib import suppress
from hashlib import sha256
from pathlib import Path

from .base import HarnessContext
from .cline_paths import cline_data_dir
from .mcp_servers import ManagedMcpServer, proxy_launcher_entry


def cline_mcp_settings_candidates(context: HarnessContext) -> tuple[Path, ...]:
    """Return current and legacy Cline MCP settings paths without executing Cline."""

    explicit = os.environ.get("CLINE_MCP_SETTINGS_PATH", "").strip()
    cline_dir = cline_data_dir(context)
    home = context.home_dir
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit).expanduser())
    paths.extend(
        (
            cline_dir / "data" / "settings" / "cline_mcp_settings.json",
            cline_dir / "settings" / "cline_mcp_settings.json",
            home
            / "Library"
            / "Application Support"
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json",
            home
            / ".config"
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json",
            home
            / "AppData"
            / "Roaming"
            / "Code"
            / "User"
            / "globalStorage"
            / "saoudrizwan.claude-dev"
            / "settings"
            / "cline_mcp_settings.json",
        )
    )
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return tuple(unique)


def _json_object(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _well_formed(row: object) -> bool:
    return (
        isinstance(row, dict)
        and set(row) == {"name", "command", "args", "transport", "env"}
        and all(isinstance(row[key], str) for key in ("name", "command", "transport"))
        and _strings(row["args"])
        and isinstance(row["env"], dict)
        and _strings(list(row["env"].values()))
    )


def _proxy_plan(
    context: HarnessContext, path: Path, payload: dict[str, object]
) -> tuple[str, list[ManagedMcpServer], list[str]]:
    """Ask the native ``cline_install_plan`` kind which servers of one settings file to proxy."""

    from ..native_context import _resolve_existing_digest_home
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {"op": "mcp_proxy", "settings": json.dumps(payload)}
    try:
        answer = native_runner_authority(
            "cline_install_plan", request, guard_home=_resolve_existing_digest_home(context.guard_home)
        )
        plan = json.loads(answer["plan"]) if set(answer) == {"plan"} and isinstance(answer["plan"], str) else None
    except (NativeRunnerAuthorityError, json.JSONDecodeError) as error:
        raise RuntimeError("Could not plan the Cline MCP proxy install.") from error
    if (
        not isinstance(plan, dict)
        or set(plan) != {"key", "managed", "remote"}
        or plan["key"] not in {"mcpServers", "mcp"}
        or not isinstance(plan["managed"], list)
        or not all(_well_formed(row) for row in plan["managed"])
        or not _strings(plan["remote"])
    ):
        raise RuntimeError("Could not plan the Cline MCP proxy install.")
    servers = [
        ManagedMcpServer(
            harness="cline",
            name=row["name"],
            source_scope="global",
            config_path=str(path),
            command=row["command"],
            args=tuple(row["args"]),
            transport=row["transport"],
            env=row["env"],
            enabled=True,
        )
        for row in plan["managed"]
    ]
    return plan["key"], servers, plan["remote"]


def _backup_root(context: HarnessContext) -> Path:
    return context.guard_home / "managed" / "cline" / "mcp-backups"


def _backup_path(context: HarnessContext, config_path: Path) -> Path:
    digest = sha256(str(config_path.resolve(strict=False)).encode("utf-8")).hexdigest()[:16]
    return _backup_root(context) / f"{digest}.json"


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.hol-guard.tmp-{os.getpid()}")
    with temporary.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _proxy_entry(context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
    entry = proxy_launcher_entry(proxy_command="cline-mcp-proxy", context=context, server=server)
    return {**entry, "type": "stdio"}


def install_cline_mcp_proxies(context: HarnessContext) -> dict[str, object]:
    """Proxy eligible local stdio servers while keeping raw secret values in-memory only."""

    changed: list[str] = []
    managed_servers: list[str] = []
    skipped_remote: list[str] = []
    for path in cline_mcp_settings_candidates(context):
        if not path.is_file() or not path.resolve(strict=False).is_relative_to(context.home_dir.resolve(strict=False)):
            continue
        payload = _json_object(path)
        if not payload:
            continue
        key, servers, remote = _proxy_plan(context, path, payload)
        skipped_remote.extend(remote)
        replacements = {server.name: _proxy_entry(context, server) for server in servers}
        managed_servers.extend(replacements)
        if not replacements:
            continue
        original_bytes = path.read_bytes()
        backup_path = _backup_path(context, path)
        if not backup_path.exists():
            backup_payload = {
                "schema_version": 1,
                "config_path": str(path),
                "original_sha256": _sha(original_bytes),
                "original_text": original_bytes.decode("utf-8"),
                "managed_sha256": None,
            }
            _atomic_write_bytes(backup_path, (json.dumps(backup_payload, sort_keys=True) + "\n").encode("utf-8"))
        entries = payload.get(key)
        payload[key] = {**(entries if isinstance(entries, dict) else {}), **replacements}
        managed_bytes = (json.dumps(payload, indent=2) + "\n").encode("utf-8")
        _atomic_write_bytes(path, managed_bytes)
        backup_payload = _json_object(backup_path)
        backup_payload["managed_sha256"] = _sha(managed_bytes)
        _atomic_write_bytes(backup_path, (json.dumps(backup_payload, sort_keys=True) + "\n").encode("utf-8"))
        changed.append(str(path))
    return {
        "changed_config_paths": changed,
        "managed_servers": sorted(dict.fromkeys(managed_servers)),
        "skipped_remote_servers": sorted(dict.fromkeys(skipped_remote)),
        "backup_root": str(_backup_root(context)),
    }


def cline_mcp_proxy_state(context: HarnessContext) -> dict[str, object]:
    backup_root = _backup_root(context)
    records: list[dict[str, object]] = []
    ready = True
    if backup_root.is_dir():
        for backup_path in sorted(backup_root.glob("*.json")):
            backup = _json_object(backup_path)
            config_value = backup.get("config_path")
            managed_sha = backup.get("managed_sha256")
            current_sha = None
            if isinstance(config_value, str) and Path(config_value).is_file():
                with suppress(OSError):
                    current_sha = _sha(Path(config_value).read_bytes())
            matched = isinstance(managed_sha, str) and current_sha == managed_sha
            ready = ready and matched
            records.append({"config_path": config_value, "managed_integrity_ok": matched})
    return {"configured": bool(records), "ready": ready if records else True, "configs": records}


def restore_cline_mcp_proxies(context: HarnessContext) -> dict[str, object]:
    restored: list[str] = []
    retained: list[str] = []
    backup_root = _backup_root(context)
    if not backup_root.is_dir():
        return {"restored": restored, "retained_modified": retained, "complete": True}
    for backup_path in sorted(backup_root.glob("*.json")):
        backup = _json_object(backup_path)
        config_value = backup.get("config_path")
        original_text = backup.get("original_text")
        managed_sha = backup.get("managed_sha256")
        if not isinstance(config_value, str) or not isinstance(original_text, str):
            retained.append(str(backup_path))
            continue
        path = Path(config_value)
        if path.is_file():
            try:
                current_sha = _sha(path.read_bytes())
            except OSError:
                retained.append(str(path))
                continue
            if not isinstance(managed_sha, str) or current_sha != managed_sha:
                retained.append(str(path))
                continue
        _atomic_write_bytes(path, original_text.encode("utf-8"))
        restored.append(str(path))
        backup_path.unlink()
    if not retained:
        with suppress(OSError):
            backup_root.rmdir()
    return {"restored": restored, "retained_modified": retained, "complete": not retained}


__all__ = [
    "cline_mcp_proxy_state",
    "cline_mcp_settings_candidates",
    "install_cline_mcp_proxies",
    "restore_cline_mcp_proxies",
]

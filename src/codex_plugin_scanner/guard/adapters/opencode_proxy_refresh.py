"""Narrow, permission-preserving refresh of managed OpenCode MCP launchers."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

from ..runtime.jsonc import normalize_jsonc
from .base import HarnessContext
from .hook_python import guard_cli_command
from .opencode_artifacts import _command_parts, config_paths
from .opencode_config_lock import opencode_config_lock


def _member_span(text: str, offset: int, key: str) -> tuple[int, int]:
    decoder = json.JSONDecoder()

    def skip(index: int) -> int:
        while index < len(text) and text[index].isspace():
            index += 1
        return index

    index = skip(offset)
    if text[index] != "{":
        raise ValueError("OpenCode launcher refresh expected an object")
    index = skip(index + 1)
    found: list[tuple[int, int]] = []
    while text[index] != "}":
        name, end = decoder.raw_decode(text, index)
        colon = skip(end)
        if not isinstance(name, str) or text[colon] != ":":
            raise ValueError("Invalid OpenCode object member")
        start = skip(colon + 1)
        _, end = decoder.raw_decode(text, start)
        if name == key:
            found.append((start, end))
        index = skip(end)
        if text[index] == "}":
            break
        if text[index] != ",":
            raise ValueError("Invalid OpenCode object separator")
        index = skip(index + 1)
    if len(found) != 1:
        raise ValueError("OpenCode launcher member is missing or ambiguous")
    return found[0]


def _replace_command(text: str, name: str, command: list[str]) -> str:
    normalized = normalize_jsonc(text)
    start = 0
    end = len(text)
    for key in ("mcp", name, "command"):
        start, end = _member_span(normalized, start, key)
    # Retain comments embedded in the replaced array as notes before its value.
    old = text[start:end]
    masked = normalize_jsonc(old)
    notes: list[str] = []
    index = 0
    while index < len(old):
        if old[index : index + 2] == "//" and masked[index : index + 2] == "  ":
            stop = old.find("\n", index)
            stop = len(old) if stop < 0 else stop
            notes.append(old[index:stop] + "\n")
            index = stop
        elif old[index : index + 2] == "/*" and masked[index : index + 2] == "  ":
            stop = old.find("*/", index + 2) + 2
            notes.append(old[index:stop] + "\n")
            index = stop
        else:
            index += 1
    replacement = "".join(notes) + json.dumps(command)
    return text[:start] + replacement + text[end:]


def _write_existing(path: Path, before: bytes, after: bytes, mode: int) -> None:
    if path.is_symlink() or path.read_bytes() != before:
        raise ValueError("OpenCode config changed during launcher refresh")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    staged = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), mode)
            handle.write(after)
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink() or path.read_bytes() != before:
            raise ValueError("OpenCode config changed during launcher refresh")
        os.replace(staged, path)
    finally:
        staged.unlink(missing_ok=True)


def refresh_opencode_proxy_launchers(context: HarnessContext, *, warnings: list[str] | None = None) -> int:
    """Refresh verified CLI prefixes without changing server or tool authority."""
    with opencode_config_lock(context.home_dir):
        return _refresh_locked(context, warnings=warnings)


def _refresh_locked(context: HarnessContext, *, warnings: list[str] | None = None) -> int:
    from .opencode_install_snapshot import (
        OpenCodeInstallSnapshotError,
        _binding_matches_native,
        _scope_for,
        _verified_proxy_binding,
    )

    writes: list[tuple[Path, bytes, bytes, int]] = []
    refreshed = 0
    for path in config_paths(context):
        if not path.exists():
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1_000_000:
            raise OpenCodeInstallSnapshotError("OpenCode config is not a bounded regular file")
        if os.name != "nt" and info.st_uid != os.geteuid():
            raise OpenCodeInstallSnapshotError("OpenCode config is owned by another user")
        before = path.read_bytes()
        try:
            text = before.decode("utf-8")
            payload: object = json.loads(normalize_jsonc(text))
        except (UnicodeError, ValueError):
            if warnings is not None:
                warnings.append("An invalid OpenCode config was left unchanged; other configs were checked.")
            continue
        if not isinstance(payload, dict):
            raise OpenCodeInstallSnapshotError("OpenCode config must be an object")
        mcp = payload.get("mcp")
        if not isinstance(mcp, dict):
            continue
        changed = False
        for name, entry in mcp.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            binding = _verified_proxy_binding(
                name,
                entry,
                context=context,
                scope=_scope_for(context, path),
                expected_config_path=path,
            )
            if binding is None:
                continue
            native = mcp.get(binding.native_name)
            if isinstance(native, dict) and (
                native.get("type", "local") not in {"local", "stdio"} or not _binding_matches_native(binding, native)
            ):
                continue
            _, args = _command_parts(entry)
            proxy_args = list(args[args.index("opencode-mcp-proxy") :])
            command = guard_cli_command(context, ["-m", "codex_plugin_scanner.cli", "guard", *proxy_args])
            if entry.get("command") == command:
                continue
            text = _replace_command(text, name, command)
            refreshed += 1
            changed = True
        if changed:
            writes.append((path, before, text.encode("utf-8"), stat.S_IMODE(info.st_mode)))
    applied: list[tuple[Path, bytes, bytes, int]] = []
    try:
        for path, before, after, mode in writes:
            _write_existing(path, before, after, mode)
            applied.append((path, before, after, mode))
    except (OSError, ValueError):
        for path, before, after, mode in reversed(applied):
            _write_existing(path, after, before, mode)
        raise
    return refreshed

"""Private qualification records; no production installer selects this pilot."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from ..codex_hook_integrity import load_hook_secret
from ..local_authority_integrity import verify_local_authority_payload

SCHEMA = "guard-claude-launcher-pilot.v1"
PURPOSE = "claude-native-launcher-pilot"
EVENTS = ("PreToolUse", "PostToolUse")


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_mode, value.st_uid)


def file_binding(path: Path, *, invocation: bool = False) -> dict[str, object]:
    """Preserve an interpreter invocation symlink independently of its target."""
    lexical = Path(os.path.abspath(path))
    before = lexical.lstat()
    resolved = lexical.resolve(strict=True)
    current = resolved.stat()
    if (not invocation and stat.S_ISLNK(before.st_mode)) or not stat.S_ISREG(current.st_mode):
        raise ValueError("claude_pilot_file_shape_invalid")
    if os.name != "nt" and (current.st_uid not in {0, os.getuid()} or current.st_mode & 0o022):
        raise ValueError("claude_pilot_file_ownership_invalid")
    digest = hashlib.sha256()
    descriptor = os.open(
        resolved,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
    )
    with os.fdopen(descriptor, "rb") as stream:
        if _stamp(os.fstat(stream.fileno())) != _stamp(current):
            raise ValueError("claude_pilot_file_changed")
        total = 0
        for chunk in iter(lambda: stream.read(65_536), b""):
            total += len(chunk)
            if total > 512 * 1024 * 1024:
                raise ValueError("claude_pilot_file_limit")
            digest.update(chunk)
        if total != current.st_size or _stamp(os.fstat(stream.fileno())) != _stamp(current):
            raise ValueError("claude_pilot_file_changed")
    after = lexical.lstat()
    if _stamp(before) != _stamp(after) or _stamp(current) != _stamp(resolved.stat()):
        raise ValueError("claude_pilot_file_changed")
    return {
        "path": str(lexical),
        "resolved": str(resolved),
        "size": current.st_size,
        "sha256": digest.hexdigest(),
        "device": current.st_dev,
        "inode": current.st_ino,
        "mtime_ns": current.st_mtime_ns,
        "invocation": invocation,
        "link_device": before.st_dev,
        "link_inode": before.st_ino,
        "link_mtime_ns": before.st_mtime_ns,
    }


def verify_file(binding: dict[str, Any]) -> None:
    if file_binding(Path(binding["path"]), invocation=binding.get("invocation") is True) != binding:
        raise ValueError("claude_pilot_file_identity_changed")


def bounded_read(path: Path, limit: int = 1_000_000, *, private: bool = False) -> bytes:
    parent = path.parent.lstat()
    before = path.lstat()
    if not stat.S_ISDIR(parent.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("claude_pilot_private_file_invalid")
    mask = 0o077 if private else 0o022
    owners = ({os.getuid()} if private else {0, os.getuid()}) if os.name != "nt" else set()
    if os.name != "nt" and (
        parent.st_uid not in owners or before.st_uid not in owners or parent.st_mode & mask or before.st_mode & mask
    ):
        raise ValueError("claude_pilot_private_file_permissions")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(descriptor, "rb") as stream:
        if _stamp(os.fstat(stream.fileno())) != _stamp(before):
            raise ValueError("claude_pilot_private_file_changed")
        value = stream.read(limit + 1)
        if _stamp(os.fstat(stream.fileno())) != _stamp(before):
            raise ValueError("claude_pilot_private_file_changed")
    if len(value) > limit or _stamp(path.lstat()) != _stamp(before):
        raise ValueError("claude_pilot_private_file_changed")
    return value


def load_record(path: Path, event: str, *, require_registration: bool = True) -> dict[str, Any]:
    path = path.absolute()
    record = json.loads(bounded_read(path, private=True))
    if not isinstance(record, dict) or record.get("schema") != SCHEMA or event not in EVENTS:
        raise ValueError("claude_pilot_record_invalid")
    guard_home = path.parent.parent.parent
    if path != guard_home / "managed" / "claude-pilot" / "launcher.json":
        raise ValueError("claude_pilot_record_location_invalid")
    secret = load_hook_secret(guard_home)
    authentication = record.get("authentication")
    if not isinstance(authentication, dict):
        raise ValueError("claude_pilot_record_unsigned")
    unsigned = {key: value for key, value in record.items() if key != "authentication"}
    if (
        verify_local_authority_payload(
            unsigned,
            authentication,
            key=secret.key,
            key_id=secret.key_id,
            purpose=PURPOSE,
        ).status
        != "valid"
    ):
        raise ValueError("claude_pilot_record_authentication_failed")
    if record.get("guard_home") != str(guard_home) or record.get("installation_id") != secret.installation_id:
        raise ValueError("claude_pilot_record_installation_changed")
    for binding in record["files"].values():
        verify_file(binding)
    if not require_registration:
        return record
    configuration = Path(record["configuration"])
    raw = bounded_read(configuration)
    if len(raw) > 1_000_000 or hashlib.sha256(raw).hexdigest() != record["registration_sha256"]:
        raise ValueError("claude_pilot_registration_changed")
    groups = json.loads(raw).get("hooks", {}).get(event, [])
    matching = [
        handler
        for group in groups
        for handler in group.get("hooks", [])
        if (handler.get("command"), *handler.get("args", [])) == tuple(record["argv"][event])
    ]
    if len(matching) != 1:
        raise ValueError("claude_pilot_registration_missing_or_ambiguous")
    return record

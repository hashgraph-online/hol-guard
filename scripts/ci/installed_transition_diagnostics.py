"""Read-only, bounded observations for installed artifact transition failures."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

STATE_LIMIT = 1024 * 1024 + 16 * 1024
STAGES = frozenset(
    {
        "import_probe",
        "installed_identity",
        "private_history",
        "open_store",
        "verify_authority",
        "verify_receipts",
        "reject_stale_write",
        "construct_daemon",
        "native_start",
        "registered_hooks",
        "retire",
        "checkpoint",
        "failed",
    }
)
LEGACY_REJECTION_REASONS = frozenset(
    {
        "native_policy_snapshot_cache_invalid",
        "native_policy_snapshot_unknown_field",
        "native_policy_snapshot_state_invalid",
    }
)


def exception_metadata(error: Exception) -> dict:
    """Keep a stable class/digest and shipped frame, never exception text."""
    kind = type(error).__name__
    result = {
        "category": kind if re.fullmatch(r"[A-Za-z]{1,64}", kind) else "Exception",
        "diagnostic_digest": hashlib.sha256(str(error).encode("utf-8", errors="replace")).hexdigest(),
    }
    if isinstance(error, OSError) and type(error.errno) is int:
        result["errno"] = error.errno
    frame = error.__traceback__
    while frame is not None:
        module = str(frame.tb_frame.f_globals.get("__name__", ""))
        if module.startswith(("scripts.", "codex_plugin_scanner.")):
            label = Path(frame.tb_frame.f_code.co_filename).stem + "." + frame.tb_frame.f_code.co_name
            if re.fullmatch(r"[A-Za-z0-9_.]{1,96}", label):
                result.update(
                    origin=label.replace("secret", "sensitive").replace("token", "credential"), line=frame.tb_lineno
                )
        frame = frame.tb_next
    return result


def publisher_metadata(publisher: object) -> dict:
    try:
        error = getattr(publisher, "last_error", None)
        reason = error if isinstance(error, str) and re.fullmatch(r"native_[a-z0-9_]{1,80}", error) else "unclassified"
        thread = getattr(publisher, "_thread", None)
        is_ready = getattr(publisher, "is_ready", None)
        ready = is_ready() if callable(is_ready) else None
        return {
            "ready": ready if type(ready) is bool else None,
            "reason": reason,
            "diagnostic_digest": hashlib.sha256(str(error).encode("utf-8", errors="replace")).hexdigest(),
            "thread_alive": thread is not None and thread.is_alive(),
        }
    except Exception as error:
        return {"status": "unreadable", "failure": exception_metadata(error)}


def _private_bytes(guard_home: Path, relative: Path) -> bytes | None:
    path = guard_home / relative
    if os.name == "nt":
        # Both pinned builds expose these same production private-handle readers.
        from codex_plugin_scanner.guard import native_policy_snapshot as api

        with api._windows_private_state_binding(guard_home):
            return api._windows_read_snapshot_bytes(path, maximum_bytes=STATE_LIMIT)
    for parent in (guard_home, path.parent):
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ValueError("transition_state_parent_not_private")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or not 0 < before.st_size <= STATE_LIMIT
        ):
            raise ValueError("transition_state_file_not_private")
        chunks = bytearray()
        while len(chunks) <= STATE_LIMIT:
            chunk = os.read(descriptor, min(65536, STATE_LIMIT + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(chunks) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError("transition_state_changed_during_read")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def policy_state(guard_home: Path) -> dict:
    """Fingerprint exact private bytes; this does not assert legacy MAC validation."""
    observed = {"scope": "private_file_bytes", "authentication_qualified": False}
    for kind, relative in (
        ("authority", Path("native-runtime/policy-snapshot-v3.json")),
        ("publisher", Path("native-runtime/policy-snapshot-publisher-v3.json")),
        ("generation", Path("native-policy-snapshot-generation-v3.json")),
    ):
        try:
            payload = _private_bytes(guard_home, relative)
            if payload is None:
                observed[kind] = {"status": "absent"}
                continue
            document = json.loads(payload)
            if not isinstance(document, dict):
                raise ValueError("transition_state_document_invalid")
            item = {"status": "read", "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
            if kind == "authority":
                item["binding_present"] = isinstance(document.get("command_control_floor"), dict)
                generation = document.get("generation_floor")
            else:
                generation = document.get("generation")
            if type(generation) is int and 0 <= generation < 2**64:
                item["generation"] = generation
            observed[kind] = item
        except Exception as error:
            observed[kind] = {"status": "unreadable", "failure": exception_metadata(error)}
    return observed


def state_preserved(before: object, after: object) -> bool:
    return (
        isinstance(before, dict)
        and isinstance(after, dict)
        and all(isinstance(before.get(kind), dict) for kind in ("authority", "publisher", "generation"))
        and before == after
        and all(before.get(kind, {}).get("status") == "read" for kind in ("authority", "publisher", "generation"))
        and before["authority"].get("binding_present") is True
    )


def process_metadata(result: object) -> dict:
    evidence = {"return_code": getattr(result, "returncode", None)}
    for channel in ("stdout", "stderr"):
        value = getattr(result, channel, "")
        data = value if isinstance(value, bytes) else str(value).encode("utf-8", errors="replace")
        evidence[channel + "_bytes"] = len(data)
        evidence[channel + "_sha256"] = hashlib.sha256(data).hexdigest()
        if channel == "stderr":
            stages = re.findall(rb"(?m)^HOL_GUARD_TRANSITION_STAGE=([a-z_]+)\r?$", data)
            if stages and stages[-1].decode("ascii") in STAGES:
                evidence["last_stage"] = stages[-1].decode("ascii")
    return evidence

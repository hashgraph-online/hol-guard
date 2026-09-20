"""Bounded failure identifiers for CI, without child stderr or response bodies."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

from scripts.native_slo_contract import assert_privacy_safe

_CODEX_FILE_ROLES = frozenset(
    {
        "interpreter",
        "config_target",
        "bridge",
        "bridge_resume",
        "bridge_runtime",
        "fallback_entrypoint",
        "daemon_entrypoint",
        "daemon_manager",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    }
)
_CODEX_FILE_FAILURE_CODES = frozenset(
    f"codex_hook_{role}_{suffix}"
    for role in _CODEX_FILE_ROLES
    for suffix in ("missing", "not_regular", "owner_untrusted", "permissions_unsafe", "not_executable")
)
_CONFIG_CAUSE_TYPES = (
    OSError,
    PermissionError,
    FileNotFoundError,
    NotADirectoryError,
    IsADirectoryError,
    FileExistsError,
    BlockingIOError,
    TimeoutError,
    InterruptedError,
    BrokenPipeError,
    ConnectionError,
    ConnectionAbortedError,
    ConnectionRefusedError,
    ConnectionResetError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
    ImportError,
    ModuleNotFoundError,
    NotImplementedError,
)


def _interpreter_failure_metadata() -> dict[str, object]:
    """Read the current invocation after rejection; never repair or re-attest it."""
    try:
        invocation = Path(sys.executable).absolute()
        invocation_metadata = invocation.lstat()
        metadata = invocation.resolve(strict=True).lstat()
    except (OSError, RuntimeError):
        return {"interpreter_metadata_available": False}
    uid = os.getuid() if hasattr(os, "getuid") else None
    gid = os.getgid() if hasattr(os, "getgid") else None
    return {
        "interpreter_metadata_available": True,
        "interpreter_metadata_phase": "after_integrity_rejection",
        "interpreter_invocation_symlink": stat.S_ISLNK(invocation_metadata.st_mode),
        "interpreter_regular": stat.S_ISREG(metadata.st_mode),
        "interpreter_mode": stat.S_IMODE(metadata.st_mode),
        "interpreter_owner_current": uid is not None and metadata.st_uid == uid,
        "interpreter_owner_root": metadata.st_uid == 0,
        "interpreter_group_current": gid is not None and metadata.st_gid == gid,
        "interpreter_group_root": metadata.st_gid == 0,
        "interpreter_group_writable": bool(metadata.st_mode & stat.S_IWGRP),
        "interpreter_world_writable": bool(metadata.st_mode & stat.S_IWOTH),
    }


class FixtureFailureError(RuntimeError):
    """Keep bounded child evidence intact across the private control pipe."""

    def __init__(self, detail: Mapping[str, object], *, message: str | None = None) -> None:
        self.detail = assert_privacy_safe(dict(detail))
        # A local wrapper may preserve an existing exception's caller-facing
        # message. Exporters use only the sanitized detail, never this text.
        super().__init__(message or "qualification_fixture." + str(self.detail.get("reason", "unclassified_failure")))


def _location(error: Exception) -> dict[str, object]:
    """Record a shipped code location, never exception text or frame locals."""
    result: dict[str, object] = {}
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        module = str(frame.f_globals.get("__name__", ""))
        if module.startswith(("scripts.", "codex_plugin_scanner.")) or (
            module == "__main__" and Path(frame.f_code.co_filename).name == "native_slo_daemon_fixture.py"
        ):
            unit = Path(frame.f_code.co_filename).stem
            routine = frame.f_code.co_name
            identifier = (unit + "." + routine).replace("secret", "sensitive").replace("token", "credential")
            if re.fullmatch(r"[A-Za-z0-9_.]{1,96}", identifier):
                result = {"origin": identifier, "line": traceback.tb_lineno}
        traceback = traceback.tb_next
    if isinstance(error, OSError) and isinstance(error.errno, int):
        result["errno"] = error.errno
    return result


def _configuration_failure_metadata(error: Exception) -> dict[str, object]:
    """Retain explicit bounded causes after rejection, without reading files or error text."""
    from codex_plugin_scanner.guard.config_source_io import GuardConfigSourceError

    if type(error) is not GuardConfigSourceError:
        return {}
    result: dict[str, object] = {"config_diagnostic_available": True, "config_cause_count": 0}
    seen = {id(error)}
    cause = error.__cause__
    for index in range(1, 4):
        if cause is None:
            break
        if id(cause) in seen:
            result["config_cause_cycle"] = True
            break
        seen.add(id(cause))
        prefix = f"config_cause_{index}_"
        cause_type = type(cause)
        result["config_cause_count"] = index
        if not any(cause_type is allowed for allowed in _CONFIG_CAUSE_TYPES):
            result[prefix + "category"] = "unclassified"
            result["config_cause_unavailable"] = True
            break
        result[prefix + "category"] = cause_type.__name__
        if isinstance(cause, Exception):
            for name, value in _location(cause).items():
                if name != "errno" or (type(value) is int and 0 <= value <= 0xFFFFFFFF):
                    result[prefix + name] = value
        if isinstance(cause, OSError):
            winerror = getattr(cause, "winerror", None)
            if type(winerror) is int and 0 <= winerror <= 0xFFFFFFFF:
                result[prefix + "winerror"] = winerror
        cause = cause.__cause__
    else:
        if cause is not None:
            result["config_cause_truncated"] = True
    return result


def failure_evidence(error: Exception) -> dict[str, object]:
    if isinstance(error, FixtureFailureError):
        return {**error.detail, "reason": "qualification_fixture." + str(error.detail["reason"])[:64]}
    message = str(error)
    evidence: dict[str, object] = {
        "schema": "hol-guard.native-qualification-failure.v1",
        "category": type(error).__name__,
        "reason": "unclassified_failure",
        "diagnostic_digest": hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest(),
        **_location(error),
    }
    try:
        evidence.update(_configuration_failure_metadata(error))
    except Exception:
        # Optional failure evidence must not replace the original failure.
        evidence["config_diagnostic_available"] = False
    from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError

    if isinstance(error, CodexHookIntegrityError) and error.reason in _CODEX_FILE_FAILURE_CODES:
        evidence["reason"] = error.reason
        if error.reason == "codex_hook_interpreter_permissions_unsafe":
            evidence.update(_interpreter_failure_metadata())
    if message.startswith(("native_qualification_mismatch:", "native_qualification_setup_unproven:")):
        pieces = message.split(":", 2)
        if (
            len(pieces) == 3
            and re.fullmatch(r"[A-Za-z0-9_./-]{1,96}", pieces[1])
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", pieces[2])
        ):
            evidence.update(reason=pieces[0], case=pieces[1].replace("/", "."), field=pieces[2])
    elif message.startswith(
        (
            "qualification",
            "priority_launcher_",
            "installed_ollama_",
            "native_installed_slo_failed:",
            "daemon fixture",
            "expiry fixture",
            "resident did not explicitly reject",
        )
    ) and re.fullmatch(r"[A-Za-z0-9 _:.=-]{1,96}", message):
        evidence["reason"] = message.replace(" ", "_").replace("secret", "sensitive")
    return assert_privacy_safe(evidence)

"""Resource-bounded, offline inspection for already-downloaded archives.

Trust boundary: the parent passes only a read-only path, its expected digest,
and numeric limits to a separate isolated-Python worker. The worker receives a
minimal environment, denies network/process/write capabilities, applies hard
resource limits, never extracts or executes archive content, and returns only
a bounded typed result. Unsupported containment fails closed.
"""

from __future__ import annotations

import json
import math
import re
import socket
import stat
import subprocess
import sys
from pathlib import Path

import codex_plugin_scanner

from .offline_archive_contract import (
    _CHILD_RESULT_MAX_BYTES,
    _DEFAULT_MAX_ARCHIVE_BYTES,
    _DEFAULT_MAX_DECOMPRESSION_RATIO,
    _DEFAULT_MAX_EXPANDED_BYTES,
    _DEFAULT_MAX_FILES,
    _DEFAULT_MAX_MEMBER_BYTES,
    _DEFAULT_MAX_MEMORY_BYTES,
    _DEFAULT_MAX_NESTED_ARCHIVES,
    _DEFAULT_MAX_PACKAGE_JSON_BYTES,
    _DEFAULT_MAX_PATH_DEPTH,
    _DEFAULT_TIMEOUT_SECONDS,
    ArchiveInspectionResult,
    _result,
)
from .offline_archive_sandbox import (
    _child_environment,
    _child_limits,
    _install_child_capability_guard,
    _platform_sandbox_command,
)
from .offline_archive_worker import _inspect_archive


def _isolated_child_command(arguments: list[str]) -> list[str]:
    """Run the split worker package without inheriting ambient import paths."""

    package_file = codex_plugin_scanner.__file__
    if package_file is None:
        raise RuntimeError("guard_archive_inspector_package_root_unavailable")
    source_root = Path(package_file).resolve().parent.parent
    bootstrap = (
        "import importlib,pathlib,sys,types;"
        "r=pathlib.Path(sys.argv.pop(1));"
        "p=["
        "('codex_plugin_scanner',r/'codex_plugin_scanner'),"
        "('codex_plugin_scanner.guard',r/'codex_plugin_scanner'/'guard'),"
        "('codex_plugin_scanner.guard.runtime',r/'codex_plugin_scanner'/'guard'/'runtime')"
        "];"
        "[(lambda m,n,q:(setattr(m,'__path__',[str(q)]),"
        "setattr(m,'__package__',n),sys.modules.__setitem__(n,m)))"
        "(types.ModuleType(n),n,q) for n,q in p];"
        "m=importlib.import_module("
        "'codex_plugin_scanner.guard.runtime.offline_archive_inspection'"
        ");"
        "raise SystemExit(m._child_main(sys.argv[1:]))"
    )
    return [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        bootstrap,
        str(source_root),
        *arguments,
    ]


def inspect_archive_offline(
    path: Path,
    *,
    expected_sha256: str,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    max_archive_bytes: int = _DEFAULT_MAX_ARCHIVE_BYTES,
    max_files: int = _DEFAULT_MAX_FILES,
    max_expanded_bytes: int = _DEFAULT_MAX_EXPANDED_BYTES,
    max_member_bytes: int = _DEFAULT_MAX_MEMBER_BYTES,
    max_package_json_bytes: int = _DEFAULT_MAX_PACKAGE_JSON_BYTES,
    max_memory_bytes: int = _DEFAULT_MAX_MEMORY_BYTES,
    max_decompression_ratio: float = _DEFAULT_MAX_DECOMPRESSION_RATIO,
    max_nested_archives: int = _DEFAULT_MAX_NESTED_ARCHIVES,
    max_path_depth: int = _DEFAULT_MAX_PATH_DEPTH,
) -> ArchiveInspectionResult:
    """Inspect a digest-bound local blob in an isolated subprocess."""

    if (
        timeout_seconds <= 0
        or max_archive_bytes <= 0
        or max_files <= 0
        or max_expanded_bytes <= 0
        or max_member_bytes <= 0
        or max_package_json_bytes <= 0
        or max_memory_bytes <= 0
        or not math.isfinite(max_decompression_ratio)
        or max_decompression_ratio <= 0
        or max_nested_archives < 0
        or max_path_depth <= 0
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        return _result(
            "incomplete",
            "external_archive_inspection_policy_invalid",
            "External archive inspection policy is invalid.",
            severity="high",
        )
    try:
        resolved_path = path.resolve(strict=True)
        file_stat = path.lstat()
    except (OSError, RuntimeError):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive is unavailable for offline inspection.",
            severity="high",
        )
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_nlink != 1
        or stat.S_IMODE(file_stat.st_mode) & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    ):
        return _result(
            "blocked",
            "external_archive_blob_rejected",
            "External archive blob is not a regular immutable file.",
            severity="high",
        )
    child_command = _isolated_child_command(
        [
            "--child-inspect",
            str(resolved_path),
            expected_sha256,
            str(timeout_seconds),
            str(max_archive_bytes),
            str(max_files),
            str(max_expanded_bytes),
            str(max_member_bytes),
            str(max_package_json_bytes),
            str(max_memory_bytes),
            str(max_decompression_ratio),
            str(max_nested_archives),
            str(max_path_depth),
        ]
    )
    command = _platform_sandbox_command(child_command)
    if command is None:
        return _result(
            "incomplete",
            "external_archive_sandbox_unavailable",
            "External archive offline inspector sandbox is unavailable.",
            severity="high",
        )
    try:
        completed = subprocess.run(
            command,
            cwd=resolved_path.parent,
            env=_child_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout_seconds + 0.5,
        )
    except subprocess.TimeoutExpired:
        return _result(
            "incomplete",
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            severity="high",
        )
    except OSError:
        return _result(
            "incomplete",
            "external_archive_sandbox_unavailable",
            "External archive offline inspector could not be started.",
            severity="high",
        )
    if completed.returncode != 0 or len(completed.stdout) > _CHILD_RESULT_MAX_BYTES:
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector did not complete successfully.",
            severity="high",
        )
    try:
        payload = json.loads(completed.stdout.decode("utf-8"))
        status = payload["status"]
        code = payload["code"]
        message = payload["message"]
        severity = payload["severity"]
        sha256 = payload.get("sha256")
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            severity="high",
        )
    if (
        status not in {"clean", "blocked", "incomplete"}
        or not isinstance(code, str)
        or not isinstance(message, str)
        or severity not in {"low", "medium", "high", "critical"}
        or (sha256 is not None and (not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256)))
    ):
        return _result(
            "incomplete",
            "external_archive_inspection_incomplete",
            "External archive offline inspector returned an invalid result.",
            severity="high",
        )
    if status == "clean" and sha256 != expected_sha256:
        return _result(
            "blocked",
            "external_archive_digest_mismatch",
            "External archive inspector did not verify the expected digest.",
            severity="high",
            sha256=sha256,
        )
    return ArchiveInspectionResult(status, code, message, severity, sha256)


def _child_main(arguments: list[str]) -> int:
    if arguments == ["--child-network-probe"]:
        _install_child_capability_guard()
        try:
            network_socket = socket.socket()
        except PermissionError:
            sys.stdout.write("denied")
            return 0
        network_socket.close()
        return 3
    if len(arguments) != 13 or arguments[0] != "--child-inspect":
        return 2
    try:
        path = Path(arguments[1])
        expected_sha256 = arguments[2]
        timeout_seconds = float(arguments[3])
        max_archive_bytes = int(arguments[4])
        max_files = int(arguments[5])
        max_expanded_bytes = int(arguments[6])
        max_member_bytes = int(arguments[7])
        max_package_json_bytes = int(arguments[8])
        max_memory_bytes = int(arguments[9])
        max_decompression_ratio = float(arguments[10])
        max_nested_archives = int(arguments[11])
        max_path_depth = int(arguments[12])
    except ValueError:
        return 2
    _install_child_capability_guard()
    if not _child_limits(timeout_seconds, max_memory_bytes):
        result = _result(
            "incomplete",
            "external_archive_sandbox_unavailable",
            "External archive resource sandbox is unavailable on this platform.",
            severity="high",
        )
    else:
        result = _inspect_archive(
            path,
            expected_sha256=expected_sha256,
            timeout_seconds=timeout_seconds,
            max_archive_bytes=max_archive_bytes,
            max_files=max_files,
            max_expanded_bytes=max_expanded_bytes,
            max_member_bytes=max_member_bytes,
            max_package_json_bytes=max_package_json_bytes,
            max_decompression_ratio=max_decompression_ratio,
            max_nested_archives=max_nested_archives,
            max_path_depth=max_path_depth,
        )
    sys.stdout.write(
        json.dumps(
            {
                "status": result.status,
                "code": result.code,
                "message": result.message,
                "severity": result.severity,
                "sha256": result.sha256,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through parent process
    raise SystemExit(_child_main(sys.argv[1:]))


__all__ = ["ArchiveInspectionResult", "inspect_archive_offline"]

"""Resident bridge for the ``shim_admin`` op: package-shim administration.

Rust owns package-shim status, PATH ordering, install, repair, uninstall,
intercept probing and the shell-profile blocks. Python only gathers the process
facts those helpers used to read from ``os``, ``sys`` and ``Path`` (the
resident cannot see this interpreter), ships one request, verifies that the
answer is bound to it by ``request_id`` and canonical ``request_sha256``, and
returns the decoded result. Every outcome other than a well-formed, ``ok``,
request-bound reply raises ``NativeShimAdminError``; callers fail closed and
never recompute a shim result in Python.
"""

from __future__ import annotations

import itertools
import json
import logging
import os
import sys
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .native_approval_errors import resident_refusal_code
from .native_context import _canonical_request_sha256, _resolve_digest_home, ensure_resident_prerequisite
from .native_resident_client import native_resident_client_request
from .native_runtime import _isolated_environment, _native_error, native_runtime_status
from .native_runtime_resilience import (
    native_record_overload,
    native_record_resident_failure,
    native_record_resident_success,
    native_runtime_health_snapshot,
)
from .sqlite_tuning import SQLITE_CONNECT_TIMEOUT_SECONDS
from .stable_guard_cli import resolve_frozen_guard_cli, trusted_frozen_guard_cli_paths

logger = logging.getLogger(__name__)

UNAVAILABLE = "native_shim_admin_unavailable"
_UNRECORDED_AUDIT_PROOF = frozenset({UNAVAILABLE, "native_overloaded"})
# Exact resident detail for a blank, truncated, or otherwise unusable manifest.
# Other `native_shim_admin_failed` outcomes, including a refused write, still raise.
_STRICT_MANIFEST_DETAIL = "package shim manifest is not strict JSON"
_OPERATION = "shim_admin"
_RESIDENT_PROTOCOL_FEATURE = "resident-protocol-v2"
_FEATURE = "shim-admin-v4"
_REQUEST_SCHEMA = "guard-shim-admin-request.v2"
_RESULT_SCHEMA = "guard-shim-admin-result.v2"
_MAX_REQUEST_BYTES = 512 * 1024
_DEFAULT_TIMEOUT_SECONDS = 30.0
_PROBE_BATCH_CEILING_SECONDS = 600
_PROBE_TRANSPORT_SLACK_SECONDS = 15.0
_PROBE_MANAGER_COUNT = 20
_PROBE_TIMEOUT_SECONDS = int(SQLITE_CONNECT_TIMEOUT_SECONDS) + 5
# The environment keys the non-probe subops read; a probe forwards everything
# because the shim it executes inherits the caller's environment. The Windows
# path model also reads the profile and cwd-search keys from this map, so a
# status or repair subop must see them too.
_ENVIRONMENT_KEYS = (
    "HOME",
    "PATH",
    "PATHEXT",
    "SHELL",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERNAME",
    "NoDefaultCurrentDirectoryInExePath",
)
_RESULT_KEYS = frozenset({"schema", "request_id", "request_sha256", "status", "code", "detail", "result"})
_request_counter = itertools.count(1)
# Contract constant mirrored from guard-command's manager table; a drift test compares it to the resident.
SUPPORTED_PACKAGE_SHIM_MANAGERS: tuple[str, ...] = (
    "brew",
    "bun",
    "bundle",
    "bunx",
    "cargo",
    "composer",
    "go",
    "gradle",
    "mvn",
    "npm",
    "npx",
    "pip",
    "pip3",
    "pipenv",
    "pipx",
    "pnpm",
    "poetry",
    "uv",
    "uvx",
    "yarn",
)


class HarnessContextLike(Protocol):
    @property
    def home_dir(self) -> Path: ...

    @property
    def workspace_dir(self) -> Path | None: ...

    @property
    def guard_home(self) -> Path: ...


class NativeShimAdminError(RuntimeError):
    """The resident could not supply a complete, request-bound shim-admin answer."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _request_id() -> str:
    return f"shim-admin-{os.getpid()}-{next(_request_counter)}"


def _environment(*, full: bool) -> dict[str, str]:
    names: Sequence[str] = tuple(os.environ) if full else _ENVIRONMENT_KEYS
    selected: dict[str, str] = {}
    for name in names:
        value = os.environ.get(name)
        if value is None:
            continue
        try:
            name.encode("utf-8")
            value.encode("utf-8")
        except UnicodeEncodeError:
            continue
        selected[name] = value
    return selected


def _trusted_import_root() -> Path:
    from .shims import _trusted_import_root as trusted_import_root

    return trusted_import_root()


def _facts(*, full_environment: bool, shim_dir: Path) -> dict[str, object]:
    frozen = bool(getattr(sys, "frozen", False))
    argv0 = sys.argv[0] if sys.argv else None
    # Imported here so a test patch of `shims._is_transient_path` is visible.
    # `shims` imports this module at load time.
    from .shims import _is_transient_path

    return {
        "environ": _environment(full=full_environment),
        "home": str(Path.home()),
        "cwd": os.getcwd(),
        "executable": sys.executable,
        "frozen": frozen,
        "frozen_cli": resolve_frozen_guard_cli() if frozen else "",
        "trusted_frozen_cli_paths": sorted(trusted_frozen_guard_cli_paths()) if frozen else [],
        "python_version": [sys.version_info[0], sys.version_info[1]],
        "import_root": str(_trusted_import_root()),
        "argv0": argv0,
        "windows": os.name == "nt",
        "sqlite_connect_timeout_seconds": float(SQLITE_CONNECT_TIMEOUT_SECONDS),
        "now": datetime.now(timezone.utc).isoformat(),
        "shim_dir_transient": _is_transient_path(shim_dir),
    }


def native_shim_admin(
    subop: str,
    *,
    guard_home: Path,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
    managers: Sequence[str] | None = None,
    path_env: str | None = None,
    manager: str | None = None,
    executable: str | None = None,
    command: str | None = None,
    repair: bool | None = None,
    allow_inactive_path: bool | None = None,
    project_shell_profile: bool | None = None,
    timeout_seconds: int | None = None,
    generated_at: str | None = None,
    transport_timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """Run one shim-admin subop in the resident and return its decoded result."""

    deadline = time.monotonic() + transport_timeout_seconds
    status = native_runtime_status(deadline_monotonic=deadline)
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or _RESIDENT_PROTOCOL_FEATURE not in status.capabilities.features
        or _FEATURE not in status.capabilities.features
    ):
        raise NativeShimAdminError(UNAVAILABLE)
    home = _resolve_digest_home(guard_home)
    if native_runtime_health_snapshot(status.identity.sha256, home).circuit_open:
        raise NativeShimAdminError(UNAVAILABLE)
    try:
        if not ensure_resident_prerequisite(home):
            raise NativeShimAdminError(UNAVAILABLE)
        request: dict[str, object] = {
            "schema": _REQUEST_SCHEMA,
            "request_id": _request_id(),
            "subop": subop,
            "guard_home": str(home),
            "home_dir": str(home_dir) if home_dir is not None else None,
            "workspace_dir": str(workspace_dir) if workspace_dir is not None else None,
            "managers": list(managers) if managers is not None else None,
            # Every optional field is sent (as null when unset): the resident
            # digests the request it decoded, which serializes them all.
            "path_env": path_env,
            "manager": manager,
            "executable": executable,
            "command": command,
            "repair": repair,
            "allow_inactive_path": allow_inactive_path,
            "project_shell_profile": project_shell_profile,
            "timeout_seconds": timeout_seconds,
            "generated_at": generated_at,
            "facts": _facts(
                full_environment=subop == "probe_intercepts",
                shim_dir=home / "package-shims" / "bin",
            ),
        }
        request_sha256 = "sha256:" + _canonical_request_sha256(request)
        remaining = deadline - time.monotonic()
        payload = json.dumps(
            {
                "operation": _OPERATION,
                "deadline_budget_ms": max(1, int(remaining * 1000)),
                "request": request,
            },
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (OSError, TypeError, ValueError, RecursionError) as error:
        raise NativeShimAdminError(UNAVAILABLE) from error
    if len(payload) > _MAX_REQUEST_BYTES:
        raise NativeShimAdminError("native_shim_admin_too_large")
    output = native_resident_client_request(
        executable=status.identity.path,
        guard_home=home,
        environment=_isolated_environment(),
        payload=payload,
        deadline_monotonic=deadline,
    )
    return _decode(output, status.identity.sha256, home, request, request_sha256)


def _decode(
    output: bytes | None,
    identity: str,
    home: Path,
    request: Mapping[str, object],
    request_sha256: str,
) -> Any:
    if output is None:
        native_record_resident_failure(identity, home, reason=UNAVAILABLE)
        raise NativeShimAdminError(UNAVAILABLE)
    try:
        decoded: object = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        native_record_resident_failure(identity, home, reason="native_shim_admin_decode_failed")
        raise NativeShimAdminError("native_shim_admin_decode_failed") from error
    if _native_error(decoded) == "native_overloaded":
        native_record_overload(identity, home)
        raise NativeShimAdminError("native_overloaded")
    envelope = decoded if isinstance(decoded, dict) else None
    refusal = resident_refusal_code(envelope)
    if refusal is not None:
        native_record_resident_failure(identity, home, reason=refusal)
        raise NativeShimAdminError(refusal)
    if (
        envelope is None
        or not set(envelope) <= _RESULT_KEYS
        or envelope.get("schema") != _RESULT_SCHEMA
        or envelope.get("request_id") != request["request_id"]
        or envelope.get("request_sha256") != request_sha256
    ):
        native_record_resident_failure(identity, home, reason="native_shim_admin_schema_mismatch")
        raise NativeShimAdminError("native_shim_admin_schema_mismatch")
    native_record_resident_success(identity, home)
    code = envelope.get("code")
    result = envelope.get("result")
    if envelope.get("status") != "ok" or code != "ok" or not isinstance(result, (dict, list)):
        detail = envelope.get("detail")
        raise NativeShimAdminError(
            code if isinstance(code, str) and code != "ok" else "native_shim_admin_invalid_result",
            detail if isinstance(detail, str) else None,
        )
    return result


def _object(subop: str, context: HarnessContextLike, **fields: Any) -> dict[str, object]:
    result = native_shim_admin(
        subop,
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        workspace_dir=fields.pop("workspace_dir", context.workspace_dir),
        **fields,
    )
    if not isinstance(result, dict):
        raise NativeShimAdminError("native_shim_admin_invalid_result")
    return result


def package_shim_status(context: HarnessContextLike, *, path_env: str | None = None) -> dict[str, object]:
    return _object("status", context, path_env=path_env)


def package_shim_digest_binding_sink(
    context: HarnessContextLike,
    *,
    manager: str,
    executable: str,
    command: str | None,
    workspace_dir: Path | None = None,
    path_env: str | None = None,
) -> bool:
    """Does a healthy installed shim own this external-archive download?

    The shim can bind an approval to a digest because it performs the download
    itself, so it owns the approval only when the command is a bare launch of
    that shim. The resident parses the command and resolves the paths; a caller
    that cannot reach it leaves the approval with the user.
    """

    result = _object(
        "digest_binding_sink",
        context,
        manager=manager,
        executable=executable,
        command=command,
        workspace_dir=workspace_dir,
        path_env=path_env,
    )
    bound = result.get("bound")
    if not isinstance(bound, bool):
        raise NativeShimAdminError("native_shim_admin_invalid_result")
    return bound


def package_shim_dashboard_status(context: HarnessContextLike) -> dict[str, object]:
    return _object("dashboard_status", context)


def package_shim_protection(context: HarnessContextLike) -> dict[str, object]:
    """The resident's package-manager protection projection.

    The resident decides which detected managers count as unprotected; callers
    present this block rather than recomputing it.
    """

    return _object("protection_projection", context)


def package_shim_cloud_coverage(
    context: HarnessContextLike,
    *,
    generated_at: str | None = None,
) -> dict[str, object]:
    return _object("cloud_coverage", context, generated_at=generated_at)


def get_path_order_status(
    context: HarnessContextLike,
    *,
    manager: str,
    path_env: str | None = None,
) -> dict[str, object]:
    return _object("path_order", context, manager=manager, path_env=path_env)


def install_package_shims(
    context: HarnessContextLike,
    *,
    managers: tuple[str, ...] | None = None,
    path_env: str | None = None,
) -> dict[str, object]:
    return _object("install", context, managers=managers, path_env=path_env)


def activate_package_shims(
    context: HarnessContextLike,
    *,
    managers: tuple[str, ...] | None = None,
    repair: bool = False,
) -> dict[str, object]:
    return _object("activate", context, managers=managers, repair=repair)


def repair_package_shims(
    context: HarnessContextLike,
    *,
    managers: tuple[str, ...] | None = None,
    path_env: str | None = None,
) -> dict[str, object]:
    return _object("repair", context, managers=managers, path_env=path_env)


def uninstall_package_shims(
    context: HarnessContextLike,
    *,
    managers: tuple[str, ...] | None = None,
) -> dict[str, object]:
    return _object("uninstall", context, managers=managers)


def ensure_package_shim_path_in_shell_profile(context: HarnessContextLike) -> dict[str, object]:
    return _object("ensure_package_shim_profile", context)


def remove_guard_profile_blocks(context: HarnessContextLike) -> dict[str, object]:
    return _object("remove_guard_profile_blocks", context)


def probe_package_shim_intercepts(
    context: HarnessContextLike,
    *,
    managers: tuple[str, ...] | None = None,
    workspace_dir: Path | None = None,
    allow_inactive_path: bool = False,
    project_shell_profile: bool = False,
    timeout_seconds: int = _PROBE_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Execute the installed shims natively to prove intercept wiring is live."""

    count = max(1, len(managers) if managers else _PROBE_MANAGER_COUNT)
    # Each manager gets an equal share of the batch ceiling, as the resident
    # does, so a full slow batch finishes inside the transport deadline.
    per_probe = max(1, min(int(timeout_seconds), _PROBE_BATCH_CEILING_SECONDS // count))
    budget = per_probe * count
    return _object(
        "probe_intercepts",
        context,
        managers=managers,
        workspace_dir=workspace_dir if workspace_dir is not None else context.workspace_dir,
        allow_inactive_path=allow_inactive_path,
        project_shell_profile=project_shell_profile,
        timeout_seconds=per_probe,
        transport_timeout_seconds=float(budget) + _PROBE_TRANSPORT_SLACK_SECONDS,
    )


def package_shim_supported_managers(guard_home: Path | None = None) -> tuple[str, ...]:
    """Return the supported manager names (a static contract; ``guard_home`` is accepted for compatibility)."""

    del guard_home
    return SUPPORTED_PACKAGE_SHIM_MANAGERS


def record_package_shim_audit_result(guard_home: Path, *, audited_at: str | None = None) -> dict[str, object]:
    """Stamp ``last_audit_at``. The resident owns the write.

    A resident that is unavailable or overloaded, and a manifest that is not
    strict JSON, leaves the finished audit unstamped and reports that. This
    does not write the manifest in Python and does not authorize anything.
    A refused write still raises.
    """

    try:
        native_shim_admin("record_audit", guard_home=guard_home, generated_at=audited_at)
    except NativeShimAdminError as error:
        unrecorded = error.code in _UNRECORDED_AUDIT_PROOF or (
            error.code == "native_shim_admin_failed" and error.detail == _STRICT_MANIFEST_DETAIL
        )
        if unrecorded:
            logger.warning("package shim audit proof was not recorded: %s", error.code)
            return {"audit_proof_recorded": False, "audit_proof_error": error.code}
        raise
    return {"audit_proof_recorded": True}

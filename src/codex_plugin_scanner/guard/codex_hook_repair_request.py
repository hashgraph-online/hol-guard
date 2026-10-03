"""Private captured repair plans for review, never forward authorization.

The file preserves the exact UUID, subject and dependencies between preparation
and authentication. Loading cannot grant repair or select a different runtime.
Factors and grants are deliberately absent from this protocol.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import time
import uuid
from dataclasses import replace
from pathlib import Path
from typing import cast

from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_integrity import canonical_manifest_bytes, hook_manifest_path, load_hook_secret
from .codex_hook_manifest import CODEX_AUTHORITY_REPAIR_ACTION, CodexHookManifestSpec, PreparedCodexHookRepair
from .codex_hook_recovery import _decode, load_hook_authority_receipt
from .codex_publication_inverse_plan import (
    PreparedCodexPublicationInverse,
    bind_codex_publication_inverse_verification,
    prepare_authenticated_hook_publication_inverse,
)
from .durable_io import fsync_directory
from .local_authority_integrity import sign_local_authority_payload, verify_local_authority_payload
from .native_runtime import NativeRuntimeIdentity
from .private_file_io import (
    _private_directory_metadata_is_valid,
    _stable_directory_metadata,
    read_private_regular_bytes,
)
from .runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionFile,
    _record_files,
    inverse_recovery_budget,
)

_SCHEMA = "hol-guard.codex-authority-repair-request.v1"
_PURPOSE = "codex-authority-repair-request"
_MAX_REQUEST = 8 * 1024 * 1024
_REVIEW_SECONDS = 300.0
# Canonical JSON preserves each timestamp. Subtracting the loaded values can
# exceed the signed window by a few ulps. One microsecond covers that error.
_REVIEW_TIMESTAMP_SLACK_SECONDS = 1e-6
_INVERSE_SCHEMA = "hol-guard.codex-publication-inverse-request.v1"
_INVERSE_PURPOSE = "codex-publication-inverse-request"
RepairPlan = PreparedCodexHookRepair | PreparedCodexPublicationInverse


def _inverse_from_payload(
    value: object,
    spec: CodexHookManifestSpec,
    deadline: float,
) -> PreparedCodexPublicationInverse:
    # Reconstruct targets and predecessor bytes from the authenticated live WAL.
    # Serialized targets and dependencies never independently confer authority.
    if not isinstance(value, dict):
        raise TransitionError("authority_repair_request_plan_invalid")
    native = value.get("native_runtime")
    operation = value.get("operation_id")
    workspace = value.get("verification_workspace")
    if (
        not isinstance(native, dict)
        or set(native) != {"path", "size", "mtime_ns", "sha256"}
        or not isinstance(native["path"], str)
        or not isinstance(native["sha256"], str)
        or type(native["size"]) is not int
        or type(native["mtime_ns"]) is not int
        or not isinstance(operation, str)
        or not isinstance(workspace, str)
    ):
        raise TransitionError("authority_repair_request_plan_invalid")
    if str(uuid.UUID(operation)) != operation:
        raise TransitionError("authority_repair_request_plan_invalid")
    with inverse_recovery_budget(deadline), hook_validation_deadline(deadline):
        fresh = prepare_authenticated_hook_publication_inverse(spec)
        bound = bind_codex_publication_inverse_verification(
            replace(fresh, operation_id=operation),
            expected_runtime=NativeRuntimeIdentity(
                Path(native["path"]), native["size"], native["mtime_ns"], native["sha256"]
            ),
            workspace=Path(workspace),
            deadline_monotonic=deadline,
        )
    if bound.payload() != value:
        raise TransitionError("authority_repair_request_plan_invalid")
    return bound


def _check_deadline(deadline: float) -> None:
    if isinstance(deadline, bool) or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise TransitionError("deadline_exceeded")


def _plan_from_payload(value: object, *, home: Path, config: Path) -> PreparedCodexHookRepair:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "action",
        "guard_home",
        "config_path",
        "operation_id",
        "files",
        "native_runtime",
        "verification_workspace",
    }:
        raise TransitionError("authority_repair_request_plan_invalid")
    if (
        value["schema"] != "hol-guard.codex-authority-repair-plan.v1"
        or value["action"] != CODEX_AUTHORITY_REPAIR_ACTION
        or value["guard_home"] != str(home)
        or value["config_path"] != str(config)
        or not isinstance(value["operation_id"], str)
        or not isinstance(value["verification_workspace"], str)
    ):
        raise TransitionError("authority_repair_request_context_invalid")
    native = value["native_runtime"]
    if (
        not isinstance(native, dict)
        or set(native) != {"path", "size", "mtime_ns", "sha256"}
        or not isinstance(native["path"], str)
        or not isinstance(native["sha256"], str)
        or type(native["size"]) is not int
        or type(native["mtime_ns"]) is not int
    ):
        raise TransitionError("authority_repair_request_plan_invalid")
    files = tuple(
        TransitionFile(
            path=Path(str(item["path"])),
            before=_decode(item["before"]),
            after=_decode(item["after"]),
            before_mode=cast(int, item["before_mode"]),
            after_mode=cast(int, item["after_mode"]),
            kind=cast(str, item["kind"]),
            no_follow=cast(bool, item.get("no_follow", False)),
            expected_digest=cast(str | None, item.get("expected_digest")),
            artifact_identity=cast(dict[str, object] | None, item.get("artifact_identity")),
            invocation_identity=cast(dict[str, object] | None, item.get("invocation_identity")),
        )
        for item in _record_files(value)
    )
    changes = [item for item in files if item.path == hook_manifest_path(home, config)]
    if len(changes) != 1:
        raise TransitionError("authority_repair_request_plan_invalid")
    plan = PreparedCodexHookRepair(
        changes[0],
        files,
        home,
        config,
        value["operation_id"],
        NativeRuntimeIdentity(
            Path(native["path"]), cast(int, native["size"]), cast(int, native["mtime_ns"]), native["sha256"]
        ),
        Path(value["verification_workspace"]),
    )
    # Refuse normalization that silently changes a reviewed payload.
    if plan.payload() != value:
        raise TransitionError("authority_repair_request_plan_invalid")
    return plan


def _compare(plan: RepairPlan, deadline: float) -> None:
    _check_deadline(deadline)
    with inverse_recovery_budget(deadline), hook_validation_deadline(deadline):
        if isinstance(plan, PreparedCodexPublicationInverse):
            plan.compare_before()
            _check_deadline(deadline)
            return
        RuntimeTransition._compare(plan.payload(), "before")
        receipt = load_hook_authority_receipt(plan.guard_home, plan.config_path)
        if receipt.manifest_bytes != plan.manifest_change.after:
            raise TransitionError("authority_repair_request_plan_invalid")
        RuntimeTransition._compare(plan.payload(), "before")
    _check_deadline(deadline)


def write_codex_hook_repair_request(
    path: Path,
    plan: RepairPlan,
    *,
    deadline_monotonic: float,
) -> str:
    """Exclusively create a private review artifact; return its exact digest."""
    _check_deadline(deadline_monotonic)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise TransitionError("authority_repair_request_path_invalid")
    parent_before = path.parent.lstat()
    if not _private_directory_metadata_is_valid(parent_before):
        raise TransitionError("authority_repair_request_path_invalid")
    inverse = isinstance(plan, PreparedCodexPublicationInverse)
    if not inverse:
        plan = _plan_from_payload(plan.payload(), home=plan.guard_home, config=plan.config_path)
    _compare(plan, deadline_monotonic)
    secret = load_hook_secret(plan.guard_home)
    created = time.monotonic()
    payload: dict[str, object] = {
        "schema": _INVERSE_SCHEMA if inverse else _SCHEMA,
        "guard_home": str(plan.guard_home),
        "config_path": str(plan.config_path),
        "installation_id": secret.installation_id,
        "created_monotonic": created,
        "expires_monotonic": created + _REVIEW_SECONDS,
        "plan": plan.payload(),
        "subject": plan.subject(),
    }
    payload["authentication"] = sign_local_authority_payload(
        payload,
        key=secret.key,
        key_id=secret.key_id,
        purpose=_INVERSE_PURPOSE if inverse else _PURPOSE,
        signed_at=plan.operation_id,
    )
    encoded = canonical_manifest_bytes(payload) + b"\n"
    if len(encoded) > _MAX_REQUEST:
        raise TransitionError("authority_repair_request_too_large")
    _compare(plan, deadline_monotonic)
    parent_fd = None
    descriptor = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        if os.name != "nt":
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            if not _stable_directory_metadata(parent_before, os.fstat(parent_fd)):
                raise TransitionError("authority_repair_request_path_invalid")
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        else:
            descriptor = os.open(path, flags, 0o600)
        offset = 0
        while offset < len(encoded):
            _check_deadline(deadline_monotonic)
            written = os.write(descriptor, encoded[offset : offset + 64 * 1024])
            if written <= 0:
                raise OSError("Repair request write made no progress")
            offset += written
        os.fsync(descriptor)
        if not _stable_directory_metadata(parent_before, path.parent.lstat()):
            raise TransitionError("authority_repair_request_path_invalid")
        fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_fd is not None:
            os.close(parent_fd)
    if read_private_regular_bytes(path, max_bytes=_MAX_REQUEST, require_private_parent=True) != encoded:
        raise TransitionError("authority_repair_request_changed")
    _compare(plan, deadline_monotonic)
    return hashlib.sha256(encoded).hexdigest()


def load_codex_hook_repair_request(
    path: Path,
    *,
    guard_home: Path,
    config_path: Path,
    expected_sha256: str,
    deadline_monotonic: float,
    inverse_spec: CodexHookManifestSpec | None = None,
) -> RepairPlan:
    """Authenticate and compare the captured plan; never regenerate or grant."""
    _check_deadline(deadline_monotonic)
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(char not in "0123456789abcdef" for char in expected_sha256)
    ):
        raise TransitionError("authority_repair_request_digest_invalid")
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise TransitionError("authority_repair_request_path_invalid")
    raw = read_private_regular_bytes(path, max_bytes=_MAX_REQUEST, require_private_parent=True)
    if raw is None or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise TransitionError("authority_repair_request_changed")
    _check_deadline(deadline_monotonic)
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise TransitionError("authority_repair_request_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema",
        "guard_home",
        "config_path",
        "installation_id",
        "created_monotonic",
        "expires_monotonic",
        "plan",
        "subject",
        "authentication",
    }:
        raise TransitionError("authority_repair_request_invalid")
    home = guard_home.resolve(strict=False)
    config = config_path.parent.resolve(strict=False) / config_path.name
    inverse = inverse_spec is not None
    if (
        payload["schema"] != (_INVERSE_SCHEMA if inverse else _SCHEMA)
        or payload["guard_home"] != str(home)
        or payload["config_path"] != str(config)
    ):
        raise TransitionError("authority_repair_request_context_invalid")
    authentication = payload.pop("authentication")
    secret = load_hook_secret(home)
    if (
        not isinstance(authentication, dict)
        or set(authentication)
        != {
            "integrity_version",
            "payload_hash",
            "payload_mac",
            "integrity_key_id",
            "signed_at",
        }
        or type(authentication["integrity_version"]) is not int
        or payload["installation_id"] != secret.installation_id
    ):
        raise TransitionError("authority_repair_request_authentication_invalid")
    try:
        verification = verify_local_authority_payload(
            payload,
            authentication,
            key=secret.key,
            key_id=secret.key_id,
            purpose=_INVERSE_PURPOSE if inverse else _PURPOSE,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise TransitionError("authority_repair_request_authentication_invalid") from exc
    if verification.status != "valid":
        raise TransitionError("authority_repair_request_authentication_invalid")
    created, expires = payload["created_monotonic"], payload["expires_monotonic"]
    timestamps_are_real = (
        isinstance(created, (int, float))
        and not isinstance(created, bool)
        and math.isfinite(created)
        and isinstance(expires, (int, float))
        and not isinstance(expires, bool)
        and math.isfinite(expires)
    )
    window = expires - created if timestamps_are_real else 0.0
    if (
        not timestamps_are_real
        or not 0 < window <= _REVIEW_SECONDS + _REVIEW_TIMESTAMP_SLACK_SECONDS
        or not created <= time.monotonic() < expires
    ):
        raise TransitionError("authority_repair_request_expired")
    plan = (
        _inverse_from_payload(payload["plan"], inverse_spec, deadline_monotonic)
        if inverse_spec is not None
        else _plan_from_payload(payload["plan"], home=home, config=config)
    )
    if authentication.get("signed_at") != plan.operation_id or payload["subject"] != plan.subject():
        raise TransitionError("authority_repair_request_plan_invalid")
    _compare(plan, deadline_monotonic)
    if read_private_regular_bytes(path, max_bytes=_MAX_REQUEST, require_private_parent=True) != raw:
        raise TransitionError("authority_repair_request_changed")
    if not created <= time.monotonic() < expires:
        raise TransitionError("authority_repair_request_expired")
    _check_deadline(deadline_monotonic)
    return plan

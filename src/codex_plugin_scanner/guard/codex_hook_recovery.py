"""Authenticated inverse of an interrupted Codex manifest/config publication.

This record authorizes an exact inverse of config, manifest and the retained
authority receipt, never another install or a forward replay. Records without
a signed config identity require explicit recovery. The home-wide installer lock
must cover the record's entire lifetime. Snapshots remain private and are not
diagnostic/export material.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .codex_hook_authority_record import (
    AuthorityRecordRefusedError,
    check_receipt_manifest,
    open_authority_record,
    seal_authority_record,
)
from .codex_hook_authority_record import repair_proof_matches as native_repair_proof_matches
from .codex_hook_file_integrity import CodexHookIntegrityError, canonical_path, check_hook_validation_deadline
from .codex_hook_integrity import (
    HookSecretMaterial,
    atomic_write_bytes,
    authenticate_hook_manifest_text,
    hook_authority_receipt_path,
    hook_manifest_path,
    load_hook_secret,
    remove_hook_secret_if_unused,
    restore_private_file,
)
from .codex_hook_rollback import rollback_file_identity
from .codex_install_transaction import require_codex_install_owner
from .durable_io import fsync_directory
from .private_file_io import read_private_regular_bytes, read_private_regular_text

if TYPE_CHECKING:
    from .codex_hook_repair import PendingCodexHookRepair

_PURPOSE = "codex-hook-publication-inverse"
_SCHEMA = "hol-guard.codex-hook-recovery.v1"
_MAX_SNAPSHOT = 4 * 1024 * 1024
_MAX_RECORD = 24 * 1024 * 1024
_RECEIPT_SCHEMA = "hol-guard.codex-hook-authority-receipt.v1"
_RECEIPT_PURPOSE = "codex-hook-authority-receipt"


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedHookAuthorityReceipt:
    """Captured bytes for a future exact plan; never a lifecycle grant."""

    manifest_bytes: bytes
    receipt_bytes: bytes
    config_bytes: bytes


def load_hook_authority_receipt(home: Path, config: Path) -> AuthenticatedHookAuthorityReceipt:
    """Read exact retained authority under the caller's validation deadline.

    Authentication alone cannot authorize restoration. A repair planner must
    additionally pin these files/key, validate package and registration, and
    obtain fresh exact lifecycle approval before publishing anything.
    """
    check_hook_validation_deadline()
    path = hook_authority_receipt_path(home, config)
    raw = read_private_regular_bytes(path, max_bytes=_MAX_SNAPSHOT, require_private_parent=True)
    check_hook_validation_deadline()
    if raw is None:
        raise _error("receipt_invalid")
    secret = load_hook_secret(home)
    check_hook_validation_deadline()
    try:
        payload, _signed_at = open_authority_record(
            "receipt", raw, secret, guard_home=canonical_path(home), config_path=canonical_path(config)
        )
    except AuthorityRecordRefusedError as exc:
        raise _error(exc.reason) from exc
    check_hook_validation_deadline()
    manifest_bytes = _decode(payload["manifest"])
    if manifest_bytes is None:
        raise _error("receipt_invalid")
    try:
        manifest = authenticate_hook_manifest_text(home, manifest_bytes.decode("utf-8"), _secret=secret)
    except UnicodeDecodeError as exc:
        raise _error("receipt_invalid") from exc
    try:
        check_receipt_manifest(manifest, secret, guard_home=canonical_path(home), config_path=canonical_path(config))
    except AuthorityRecordRefusedError as exc:
        raise _error(exc.reason) from exc
    check_hook_validation_deadline()
    config_bytes = _snapshot(config)
    if config_bytes is None or payload["config_sha256"] != hashlib.sha256(config_bytes).hexdigest():
        raise _error("receipt_generation_changed")
    check_hook_validation_deadline()
    if (
        read_private_regular_bytes(path, max_bytes=_MAX_SNAPSHOT, require_private_parent=True) != raw
        or _snapshot(config) != config_bytes
    ):
        raise _error("receipt_generation_changed")
    if load_hook_secret(home) != secret:
        raise _error("receipt_generation_changed")
    check_hook_validation_deadline()
    return AuthenticatedHookAuthorityReceipt(manifest_bytes, raw, config_bytes)


def build_hook_authority_receipt(home: Path, config: Path, *, config_bytes: bytes, manifest_bytes: bytes) -> bytes:
    """Retain exact authority, without granting permission to restore it."""
    secret = load_hook_secret(home)
    payload: dict[str, object] = {
        "schema": _RECEIPT_SCHEMA,
        "guard_home": canonical_path(home),
        "config_path": canonical_path(config),
        "installation_id": secret.installation_id,
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "manifest": _encode(manifest_bytes),
    }
    try:
        return seal_authority_record("receipt", payload, secret)
    except AuthorityRecordRefusedError as exc:
        raise _error(exc.reason) from exc


def _record_path(home: Path) -> Path:
    # One pending publication per home, including installations of other targets.
    return home / "managed" / "codex" / "pending-hook-publication.json"


def hook_publication_pending(home: Path) -> bool:
    path = _record_path(home)
    return path.exists() or path.is_symlink()


def _encode(value: bytes | None) -> str | None:
    if value is None:
        return None
    if len(value) > _MAX_SNAPSHOT:
        raise _error("snapshot_too_large")
    return base64.b64encode(value).decode("ascii")


def _decode(value: object) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 4 * ((_MAX_SNAPSHOT + 2) // 3):
        raise _error("snapshot_invalid")
    try:
        result = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise _error("snapshot_invalid") from exc
    if len(result) > _MAX_SNAPSHOT:
        raise _error("snapshot_too_large")
    return result


def _error(reason: str) -> CodexHookIntegrityError:
    return CodexHookIntegrityError(
        f"codex_hook_recovery_{reason}",
        "Codex publication needs recovery; Guard preserved the recovery record and current files.",
    )


def _snapshot(path: Path) -> bytes | None:
    check_hook_validation_deadline()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        check_hook_validation_deadline()
        if path.is_symlink():
            raise _error("target_invalid") from None
        return None
    except OSError as exc:
        check_hook_validation_deadline()
        raise _error("target_invalid") from exc
    with os.fdopen(descriptor, "rb") as handle:
        check_hook_validation_deadline()
        opened = os.fstat(handle.fileno())
        check_hook_validation_deadline()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > _MAX_SNAPSHOT
            or (os.name != "nt" and opened.st_uid != os.geteuid())
            or getattr(opened, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise _error("target_invalid")
        value = handle.read(_MAX_SNAPSHOT + 1)
        check_hook_validation_deadline()
        current = path.lstat()
        check_hook_validation_deadline()
        if len(value) > _MAX_SNAPSHOT or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise _error("target_changed")
        return value


def prepare_hook_publication(
    home: Path,
    config: Path,
    *,
    before_config: bytes | None,
    before_manifest: bytes | None,
    after_config: bytes,
    after_manifest: bytes,
    key_created: bool,
    before_receipt: bytes | None = None,
    after_receipt: bytes | None = None,
    repair_plan: dict[str, object] | None = None,
    repair_publication_monotonic: float | None = None,
) -> None:
    owner = require_codex_install_owner(home)
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(home)
    path = _record_path(home)
    if path.exists() or path.is_symlink():
        raise _error("pending")
    if after_receipt is None and before_receipt is not None:
        raise _error("snapshot_invalid")
    before_config_identity = rollback_file_identity(config)
    if _snapshot(config) != before_config or _snapshot(hook_manifest_path(home, config)) != before_manifest:
        raise _error("generation_changed")
    if after_receipt is not None and _snapshot(hook_authority_receipt_path(home, config)) != before_receipt:
        raise _error("generation_changed")
    if rollback_file_identity(config) != before_config_identity:
        raise _error("generation_changed")
    secret = load_hook_secret(home)
    payload: dict[str, object] = {
        "schema": _SCHEMA,
        "phase": "prepared",
        "operation_id": owner.operation_id,
        "guard_home": canonical_path(home),
        "config_path": canonical_path(config),
        "installation_id": secret.installation_id,
        "key_created": key_created,
        "before_config": _encode(before_config),
        "before_config_identity": list(before_config_identity) if before_config_identity is not None else None,
        "before_manifest": _encode(before_manifest),
        "after_config": _encode(after_config),
        "after_manifest": _encode(after_manifest),
    }
    if after_receipt is not None:
        payload.update(before_receipt=_encode(before_receipt), after_receipt=_encode(after_receipt))
    if repair_plan is not None:
        payload["repair_plan"] = repair_plan
        payload["repair_publication_monotonic"] = repair_publication_monotonic
    elif repair_publication_monotonic is not None:
        raise _error("repair_record_invalid")
    encoded = _seal_record(payload, secret, signed_at=owner.operation_id)
    atomic_write_bytes(path, encoded, mode=0o600, private=True)


def _seal_record(payload: dict[str, object], secret: HookSecretMaterial, *, signed_at: str) -> bytes:
    try:
        encoded = seal_authority_record("recovery", payload, secret, signed_at=signed_at)
    except AuthorityRecordRefusedError as exc:
        raise _error(exc.reason) from exc
    if len(encoded) > _MAX_RECORD:
        # Readers cap the record at the same size.
        raise _error("record_too_large")
    return encoded


def _repair_proof_matches(payload: dict[str, object], proof: dict[str, object]) -> bool:
    try:
        return native_repair_proof_matches(payload, proof)
    except AuthorityRecordRefusedError as exc:
        raise _error(exc.reason) from exc


def assert_owned_hook_repair_publication(
    home: Path,
    config: Path,
    *,
    repair_plan: dict[str, object],
    config_bytes: bytes,
    manifest_bytes: bytes,
    receipt_bytes: bytes,
    publication_monotonic: float,
) -> None:
    """Accept only the authenticated, exact provisional record owned now."""
    owner = require_codex_install_owner(home)
    payload = _load_record(home)
    expected = {
        "operation_id": owner.operation_id,
        "config_path": canonical_path(config),
        "repair_plan": repair_plan,
        "phase": "prepared",
        "key_created": False,
        "repair_publication_monotonic": publication_monotonic,
        "before_config": _encode(config_bytes),
        "after_config": _encode(config_bytes),
        "before_manifest": None,
        "after_manifest": _encode(manifest_bytes),
        "before_receipt": _encode(receipt_bytes),
        "after_receipt": _encode(receipt_bytes),
    }
    if any(payload.get(key) != value for key, value in expected.items()):
        raise _error("repair_owner_mismatch")


def _load_record(home: Path, *, live_config_conflict: bool = False) -> dict[str, object]:
    check_hook_validation_deadline()
    path = _record_path(home)
    raw = read_private_regular_text(path, max_bytes=_MAX_RECORD)
    check_hook_validation_deadline()
    if raw is None:
        raise _error("record_invalid")
    secret = load_hook_secret(home)
    check_hook_validation_deadline()
    try:
        payload, _signed_at = open_authority_record(
            "recovery",
            raw,
            secret,
            guard_home=canonical_path(home),
            live_config_conflict=live_config_conflict,
        )
    except AuthorityRecordRefusedError as exc:
        raise _error(exc.reason) from exc
    return payload


def _record_authentication_targets(home: Path, payload: dict[str, object]) -> tuple[Path, Path]:
    # Hash the authenticated original target, never a substituted live symlink.
    target_hash = hashlib.sha256(str(payload["config_path"]).encode("utf-8")).hexdigest()[:24]
    manifest = home / "managed" / "codex" / f"hooks-{target_hash}.manifest.json"
    return manifest, manifest.with_name(f"hooks-{target_hash}.authority-receipt.json")


def _config_publication_slot(path: Path) -> str:
    """Return the config slot without following a substituted leaf symlink.

    Preparation records the resolved regular file. Replacing that leaf with a
    symlink must not move the publication onto the foreign target.
    """
    candidate = path.expanduser()
    return str(candidate.parent.resolve(strict=False) / candidate.name)


def mark_owned_hook_publication_conflict(home: Path, config: Path) -> None:
    """Durably refuse an inverse after this live owner sees a competing config.

    Ordinary crash recovery cannot select this mode. Only the still-held
    preparation owner may mark it. Every participant remains untouched and
    automatic recovery must retain the unresolved record, even for equal bytes.
    """
    owner = require_codex_install_owner(home)
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(home)
    payload = _load_record(home, live_config_conflict=True)
    if (
        payload.get("operation_id") != owner.operation_id
        or payload.get("config_path") != _config_publication_slot(config)
        or payload.get("phase") != "prepared"
        or "repair_plan" in payload
    ):
        raise _error("conflict_owner_mismatch")
    # Refuse to overwrite a competing authentication generation as well.
    manifest, receipt = _record_authentication_targets(home, payload)
    targets = [(manifest, "before_manifest", "after_manifest")]
    if "after_receipt" in payload:
        targets.append((receipt, "before_receipt", "after_receipt"))
    for target, before, after in targets:
        if _snapshot(target) not in (_decode(payload.get(before)), _decode(payload.get(after))):
            raise _error("generation_changed")
    payload["phase"] = "config_conflict"
    encoded = _seal_record(payload, load_hook_secret(home), signed_at=owner.operation_id)
    atomic_write_bytes(_record_path(home), encoded, mode=0o600, private=True)


def record_owned_hook_config_publication(home: Path, config: Path, identity: tuple[int, int, int, int, int]) -> None:
    """Make the observed published inode durable before accepting readback.

    A crash after rename but before this record remains recovery-required;
    matching bytes alone cannot prove that the pending writer owns the inode.
    """
    owner = require_codex_install_owner(home)
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(home)
    payload = _load_record(home)
    if (
        payload.get("operation_id") != owner.operation_id
        or payload.get("phase") != "prepared"
        or payload.get("config_path") != canonical_path(config)
        or "repair_plan" in payload
    ):
        raise _error("config_publication_owner_mismatch")
    if (
        rollback_file_identity(config) != identity
        or _snapshot(config) != _decode(payload.get("after_config"))
        or rollback_file_identity(config) != identity
    ):
        raise _error("generation_changed")
    payload["after_config_identity"] = list(identity)
    encoded = _seal_record(payload, load_hook_secret(home), signed_at=owner.operation_id)
    atomic_write_bytes(_record_path(home), encoded, mode=0o600, private=True)


def _require_recorded_config_identity(payload: dict[str, object], config: Path) -> None:
    if "before_config_identity" not in payload:
        raise _error("config_identity_missing")
    current = rollback_file_identity(config)
    encoded = list(current) if current is not None else None
    value = _snapshot(config)
    if rollback_file_identity(config) != current:
        raise _error("generation_changed")
    if (
        (payload.get("phase") != "committed" or "repair_plan" in payload)
        and encoded == payload["before_config_identity"]
        and value == _decode(payload.get("before_config"))
    ):
        return
    if (
        "after_config_identity" in payload
        and encoded == payload["after_config_identity"]
        and value == _decode(payload.get("after_config"))
    ):
        return
    raise _error("generation_changed")


def recover_hook_publication(home: Path) -> bool:
    """Idempotent inverse under exclusive ownership, with an all-file CAS check."""
    require_codex_install_owner(home)
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(home)
    path = _record_path(home)
    if not path.exists() and not path.is_symlink():
        return False
    payload = _load_record(home)
    if "publication_inverse" in payload:
        raise _error("explicit_inverse_pending")
    if payload["phase"] == "config_conflict":
        raise _error("config_conflict")
    config = Path(str(payload["config_path"]))
    _require_recorded_config_identity(payload, config)
    manifest, receipt = _record_authentication_targets(home, payload)
    changes = [
        (config, _decode(payload.get("before_config")), _decode(payload.get("after_config"))),
        (manifest, _decode(payload.get("before_manifest")), _decode(payload.get("after_manifest"))),
    ]
    if "after_receipt" in payload or "before_receipt" in payload:
        if "after_receipt" not in payload or "before_receipt" not in payload:
            raise _error("record_invalid")
        changes.append((receipt, _decode(payload["before_receipt"]), _decode(payload["after_receipt"])))
    # Validate both before modifying either: a foreign edit or newer generation
    # must survive, even if the other file still matches this transaction.
    committed = payload["phase"] == "committed"
    for target, before, after in changes:
        allowed = (after,) if committed else (before, after)
        if _snapshot(target) not in allowed:
            raise _error("generation_changed")
    if committed:
        _remove_record(home)
        return False
    # Restore authority participants before the config. If recovery itself is
    # interrupted after replacing the config, its unknown inode must survive
    # for explicit recovery rather than being accepted on matching bytes.
    restore_order = changes[1:] + changes[:1]
    for target, before, _after in restore_order:
        if target == config:
            _require_recorded_config_identity(payload, config)
        if _snapshot(target) != before:
            restore_private_file(target, before)
    for target, before, _after in changes:
        if _snapshot(target) != before:
            raise _error("readback_failed")
    _remove_record(home)
    if payload.get("key_created") is True:
        remove_hook_secret_if_unused(home)
    return True


def commit_hook_publication(home: Path) -> None:
    # The adapter calls this only after authenticated native hook readback.
    require_codex_install_owner(home)
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(home)
    payload = _load_record(home)
    if "publication_inverse" in payload:
        raise _error("explicit_inverse_pending")
    if "repair_plan" in payload:
        raise _error("repair_requires_native_verification")
    config = Path(str(payload["config_path"]))
    if _snapshot(config) != _decode(payload["after_config"]) or _snapshot(hook_manifest_path(home, config)) != _decode(
        payload["after_manifest"]
    ):
        raise _error("generation_changed")
    if "after_receipt" in payload and _snapshot(hook_authority_receipt_path(home, config)) != _decode(
        payload["after_receipt"]
    ):
        raise _error("generation_changed")
    _commit_record(home, payload)


def _commit_verified_hook_repair_publication(
    pending: PendingCodexHookRepair,
    *,
    proof: object,
    started_monotonic: float,
) -> None:
    """Only an exact live authorization and sealed configured-hook proof commit."""
    import time

    from .runtime_transition_admission import verified_admission_payload

    pending.compare("after")
    plan = pending.authorization.plan
    payload = _load_record(plan.guard_home)
    observation = verified_admission_payload(proof)
    observed = observation.get("observed_monotonic")
    if (
        type(started_monotonic) not in (float, int)
        or not math.isfinite(started_monotonic)
        or not isinstance(observed, (float, int))
        or isinstance(observed, bool)
        or not math.isfinite(observed)
        or not pending.publication_monotonic <= started_monotonic <= observed <= time.monotonic()
        or not _repair_proof_matches(payload, observation)
    ):
        raise _error("repair_native_verification_invalid")
    pending.compare("after")
    payload["native_verification"] = observation
    _commit_record(plan.guard_home, payload)


def _commit_record(home: Path, payload: dict[str, object]) -> None:
    payload["phase"] = "committed"
    _require_recorded_config_identity(payload, Path(str(payload["config_path"])))
    # Publish the commit before cleanup. A crash during cleanup must retain the
    # authenticated candidate, rather than applying the predecessor inverse.
    encoded = _seal_record(payload, load_hook_secret(home), signed_at=str(payload["operation_id"]))
    atomic_write_bytes(_record_path(home), encoded, mode=0o600, private=True)
    _remove_record(home)


def _remove_record(home: Path) -> None:
    path = _record_path(home)
    if path.is_symlink():
        raise _error("record_invalid")
    path.unlink()
    fsync_directory(path.parent)

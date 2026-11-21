"""Authenticated inverse of an interrupted Codex manifest/config publication.

This record authorizes an exact inverse of config, manifest and the retained
authority receipt, never another install or a forward replay. Records without
a signed config identity require explicit recovery. The home-wide installer lock
must cover the record's entire lifetime. Snapshots remain private and are not
diagnostic/export material.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .codex_hook_file_integrity import CodexHookIntegrityError, check_hook_validation_deadline
from .native_owned import require_codex_install_owner

if TYPE_CHECKING:
    from .codex_hook_repair import PendingCodexHookRepair

_PURPOSE = "codex-hook-publication-inverse"
_MAX_SNAPSHOT = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticatedHookAuthorityReceipt:
    """Captured bytes for a future exact plan; never a lifecycle grant."""

    manifest_bytes: bytes
    receipt_bytes: bytes
    config_bytes: bytes


def load_hook_authority_receipt(
    home: Path,
    config: Path,
    *,
    require_manifest: tuple[bytes | None, str] | None = None,
) -> AuthenticatedHookAuthorityReceipt:
    """Read exact retained authority under the caller's validation deadline.

    `require_manifest` names the manifest bytes the receipt must retain and the
    refusal the runtime raises when it retains others.

    Authentication alone cannot authorize restoration. A repair planner must
    additionally pin these files/key, validate package and registration, and
    obtain fresh exact lifecycle approval before publishing anything.
    """
    check_hook_validation_deadline()
    fields: dict[str, object] = {}
    if require_manifest is not None:
        fields = {"expect_manifest": _encode(require_manifest[0]), "mismatch": require_manifest[1]}
    answer = _publication("receipt_load", home, config=_path_text(config), **fields)
    if not isinstance(answer, dict):
        raise _error("receipt_invalid")
    manifest, receipt, config_bytes = (_decode(answer.get(key)) for key in ("manifest", "receipt", "config"))
    if manifest is None or receipt is None or config_bytes is None:
        raise _error("receipt_invalid")
    check_hook_validation_deadline()
    return AuthenticatedHookAuthorityReceipt(manifest, receipt, config_bytes)


def build_hook_authority_receipt(home: Path, config: Path, *, config_bytes: bytes, manifest_bytes: bytes) -> bytes:
    """Retain exact authority, without granting permission to restore it."""
    text = _publication(
        "receipt_build",
        home,
        config=_path_text(config),
        config_bytes=_encode(config_bytes),
        manifest_bytes=_encode(manifest_bytes),
    )
    if not isinstance(text, str):
        raise _error("invalid")
    return text.encode("ascii")


def _publication(op: str, home: Path, **fields: Any) -> object:
    from .native_transition_files import publication

    return publication(op, home, **fields)


def _path_text(path: Path) -> str:
    return os.path.abspath(path.expanduser())


def hook_publication_pending(home: Path) -> bool:
    return _publication("pending", home) is True


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
    """The private bytes of one single-link regular file, or ``None`` when absent."""
    target = _path_text(path)
    return _decode(_publication("snapshot", Path(target), path=target))


def _owned(home: Path) -> str:
    owner = require_codex_install_owner(home)
    from .runtime_transition import assert_transition_mutation_allowed

    assert_transition_mutation_allowed(home)
    return owner.operation_id


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
    _publication(
        "prepare",
        home,
        operation_id=_owned(home),
        config=_path_text(config),
        before_config=_encode(before_config),
        before_manifest=_encode(before_manifest),
        after_config=_encode(after_config),
        after_manifest=_encode(after_manifest),
        key_created=key_created,
        before_receipt=_encode(before_receipt),
        after_receipt=_encode(after_receipt),
        repair_plan=repair_plan,
        repair_publication_monotonic=repair_publication_monotonic,
    )


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
    _publication(
        "assert_repair",
        home,
        operation_id=owner.operation_id,
        config=_path_text(config),
        repair_plan=repair_plan,
        config_bytes=_encode(config_bytes),
        manifest_bytes=_encode(manifest_bytes),
        receipt_bytes=_encode(receipt_bytes),
        publication_monotonic=publication_monotonic,
    )


def _load_record(home: Path, *, live_config_conflict: bool = False) -> dict[str, object]:
    payload = _publication("load", home, live_config_conflict=live_config_conflict)
    if not isinstance(payload, dict):
        raise _error("record_invalid")
    return payload


def mark_owned_hook_publication_conflict(home: Path, config: Path) -> None:
    """Durably refuse an inverse after this live owner sees a competing config.

    Ordinary crash recovery cannot select this mode. Only the still-held
    preparation owner may mark it. Every participant remains untouched: no
    recovery restores the predecessor config over the foreign one. Automatic
    recovery retires the record only while Guard's authority files still hold
    this transaction's bytes, so the next install can publish again.
    """
    _publication("conflict", home, operation_id=_owned(home), config=_path_text(config))


def record_owned_hook_config_publication(home: Path, config: Path, identity: tuple[int, int, int, int, int]) -> None:
    """Make the observed published inode durable before accepting readback.

    A crash after rename but before this record remains recovery-required;
    matching bytes alone cannot prove that the pending writer owns the inode.
    """
    _publication("config", home, operation_id=_owned(home), config=_path_text(config), identity=list(identity))


def recover_hook_publication(home: Path) -> bool:
    """Idempotent inverse under exclusive ownership, with an all-file CAS check."""
    _owned(home)
    return _publication("recover", home) is True


def commit_hook_publication(home: Path) -> None:
    # The adapter calls this only after authenticated native hook readback.
    _owned(home)
    # The committed record is durable before cleanup: a crash in between keeps
    # the authenticated candidate rather than applying the predecessor inverse.
    _publication("commit", home)
    _remove_record(home)


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
    observation = verified_admission_payload(proof)
    pending.compare("after")
    # The runtime checks the proof's timing and that it is this publication's.
    _publication(
        "commit_repair",
        plan.guard_home,
        observation=observation,
        publication=pending.publication_monotonic,
        started=started_monotonic,
        now=time.monotonic(),
    )
    _remove_record(plan.guard_home)


def _remove_record(home: Path) -> None:
    _publication("remove", home)

"""Durable, exact-authorized runtime transition phases and file inverses.

Adapter preparation supplies the complete file plan before mutation. This layer
does not discover adapter files or declare a daemon functional: callers must
provide actual functional proof before the final commit.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from .approval_gate import ApprovalGateGrant, public_config, validate_grant
from .codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from .codex_hook_integrity import atomic_write_bytes, canonical_manifest_bytes, restore_private_file
from .codex_hook_recovery import _decode, _encode, _snapshot
from .codex_install_transaction import require_codex_install_owner
from .durable_io import fsync_directory
from .live_process_identity import current_process_identity
from .local_authority_integrity import sign_local_authority_payload, verify_local_authority_payload
from .private_file_io import read_private_regular_text
from .runtime_transition_modes import normalized_after_mode, publishes_user_file, recorded_noop
from .sqlite_tuning import sqlite_operation_deadline

_PURPOSE = "guard-runtime-transition-inverse"
_SCHEMA = "hol-guard.runtime-transition.v1"
_MAX_RECORD = 32 * 1024 * 1024
_REFUSAL_SCHEMA = "hol-guard.runtime-transition-not-started.v1"
_REFUSAL_PURPOSE = "guard-runtime-transition-not-started"
_ACTIVE_TRANSITION: ContextVar[tuple[Path, str, float] | None] = ContextVar(
    "runtime_transition_operation", default=None
)
_INVERSE_DEADLINE: ContextVar[float | None] = ContextVar("runtime_transition_inverse_deadline", default=None)
_FORWARD = {
    "AuthorizedForExactTransition": "HooksPrepared",
    "HooksPrepared": "Switching",
    "Switching": "CandidateFunctional",
    "CandidateFunctional": "Committed",
}


class TransitionError(RuntimeError):
    def __init__(self, reason: str, detail: str | None = None):
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"Runtime transition requires recovery: {reason}{suffix}")
        self.reason = reason
        self.detail = detail


def _check_inverse_deadline() -> None:
    deadline = _INVERSE_DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise TransitionError("deadline_exceeded")


@contextmanager
def inverse_recovery_budget(deadline: float):
    """Budget only: this scope conveys no publication or lifecycle authority."""
    parent = _INVERSE_DEADLINE.get()
    token = _INVERSE_DEADLINE.set(deadline if parent is None else min(parent, deadline))
    try:
        _check_inverse_deadline()
        with sqlite_operation_deadline(_INVERSE_DEADLINE.get() or deadline):
            yield
    finally:
        _INVERSE_DEADLINE.reset(token)


@dataclass(frozen=True)
class TransitionStatus:
    operation_id: str
    phase: str
    first_cause: str | None
    recovery_causes: tuple[dict[str, object], ...]
    artifact_generation: str | None = None


def _object_mapping(value: object, *, reason: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise TransitionError(reason)
    return cast(dict[str, object], value)


def _record_objects(payload: Mapping[str, object], key: str, *, maximum: int) -> list[dict[str, object]]:
    value = payload.get(key, [])
    if not isinstance(value, list) or len(value) > maximum:
        raise TransitionError(f"{key}_invalid")
    return [_object_mapping(item, reason=f"{key}_invalid") for item in value]


def _record_number(payload: Mapping[str, object], key: str) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TransitionError("deadline_invalid")
    try:
        finite = math.isfinite(value)
    except OverflowError as exc:
        raise TransitionError("deadline_invalid") from exc
    if not finite:
        raise TransitionError("deadline_invalid")
    return float(value)


def _validate_digest_dependency(change: Mapping[str, object]) -> None:
    if "expected_digest" not in change:
        if "artifact_identity" in change or "invocation_identity" in change:
            raise TransitionError("artifact_dependency_invalid")
        return
    digest = change["expected_digest"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(c not in "0123456789abcdef" for c in digest)
        or change.get("before") is not None
        or change.get("after") is not None
        or change.get("before_mode") != change.get("after_mode")
        or change.get("kind") != "binding"
        or change.get("no_follow") is not True
    ):
        raise TransitionError("authority_dependency_invalid")
    if "artifact_identity" in change:
        identity = change["artifact_identity"]
        if not isinstance(identity, dict) or set(identity) not in (
            {"size", "owner_uid"},
            {"size", "owner_uid", "role"},
        ):
            raise TransitionError("artifact_dependency_invalid")
        if "role" in identity and (not isinstance(identity["role"], str) or not 0 < len(identity["role"]) <= 128):
            raise TransitionError("artifact_dependency_invalid")
        size, owner = identity["size"], identity["owner_uid"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size < 2**63
            or isinstance(owner, bool)
            or (owner is not None and (not isinstance(owner, int) or owner < 0))
            or (os.name != "nt" and owner not in {0, os.geteuid()})
        ):
            raise TransitionError("artifact_dependency_invalid")
    if "invocation_identity" in change:
        invocation = change["invocation_identity"]
        if (
            "artifact_identity" not in change
            or not isinstance(invocation, dict)
            or set(invocation) != {"path", "mode", "owner_uid", "link_target"}
        ):
            raise TransitionError("invocation_dependency_invalid")
        path, mode, owner, link = (invocation[field] for field in ("path", "mode", "owner_uid", "link_target"))
        if (
            not isinstance(path, str)
            or not 0 < len(path) <= 4096
            or "\0" in path
            or not Path(path).is_absolute()
            or isinstance(mode, bool)
            or not isinstance(mode, int)
            or mode & ~0o777
            or isinstance(owner, bool)
            or (owner is not None and (not isinstance(owner, int) or owner < 0))
            or (os.name != "nt" and owner not in {0, os.geteuid()})
            or (link is not None and (not isinstance(link, str) or not 0 < len(link) <= 4096 or "\0" in link))
        ):
            raise TransitionError("invocation_dependency_invalid")


def _invocation_generation(target: Path, identity: Mapping[str, object]) -> tuple[int, ...]:
    """Verify the authenticated invocation, preserving symlink semantics such as venv selection."""
    _check_inverse_deadline()
    active = _ACTIVE_TRANSITION.get()
    if active is not None and time.monotonic() >= active[2]:
        raise TransitionError("forward_authorization_expired")
    path = Path(str(identity["path"]))
    try:
        before = path.lstat()
        link = os.readlink(path) if stat.S_ISLNK(before.st_mode) else None
        if not stat.S_ISLNK(before.st_mode) and not stat.S_ISREG(before.st_mode):
            raise TransitionError("invocation_dependency_invalid")
        if link != identity["link_target"] or path.resolve(strict=True) != target or not os.access(path, os.X_OK):
            raise TransitionError("invocation_generation_changed")
        if os.name != "nt" and (before.st_mode & 0o777 != identity["mode"] or before.st_uid != identity["owner_uid"]):
            raise TransitionError("invocation_generation_changed")
        after = path.lstat()

        def fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )

        if fingerprint(before) != fingerprint(after):
            raise TransitionError("invocation_generation_changed")
        if active is not None and time.monotonic() >= active[2]:
            raise TransitionError("forward_authorization_expired")
        _check_inverse_deadline()
        return fingerprint(after)
    except (OSError, RuntimeError) as exc:
        if isinstance(exc, TransitionError):
            raise
        raise TransitionError("invocation_dependency_unavailable") from exc


def _unsafe_file_mode(mode: int, artifact_identity: object) -> bool:
    artifact_role = isinstance(artifact_identity, dict) and isinstance(artifact_identity.get("role"), str)
    return bool(mode & ~0o777 or (os.name != "nt" and (mode & 0o002 or (mode & 0o020 and not artifact_role))))


def _artifact_digest(target: Path, identity: Mapping[str, object], mode: int) -> str:
    """Hash the signed size through one owned descriptor with bounded working memory."""
    active = _ACTIVE_TRANSITION.get()

    def fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
        )

    def check_deadline() -> None:
        _check_inverse_deadline()
        if active is not None and time.monotonic() >= active[2]:
            raise TransitionError("forward_authorization_expired")

    check_deadline()
    try:
        trusted = validate_regular_file(target, role=str(identity.get("role", "artifact")), executable_required=False)
    except CodexHookIntegrityError as exc:
        raise TransitionError("artifact_permissions_invalid") from exc
    check_deadline()
    try:
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise TransitionError("artifact_dependency_unavailable") from exc
    try:
        opened = os.fstat(descriptor)
        if fingerprint(trusted) != fingerprint(opened):
            raise TransitionError("generation_changed")
        if not stat.S_ISREG(opened.st_mode) or getattr(opened, "st_file_attributes", 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
        ):
            raise TransitionError("artifact_dependency_invalid")
        if opened.st_size != identity["size"]:
            raise TransitionError("generation_changed")
        if os.name != "nt":
            if opened.st_uid != identity["owner_uid"]:
                raise TransitionError("artifact_owner_changed")
            if opened.st_mode & 0o777 != mode:
                raise TransitionError("file_mode_changed")
        digest = hashlib.sha256()
        count = 0
        while True:
            check_deadline()
            chunk = os.read(descriptor, 64 * 1024)
            check_deadline()
            if not chunk:
                break
            count += len(chunk)
            if count > opened.st_size:
                raise TransitionError("generation_changed")
            digest.update(chunk)
        final, current = os.fstat(descriptor), target.lstat()
        if (
            count != opened.st_size
            or fingerprint(opened) != fingerprint(final)
            or fingerprint(final) != fingerprint(current)
        ):
            raise TransitionError("generation_changed")
        check_deadline()
        return digest.hexdigest()
    except OSError as exc:
        raise TransitionError("artifact_dependency_unavailable") from exc
    finally:
        os.close(descriptor)


def _record_files(payload: Mapping[str, object]) -> list[dict[str, object]]:
    changes = _record_objects(payload, "files", maximum=128)
    paths = []
    for change in changes:
        required = {"path", "before", "after", "before_mode", "after_mode", "kind"}
        path = change.get("path")
        if (
            not required
            <= set(change)
            <= required | {"no_follow", "expected_digest", "artifact_identity", "invocation_identity"}
            or not isinstance(path, str)
            or not Path(path).is_absolute()
            or change["kind"] not in ("binding", "selection")
            or not isinstance(change.get("no_follow", False), bool)
        ):
            raise TransitionError("files_invalid")
        _validate_digest_dependency(change)
        for generation in ("before", "after"):
            recorded_mode = change[f"{generation}_mode"]
            if isinstance(recorded_mode, bool) or not isinstance(recorded_mode, int):
                raise TransitionError("file_mode_invalid")
            if recorded_mode & ~0o777:
                raise TransitionError("file_mode_invalid")
            if (
                generation == "after"
                and _unsafe_file_mode(recorded_mode, change.get("artifact_identity"))
                and not recorded_noop(change)
            ):
                raise TransitionError("file_mode_invalid", path)
            encoded = change[generation]
            if encoded is not None and not isinstance(encoded, str):
                raise TransitionError("files_invalid")
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise TransitionError("plan_invalid")
    return changes


def _artifact_identity(value: object) -> dict[str, str]:
    artifact = _object_mapping(value, reason="artifact_identity_invalid")
    required = {"version", "source_commit", "target", "format", "sha256", "path", "generation"}
    if set(artifact) != required or any(
        not isinstance(item, str) or not 0 < len(item) <= 4096 for item in artifact.values()
    ):
        raise TransitionError("artifact_identity_invalid")
    identity = cast(dict[str, str], artifact)
    if not Path(identity["path"]).is_absolute():
        raise TransitionError("artifact_path_invalid")
    return identity


def _native_runtime_bindings(payload: Mapping[str, object]) -> dict[str, dict[str, object]]:
    bindings = _object_mapping(payload.get("native_runtimes", {}), reason="native_runtime_bindings_invalid")
    if bindings and set(bindings) != {"candidate", "predecessor"}:
        raise TransitionError("native_runtime_bindings_invalid")
    result: dict[str, dict[str, object]] = {}
    for side, value in bindings.items():
        identity = _object_mapping(value, reason="native_runtime_bindings_invalid")
        if (
            set(identity) != {"path", "size", "mtime_ns", "sha256"}
            or not isinstance(identity["path"], str)
            or not Path(identity["path"]).is_absolute()
            or type(identity["size"]) is not int
            or identity["size"] <= 0
            or type(identity["mtime_ns"]) is not int
            or identity["mtime_ns"] <= 0
            or not isinstance(identity["sha256"], str)
            or len(identity["sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in identity["sha256"])
        ):
            raise TransitionError("native_runtime_bindings_invalid")
        dependencies = _record_files(payload)
        if not any(
            change["path"] == identity["path"]
            and change.get("expected_digest") == identity["sha256"]
            and isinstance(change.get("artifact_identity"), dict)
            and cast(dict[str, object], change["artifact_identity"]).get("size") == identity["size"]
            for change in dependencies
        ):
            raise TransitionError("native_runtime_dependency_missing")
        result[side] = identity
    return result


class PolicyAuthority(Protocol):
    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]: ...


class ManagedInstallStore(Protocol):
    def get_managed_install(self, harness: str) -> dict[str, object] | None: ...
    def compare_and_set_managed_installs(
        self,
        changes: Sequence[tuple[str, tuple[dict[str, object] | None, ...], dict[str, object] | None]],
        *,
        before_mutation: Callable[[], None],
    ) -> bool: ...


@dataclass(frozen=True)
class TransitionInstall:
    harness: str
    before: dict[str, object] | None
    after: dict[str, object] | None

    def snapshot(self, generation: str) -> dict[str, object] | None:
        if generation == "before":
            return self.before
        if generation == "after":
            return self.after
        raise TransitionError("managed_install_generation_invalid")

    def payload(self) -> dict[str, object]:
        if not self.harness or len(self.harness) > 80:
            raise TransitionError("managed_install_target_invalid")
        for snapshot in (self.before, self.after):
            if snapshot is not None and (
                set(snapshot) != {"harness", "active", "workspace", "manifest", "updated_at"}
                or snapshot["harness"] != self.harness
                or not isinstance(snapshot["active"], bool)
                or not isinstance(snapshot["manifest"], dict)
                or not isinstance(snapshot["updated_at"], str)
                or (snapshot["workspace"] is not None and not isinstance(snapshot["workspace"], str))
            ):
                raise TransitionError("managed_install_snapshot_invalid")
        # Normalize tuples to the same JSON shape returned by GuardStore.
        encoded = json.dumps(
            {"harness": self.harness, "before": self.before, "after": self.after},
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(encoded.encode()) > 1024 * 1024:
            raise TransitionError("managed_install_snapshot_too_large")
        return json.loads(encoded)


def _record_installs(payload: Mapping[str, object]) -> list[TransitionInstall]:
    changes = []
    for row in _record_objects(payload, "managed_installs", maximum=64):
        harness = row.get("harness")
        if not isinstance(harness, str) or set(row) != {"harness", "before", "after"}:
            raise TransitionError("managed_install_snapshot_invalid")
        snapshots = [
            None if row[key] is None else _object_mapping(row[key], reason="managed_install_snapshot_invalid")
            for key in ("before", "after")
        ]
        change = TransitionInstall(harness, snapshots[0], snapshots[1])
        change.payload()
        changes.append(change)
    if len({change.harness for change in changes}) != len(changes):
        raise TransitionError("managed_install_plan_invalid")
    return changes


def assert_transition_mutation_allowed(home: Path) -> None:
    canonical_home = home.resolve(strict=False)
    path = canonical_home / "managed" / "runtime-transition.json"
    if path.exists() or path.is_symlink():
        # Ordinary installs cannot join by borrowing a scope: their writes are
        # not necessarily in the exact approved plan. Only publish() applies it.
        raise TransitionError("pending_transition")


def _assert_publish_scope(home: Path) -> None:
    active = _ACTIVE_TRANSITION.get()
    if active is None or active[0] != home:
        raise TransitionError("publication_owner_missing")
    if time.monotonic() >= active[2]:
        raise TransitionError("forward_authorization_expired")


@dataclass(frozen=True)
class TransitionFile:
    path: Path
    before: bytes | None
    after: bytes | None
    before_mode: int = 0o600
    after_mode: int = 0o600
    kind: str = "binding"
    no_follow: bool = False
    expected_digest: str | None = None
    artifact_identity: dict[str, object] | None = None
    invocation_identity: dict[str, object] | None = None

    def __post_init__(self) -> None:
        # An existing user file carries its own mode forward, minus the group/world
        # write bits Guard never publishes (umask 0002 dotfiles are 0664). Normalize
        # here so payload() and every direct writer publish the same mode. A new
        # file's mode is chosen by Guard, so an unsafe request there stays an error.
        if self.before is not None and publishes_user_file(
            before=self.before,
            after=self.after,
            before_mode=self.before_mode,
            after_mode=self.after_mode,
            expected_digest=self.expected_digest,
            artifact_identity=self.artifact_identity,
        ):
            object.__setattr__(self, "after_mode", normalized_after_mode(self.after_mode))

    @classmethod
    def identity_dependency(cls, path: Path) -> TransitionFile:
        """Pin existing authority without copying its secret bytes into the journal."""
        data = _snapshot(path)
        if data is None:
            raise TransitionError("authority_dependency_missing")
        mode = path.stat().st_mode & 0o777
        return cls(
            path.resolve(strict=False),
            None,
            None,
            before_mode=mode,
            after_mode=mode,
            no_follow=True,
            expected_digest=hashlib.sha256(data).hexdigest(),
        )

    @classmethod
    def artifact_dependency(
        cls,
        identity: Mapping[str, object],
        *,
        invocation: Mapping[str, object] | None = None,
    ) -> TransitionFile:
        """Pin the exact authenticated artifact without journaling its bytes."""
        path, mode, digest = identity.get("path"), identity.get("mode"), identity.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(mode, int)
            or isinstance(mode, bool)
            or not isinstance(digest, str)
        ):
            raise TransitionError("artifact_dependency_invalid")
        invocation_identity = (
            None
            if invocation is None
            else {
                "path": invocation.get("invocation_path"),
                "mode": invocation.get("invocation_mode"),
                "owner_uid": invocation.get("invocation_owner_uid"),
                "link_target": invocation.get("link_target"),
            }
        )
        change = cls(
            Path(path),
            None,
            None,
            before_mode=mode,
            after_mode=mode,
            no_follow=True,
            expected_digest=digest,
            artifact_identity={
                "size": identity.get("size"),
                "owner_uid": identity.get("owner_uid"),
                "role": identity.get("role"),
            },
            invocation_identity=invocation_identity,
        )
        RuntimeTransition._compare({"files": [change.payload()]}, "before")
        return change

    def payload(self) -> dict[str, object]:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise TransitionError("file_target_invalid")
        if not isinstance(self.no_follow, bool):
            raise TransitionError("file_publication_contract_invalid")
        if self.kind not in {"binding", "selection"}:
            raise TransitionError("file_kind_invalid")
        for mode in (self.before_mode, self.after_mode):
            if isinstance(mode, bool) or bool(mode & ~0o777):
                raise TransitionError("file_mode_invalid", str(self.path))
        pinned = self.expected_digest is not None or self.artifact_identity is not None
        publishes = publishes_user_file(
            before=self.before,
            after=self.after,
            before_mode=self.before_mode,
            after_mode=self.after_mode,
            expected_digest=self.expected_digest,
            artifact_identity=self.artifact_identity,
        )
        # The previous mode is the user's file. Only the published mode must be private.
        if (publishes or pinned) and _unsafe_file_mode(self.after_mode, self.artifact_identity):
            raise TransitionError("file_mode_invalid", str(self.path))
        payload: dict[str, object] = {
            "path": str(self.path.resolve(strict=False)),
            "before": _encode(self.before),
            "after": _encode(self.after),
            "before_mode": self.before_mode,
            "after_mode": self.after_mode,
            "kind": self.kind,
            "no_follow": self.no_follow,
        }
        if self.expected_digest is not None:
            payload["expected_digest"] = self.expected_digest
        if self.artifact_identity is not None:
            payload["artifact_identity"] = dict(self.artifact_identity)
        if self.invocation_identity is not None:
            payload["invocation_identity"] = dict(self.invocation_identity)
        _validate_digest_dependency(payload)
        return payload


def merge_transition_dependency(previous: TransitionFile, change: TransitionFile) -> TransitionFile:
    """Merge shared immutable bytes without weakening either invocation contract.

    Frozen roles share one executable. Their role names remain authenticated
    in the hook manifest; the transition needs one filesystem dependency with
    the strongest exact invocation contract, rather than duplicate targets.
    Mutable writes and authority-only dependencies never use this merge.
    """
    before, after = previous.payload(), change.payload()
    if before == after:
        return previous
    for payload in (before, after):
        if (
            payload.get("expected_digest") is None
            or not isinstance(payload.get("artifact_identity"), dict)
            or payload["before"] is not None
            or payload["after"] is not None
        ):
            raise TransitionError("adapter_preparation_generation_conflict")
    normalized = []
    for payload in (before, after):
        item = dict(payload)
        identity = dict(cast(dict[str, object], item["artifact_identity"]))
        identity["role"] = "artifact"
        item["artifact_identity"] = identity
        item.pop("invocation_identity", None)
        normalized.append(item)
    if normalized[0] != normalized[1] or (
        previous.invocation_identity is not None
        and change.invocation_identity is not None
        and previous.invocation_identity != change.invocation_identity
    ):
        raise TransitionError("adapter_preparation_generation_conflict")
    return replace(
        previous,
        artifact_identity=cast(dict[str, object], normalized[0]["artifact_identity"]),
        invocation_identity=previous.invocation_identity or change.invocation_identity,
    )


@dataclass(frozen=True)
class TransitionPlan:
    operation_id: str
    guard_home: Path
    predecessor: Mapping[str, object]
    candidate: Mapping[str, object]
    files: tuple[TransitionFile, ...]
    deadline_epoch: float
    managed_installs: tuple[TransitionInstall, ...] = ()
    native_runtimes: Mapping[str, object] | None = None

    def payload(self) -> dict[str, object]:
        if sum(len(change.before or b"") + len(change.after or b"") for change in self.files) > 16 * 1024 * 1024:
            raise TransitionError("plan_too_large")
        changes = [change.payload() for change in self.files]
        paths = [change["path"] for change in changes]
        installs = [change.payload() for change in self.managed_installs]
        if len(installs) > 64 or len({change["harness"] for change in installs}) != len(installs):
            raise TransitionError("managed_install_plan_invalid")
        if len(canonical_manifest_bytes({"installs": installs})) > 4 * 1024 * 1024:
            raise TransitionError("managed_install_plan_too_large")
        if not self.operation_id or not changes or len(changes) > 128 or len(paths) != len(set(paths)):
            raise TransitionError("plan_invalid")
        # Artifacts are verified before this plan is built;
        # preserve their complete source/format/path identities in the authority.
        for artifact in (self.predecessor, self.candidate):
            _artifact_identity(dict(artifact))
        payload: dict[str, object] = {
            "operation_id": self.operation_id,
            "guard_home": str(self.guard_home.resolve(strict=False)),
            "predecessor": dict(self.predecessor),
            "candidate": dict(self.candidate),
            "files": changes,
            "deadline_epoch": self.deadline_epoch,
            "managed_installs": installs,
            "native_runtimes": dict(self.native_runtimes or {}),
        }
        _native_runtime_bindings(payload)
        return payload

    def subject(self) -> str:
        return hashlib.sha256(canonical_manifest_bytes(self.payload())).hexdigest()


class RuntimeTransition:
    def __init__(self, home: Path, authority: PolicyAuthority, *, install_store: ManagedInstallStore | None = None):
        self.home = home.resolve(strict=False)
        self.authority = authority
        self.install_store = install_store
        self.path = self.home / "managed" / "runtime-transition.json"
        self._forward_grant: ApprovalGateGrant | None = None

    def _key(self) -> tuple[bytes, str]:
        # Never create or rotate an authority as a recovery shortcut.
        key, key_id = self.authority._policy_integrity_secret_material(create=False)
        if key is None or key_id is None:
            raise TransitionError("signing_authority_unavailable")
        return key, key_id

    def _refusal_path(self, operation_id: str) -> Path:
        try:
            if str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError("noncanonical UUID")
        except (ValueError, TypeError, AttributeError) as error:
            raise TransitionError("operation_id_invalid") from error
        return self.home / "managed" / "runtime-refusals" / f"{operation_id}.json"

    def record_approval_refusal(self, plan: TransitionPlan, reason: str, *, deadline_monotonic: float) -> None:
        """Record only a refusal before begin; this is never a forward grant."""
        require_codex_install_owner(self.home)
        if (
            plan.guard_home != self.home
            or not reason
            or len(reason) > 128
            or not reason.isascii()
            or any(not (character.isalnum() or character == "_") for character in reason)
        ):
            raise TransitionError("refusal_context_invalid")
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("deadline_exceeded")
        # Any existing journal, including an unreadable/foreign one, prevents
        # this assertion. The shared home owner excludes a concurrent begin.
        if self.path.exists() or self.path.is_symlink():
            raise TransitionError("pending_transition")
        path = self._refusal_path(plan.operation_id)
        key, key_id = self._key()
        payload: dict[str, object] = {
            "schema": _REFUSAL_SCHEMA,
            "guard_home": str(self.home),
            "operation_id": plan.operation_id,
            "artifact_generation": _artifact_identity(plan.candidate)["generation"],
            "reason_code": reason,
        }
        signed = dict(payload)
        signed["authentication"] = sign_local_authority_payload(
            payload,
            key=key,
            key_id=key_id,
            purpose=_REFUSAL_PURPOSE,
            signed_at=plan.operation_id,
        )
        encoded = canonical_manifest_bytes(signed) + b"\n"
        if len(encoded) > 4096:
            raise TransitionError("refusal_capacity")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.parent.lstat()
        if (
            path.parent.resolve(strict=True) != path.parent
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (os.name != "nt" and (metadata.st_uid != os.getuid() or metadata.st_mode & 0o077))
        ):
            raise TransitionError("refusal_directory_unsafe")
        # Bound retained evidence; never evict a refusal to authorize reuse.
        with os.scandir(path.parent) as entries:
            if sum(1 for _, _entry in zip(range(129), entries, strict=False)) >= 128:
                raise TransitionError("refusal_capacity")
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("deadline_exceeded")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            offset = 0
            while offset < len(encoded):
                if time.monotonic() >= deadline_monotonic:
                    raise TransitionError("deadline_exceeded")
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise TransitionError("refusal_write_failed")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(path.parent)

    def refusal_status(self, operation_id: str) -> TransitionStatus:
        require_codex_install_owner(self.home)
        if self.path.exists() or self.path.is_symlink():
            raise TransitionError("pending_transition")
        path = self._refusal_path(operation_id)
        raw = read_private_regular_text(path, max_bytes=4096)
        if raw is None:
            raise TransitionError("record_unavailable")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise TransitionError("refusal_invalid") from error
        if not isinstance(payload, dict):
            raise TransitionError("refusal_invalid")
        integrity = payload.pop("authentication", None)
        key, key_id = self._key()
        if (
            not isinstance(integrity, dict)
            or verify_local_authority_payload(
                payload, integrity, key=key, key_id=key_id, purpose=_REFUSAL_PURPOSE
            ).status
            != "valid"
        ):
            raise TransitionError("refusal_unauthenticated")
        generation, reason = payload.get("artifact_generation"), payload.get("reason_code")
        if (
            set(payload) != {"schema", "guard_home", "operation_id", "artifact_generation", "reason_code"}
            or payload.get("schema") != _REFUSAL_SCHEMA
            or payload.get("guard_home") != str(self.home)
            or payload.get("operation_id") != operation_id
            or not isinstance(generation, str)
            or len(generation) != 64
            or any(character not in "0123456789abcdef" for character in generation)
            or not isinstance(reason, str)
            or not reason
            or len(reason) > 128
            or not reason.isascii()
            or any(not (character.isalnum() or character == "_") for character in reason)
        ):
            raise TransitionError("refusal_context_invalid")
        return TransitionStatus(operation_id, "NotStarted", reason, (), generation)

    def _write(self, payload: dict[str, object]) -> None:
        require_codex_install_owner(self.home)
        key, key_id = self._key()
        signed = dict(payload)
        signed["authentication"] = sign_local_authority_payload(
            payload,
            key=key,
            key_id=key_id,
            purpose=_PURPOSE,
            signed_at=str(payload["operation_id"]),
        )
        encoded = canonical_manifest_bytes(signed) + b"\n"
        if len(encoded) > _MAX_RECORD:
            raise TransitionError("record_too_large")
        atomic_write_bytes(self.path, encoded, mode=0o600, private=True)

    def _read(self, operation_id: str) -> dict[str, object]:
        return self._read_record(operation_id, self.path)

    def _read_record(self, operation_id: str, path: Path) -> dict[str, object]:
        require_codex_install_owner(self.home)
        raw = read_private_regular_text(path, max_bytes=_MAX_RECORD)
        if raw is None:
            raise TransitionError("record_unavailable")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise TransitionError("record_invalid") from exc
        if not isinstance(payload, dict):
            raise TransitionError("record_invalid")
        integrity = payload.pop("authentication", None)
        key, key_id = self._key()
        if (
            not isinstance(integrity, dict)
            or verify_local_authority_payload(payload, integrity, key=key, key_id=key_id, purpose=_PURPOSE).status
            != "valid"
        ):
            raise TransitionError("record_unauthenticated")
        if payload.get("schema") != _SCHEMA or payload.get("guard_home") != str(self.home):
            raise TransitionError("record_context_mismatch")
        if payload.get("operation_id") != operation_id:
            raise TransitionError("operation_superseded")
        if not _record_files(payload):
            raise TransitionError("plan_invalid")
        _record_installs(payload)
        _native_runtime_bindings(payload)
        _record_objects(payload, "recovery_causes", maximum=8)
        for name in ("candidate", "predecessor"):
            _artifact_identity(payload.get(name))
        for name in ("deadline_epoch", "deadline_monotonic", "forward_expires_epoch", "forward_expires_monotonic"):
            _record_number(payload, name)
        return payload

    def begin(
        self,
        plan: TransitionPlan,
        *,
        authority_home: Path,
        grant: ApprovalGateGrant | None,
        deadline_monotonic: float | None = None,
    ) -> None:
        from .cli.commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home

        owner = require_codex_install_owner(self.home)
        # A refused exact UUID cannot later be reused with another factor.
        # Normal updates use a new operation and a new exact authorization.
        try:
            refused_path = self._refusal_path(plan.operation_id)
        except TransitionError:
            # Only canonical Desktop UUIDs have refusal receipts. Internal
            # transaction identifiers keep their existing identifier scope.
            refused_path = None
        if refused_path is not None and (refused_path.exists() or refused_path.is_symlink()):
            raise TransitionError("operation_previously_refused")
        payload = plan.payload()
        if payload["guard_home"] != str(self.home):
            raise TransitionError("plan_context_mismatch")
        reserved = {
            self.path,
            self.path.with_name("runtime-transition.previous.json"),
            self.home / "managed" / "codex" / "installation.lock",
        }
        key_path = self.home / "managed" / "codex" / "hook-manifest.key"
        for change in _record_files(payload):
            target = Path(str(change["path"]))
            # Authority may participate only as a validated digest dependency.
            # No key bytes or replacement can enter the forward/inverse journal.
            if target in reserved or (
                target == key_path and ("expected_digest" not in change or "artifact_identity" in change)
            ):
                raise TransitionError("authority_target_forbidden")
        if self.path.exists() or self.path.is_symlink():
            raise TransitionError("pending_transition")
        monotonic_now = time.monotonic()
        now = time.time()
        if not now < plan.deadline_epoch <= now + 60:
            raise TransitionError("deadline_invalid")
        deadline = monotonic_now + max(0, plan.deadline_epoch - now)
        if deadline_monotonic is not None:
            if not math.isfinite(deadline_monotonic) or deadline_monotonic <= monotonic_now:
                raise TransitionError("deadline_exceeded")
            deadline = min(deadline, deadline_monotonic)
        expected_authority_home = lifecycle_authority_home(
            self.home, requirement=LifecycleGateRequirement("runtime.transition", plan.subject())
        )
        if authority_home.resolve(strict=False) != expected_authority_home.resolve(strict=False):
            raise TransitionError("approval_authority_mismatch")
        approval_required = public_config(authority_home).enabled
        if approval_required:
            validate_grant(
                authority_home,
                grant,
                purpose="protection_lifecycle",
                strict=True,
                action="runtime.transition",
                scope="local-protection",
                subject=plan.subject(),
            )
        elif grant is not None:
            raise TransitionError("unexpected_grant")
        identity = current_process_identity()
        if identity is None:
            raise TransitionError("owner_identity_unavailable")
        self._compare(payload, "before")
        self._compare_installs(payload, "before")
        if time.monotonic() >= deadline:
            raise TransitionError("deadline_exceeded")
        if grant is not None:
            validate_grant(
                authority_home,
                grant,
                purpose="protection_lifecycle",
                strict=True,
                action="runtime.transition",
                scope="local-protection",
                subject=plan.subject(),
            )
        forward_expires_epoch = min(
            plan.deadline_epoch,
            datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")).timestamp()
            if grant is not None
            else plan.deadline_epoch,
        )
        payload.update(
            {
                "schema": _SCHEMA,
                "phase": "AuthorizedForExactTransition",
                "owner": identity,
                "installer_operation_id": owner.operation_id,
                "authorized_subject": plan.subject(),
                "approval_required": approval_required,
                "forward_expires_epoch": forward_expires_epoch,
                "deadline_monotonic": deadline,
                "forward_expires_monotonic": min(deadline, monotonic_now + max(0, forward_expires_epoch - now)),
                "first_cause": None,
                "recovery_causes": [],
            }
        )
        self._write(payload)
        self._forward_grant = grant

    def status(self, operation_id: str) -> TransitionStatus:
        payload = self._read(operation_id)
        return TransitionStatus(
            operation_id,
            str(payload["phase"]),
            str(payload["first_cause"]) if payload["first_cause"] is not None else None,
            tuple(_record_objects(payload, "recovery_causes", maximum=8)),
            cast(str, _artifact_identity(payload["candidate"])["generation"]),
        )

    def archived_status(self, operation_id: str) -> TransitionStatus:
        require_codex_install_owner(self.home)
        if self.path.exists() or self.path.is_symlink():
            raise TransitionError("pending_transition")
        payload = self._read_record(operation_id, self.path.with_name("runtime-transition.previous.json"))
        if payload["phase"] not in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("nonterminal_transition")
        return TransitionStatus(
            operation_id,
            str(payload["phase"]),
            str(payload["first_cause"]) if payload["first_cause"] is not None else None,
            tuple(_record_objects(payload, "recovery_causes", maximum=8)),
            cast(str, _artifact_identity(payload["candidate"])["generation"]),
        )

    def recovery_plan(self, operation_id: str) -> TransitionPlan:
        """Reconstruct only authenticated snapshots; never recreate a forward grant.

        The caller holds the permanent home owner. Private inverse bytes stay
        in process and must never be included in a CLI status response.
        """
        payload = self._read(operation_id)
        files = tuple(
            TransitionFile(
                Path(cast(str, change["path"])),
                _decode(change["before"]),
                _decode(change["after"]),
                before_mode=cast(int, change["before_mode"]),
                after_mode=cast(int, change["after_mode"]),
                kind=cast(str, change["kind"]),
                no_follow=cast(bool, change.get("no_follow", False)),
                expected_digest=cast(str | None, change.get("expected_digest")),
                artifact_identity=cast(dict[str, object] | None, change.get("artifact_identity")),
                invocation_identity=cast(dict[str, object] | None, change.get("invocation_identity")),
            )
            for change in _record_files(payload)
        )
        plan = TransitionPlan(
            operation_id,
            self.home,
            _artifact_identity(payload["predecessor"]),
            _artifact_identity(payload["candidate"]),
            files,
            _record_number(payload, "deadline_epoch"),
            managed_installs=tuple(_record_installs(payload)),
            native_runtimes=_native_runtime_bindings(payload),
        )
        if plan.subject() != payload.get("authorized_subject"):
            raise TransitionError("plan_context_mismatch")
        return plan

    def _validate_forward_grant(self, payload: dict[str, object]) -> None:
        from .cli.commands_lifecycle_gate import LifecycleGateRequirement, lifecycle_authority_home

        authority_home = lifecycle_authority_home(
            self.home,
            requirement=LifecycleGateRequirement("runtime.transition", str(payload["authorized_subject"])),
        )
        if payload["approval_required"] or public_config(authority_home).enabled:
            # Only the live coordinator retains this in-memory grant. A signed
            # inverse record is never treated as fresh forward gate proof.
            validate_grant(
                authority_home,
                self._forward_grant,
                purpose="protection_lifecycle",
                strict=True,
                action="runtime.transition",
                scope="local-protection",
                subject=str(payload["authorized_subject"]),
            )

    def _compare_installs(self, payload: dict[str, object], generation: str) -> None:
        changes = _record_installs(payload)
        if not changes:
            return
        if self.install_store is None:
            raise TransitionError("managed_install_store_unavailable")
        for change in changes:
            if self.install_store.get_managed_install(change.harness) != change.snapshot(generation):
                raise TransitionError("managed_install_generation_changed")

    def _apply_installs(
        self,
        payload: dict[str, object],
        expected: str,
        replacement: str,
        callback: Callable[[], None],
        *,
        inverse: bool = False,
    ) -> None:
        changes = _record_installs(payload)
        if not changes:
            callback()
            return
        if self.install_store is None:
            raise TransitionError("managed_install_store_unavailable")
        updates = [
            (
                change.harness,
                (change.snapshot(expected), change.after) if inverse else (change.snapshot(expected),),
                change.snapshot(replacement),
            )
            for change in changes
        ]
        if not self.install_store.compare_and_set_managed_installs(updates, before_mutation=callback):
            raise TransitionError("managed_install_generation_changed")

    @staticmethod
    def _write_file(change: dict[str, object], generation: str) -> None:
        _check_inverse_deadline()
        if change["before"] == change["after"] and change["before_mode"] == change["after_mode"]:
            # Retained backups are compared as dependencies, never replaced.
            return
        target = Path(str(change["path"]))
        data = _decode(change[generation])
        mode = change[f"{generation}_mode"]
        if not isinstance(mode, int):
            raise TransitionError("file_mode_invalid")
        if change.get("no_follow"):
            from ..safe_output import remove_file_no_follow, write_bytes_atomic_no_follow

            if data is None:
                remove_file_no_follow(target)
            else:
                write_bytes_atomic_no_follow(target, data, mode=mode)
        elif data is None:
            restore_private_file(target, None)
        else:
            atomic_write_bytes(target, data, mode=mode, private=False)
        _check_inverse_deadline()

    @staticmethod
    def _compare(payload: dict[str, object], generation: str, *, inverse: bool = False) -> None:
        changes = payload.get("files")
        if not isinstance(changes, list):
            raise TransitionError("files_invalid")
        for change in changes:
            _check_inverse_deadline()
            if not isinstance(change, dict):
                raise TransitionError("files_invalid")
            target = Path(str(change["path"]))
            if not target.is_absolute() or target.resolve(strict=False) != target:
                raise TransitionError("file_target_changed")
            if "expected_digest" in change:
                _validate_digest_dependency(change)
                if "artifact_identity" in change:
                    identity = cast(dict[str, object], change["artifact_identity"])
                    invocation = cast(dict[str, object] | None, change.get("invocation_identity"))
                    invocation_before = _invocation_generation(target, invocation) if invocation is not None else None
                    digest = _artifact_digest(target, identity, cast(int, change["before_mode"]))
                    if digest != change["expected_digest"]:
                        raise TransitionError("generation_changed")
                    if invocation is not None and _invocation_generation(target, invocation) != invocation_before:
                        raise TransitionError("invocation_generation_changed")
                    continue
                current = _snapshot(target)
                if current is None or hashlib.sha256(current).hexdigest() != change["expected_digest"]:
                    raise TransitionError("generation_changed")
                if os.name != "nt" and target.stat().st_mode & 0o777 != change["before_mode"]:
                    raise TransitionError("file_mode_changed")
                continue
            current = _snapshot(target)
            expected = _decode(change[generation])
            allowed = (expected, _decode(change["after"])) if inverse else (expected,)
            if current not in allowed:
                raise TransitionError("generation_changed")
            if current is not None and os.name != "nt":
                mode = target.stat().st_mode & 0o777
                expected_modes = (
                    (change[f"{generation}_mode"], change["after_mode"]) if inverse else (change[f"{generation}_mode"],)
                )
                if mode not in expected_modes:
                    raise TransitionError("file_mode_changed")

    @contextmanager
    def _mutation_scope(self, operation_id: str):
        payload = self._read(operation_id)
        if payload["phase"] not in {"AuthorizedForExactTransition", "HooksPrepared"}:
            raise TransitionError("phase_changed")
        if payload["owner"] != current_process_identity():
            raise TransitionError("forward_owner_changed")
        if time.monotonic() >= _record_number(payload, "forward_expires_monotonic"):
            raise TransitionError("forward_authorization_expired")
        self._validate_forward_grant(payload)
        token = _ACTIVE_TRANSITION.set((self.home, operation_id, _record_number(payload, "forward_expires_monotonic")))
        try:
            with sqlite_operation_deadline(
                min(
                    _record_number(payload, "deadline_monotonic"),
                    _record_number(payload, "forward_expires_monotonic"),
                )
            ):
                yield
        finally:
            _ACTIVE_TRANSITION.reset(token)

    def advance(self, operation_id: str, expected_phase: str, *, functional_proof: object = None) -> str:
        payload = self._read(operation_id)
        if payload["phase"] != expected_phase or expected_phase not in _FORWARD:
            raise TransitionError("phase_changed")
        if payload["owner"] != current_process_identity():
            raise TransitionError("forward_owner_changed")
        if time.monotonic() >= _record_number(payload, "deadline_monotonic"):
            raise TransitionError("deadline_exceeded")
        if expected_phase in {"AuthorizedForExactTransition", "HooksPrepared"} and time.monotonic() >= _record_number(
            payload, "forward_expires_monotonic"
        ):
            raise TransitionError("forward_authorization_expired")
        if expected_phase in {"AuthorizedForExactTransition", "HooksPrepared"}:
            self._validate_forward_grant(payload)
        self._compare_installs(payload, "after")
        if expected_phase == "AuthorizedForExactTransition":
            self._compare(
                {
                    **payload,
                    "files": [
                        change
                        for change in _record_objects(payload, "files", maximum=128)
                        if change["kind"] == "binding"
                    ],
                },
                "after",
            )
            self._compare(
                {
                    **payload,
                    "files": [
                        change
                        for change in _record_objects(payload, "files", maximum=128)
                        if change["kind"] == "selection"
                    ],
                },
                "before",
            )
        elif expected_phase == "HooksPrepared":
            self._compare(payload, "after")
            payload["functional_started_monotonic"] = time.monotonic()
        if expected_phase in {"Switching", "CandidateFunctional"}:
            observation = self._validate_functional_proof(payload, functional_proof, "candidate")
            self._compare(payload, "after")
            payload["functional_proof"] = observation
        payload["phase"] = _FORWARD[expected_phase]
        self._write(payload)
        return str(payload["phase"])

    def authorize_runtime_step(self, operation_id: str, expected_phase: str) -> None:
        """Validate the live exact grant before a coordinator lifecycle call.

        This does not admit ordinary install/bootstrap writers or export a
        reusable capability to a child process.
        """
        payload = self._read(operation_id)
        if expected_phase not in {"HooksPrepared", "Switching"} or payload["phase"] != expected_phase:
            raise TransitionError("phase_changed")
        if payload["owner"] != current_process_identity():
            raise TransitionError("forward_owner_changed")
        if time.monotonic() >= _record_number(payload, "forward_expires_monotonic"):
            raise TransitionError("forward_authorization_expired")
        self._validate_forward_grant(payload)

    def authorize_daemon_step(self, operation_id: str, *, subject: str, side: str, action: str) -> None:
        """Admit only the planned lifecycle step, including its exact inverse."""
        payload = self._read(operation_id)
        if payload["authorized_subject"] != subject:
            raise TransitionError("plan_context_mismatch")
        forward = {
            ("predecessor", "stop"): "HooksPrepared",
            ("candidate", "start"): "Switching",
            ("candidate", "observe"): "Switching",
        }
        if (side, action) in forward and payload["phase"] == forward[(side, action)]:
            self.authorize_runtime_step(operation_id, forward[(side, action)])
            return
        if (
            payload["phase"] != "RestoringPrevious"
            or payload.get("recovery_owner") != current_process_identity()
            or (side, action) not in {("candidate", "stop"), ("predecessor", "start"), ("predecessor", "observe")}
        ):
            raise TransitionError("daemon_step_not_authorized")
        if action != "stop":
            if payload.get("inverse_files_restored") is not True:
                raise TransitionError("inverse_not_restored")
            self._compare(payload, "before")
            self._compare_installs(payload, "before")

    def _validate_functional_proof(
        self,
        payload: Mapping[str, object],
        proof: object,
        side: str,
    ) -> dict[str, object]:
        from .runtime_transition_admission import verified_admission_payload

        observation = verified_admission_payload(proof)
        native = _native_runtime_bindings(payload).get(side)
        observed = _record_number(observation, "observed_monotonic")
        if (
            native is None
            or observation["runtime_identity"] != native
            or observation["operation_id"] != payload["operation_id"]
            or observation["generation"] != _artifact_identity(payload[side])["generation"]
            or observation["guard_home"] != str(self.home)
            or observed < _record_number(payload, "functional_started_monotonic")
            or observed > time.monotonic()
        ):
            raise TransitionError("functional_proof_missing")
        return observation

    def publish(self, operation_id: str, expected_phase: str) -> str:
        payload = self._read(operation_id)
        if payload["phase"] != expected_phase or expected_phase not in {
            "AuthorizedForExactTransition",
            "HooksPrepared",
        }:
            raise TransitionError("phase_changed")
        kind = "binding" if expected_phase == "AuthorizedForExactTransition" else "selection"
        selected = [change for change in _record_objects(payload, "files", maximum=128) if change["kind"] == kind]

        def publish_files():
            self._compare({**payload, "files": selected}, "before")
            for change in selected:
                _assert_publish_scope(self.home)
                self._validate_forward_grant(payload)
                self._write_file(change, "after")
            self._compare({**payload, "files": selected}, "after")

        with self._mutation_scope(operation_id):
            self._apply_installs(payload, "before" if kind == "binding" else "after", "after", publish_files)
            return self.advance(operation_id, expected_phase)

    def prepare_recovery(self, operation_id: str, *, first_cause: str) -> None:
        """Persist inverse ownership before retiring a partially started runtime."""
        payload = self._read(operation_id)
        if payload["phase"] in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("terminal_transition")
        payload["first_cause"] = payload.get("first_cause") or first_cause[:512]
        payload["phase"] = "RestoringPrevious"
        recovery_owner = current_process_identity()
        if recovery_owner is None:
            raise TransitionError("owner_identity_unavailable")
        payload["recovery_owner"] = recovery_owner
        payload["inverse_files_restored"] = False
        self._write(payload)

    def restore_files(self, operation_id: str, *, first_cause: str) -> None:
        _check_inverse_deadline()
        self.prepare_recovery(operation_id, first_cause=first_cause)
        payload = self._read(operation_id)

        def restore():
            self._compare(payload, "before", inverse=True)
            for change in _record_objects(payload, "files", maximum=128):
                self._write_file(change, "before")
            self._compare(payload, "before")

        try:
            self._apply_installs(payload, "before", "before", restore, inverse=True)
            self._compare_installs(payload, "before")
            _check_inverse_deadline()
        except Exception as exc:
            payload["phase"] = "RecoveryRequired"
            payload["recovery_causes"] = [
                *_record_objects(payload, "recovery_causes", maximum=8),
                {
                    "code": exc.reason if isinstance(exc, TransitionError) else type(exc).__name__,
                    "errno": getattr(exc, "errno", None),
                },
            ][-8:]
            self._write(payload)
            raise
        # File restoration alone never declares the previous daemon/protection
        # functional. The caller must supply a real protected-hook observation.
        payload["functional_started_monotonic"] = time.monotonic()
        payload["inverse_files_restored"] = True
        self._write(payload)

    def finish_rollback(self, operation_id: str, *, functional_proof: object) -> None:
        payload = self._read(operation_id)
        if payload["phase"] not in {"RestoringPrevious", "PreviousFunctional"}:
            raise TransitionError("phase_changed")
        if payload["recovery_owner"] != current_process_identity():
            raise TransitionError("recovery_owner_changed")
        observation = self._validate_functional_proof(payload, functional_proof, "predecessor")
        self._compare(payload, "before")
        self._compare_installs(payload, "before")
        payload["phase"] = "PreviousFunctional"
        payload["rollback_functional_proof"] = observation
        self._write(payload)
        payload["phase"] = "FailedWithVerifiedRollback"
        self._write(payload)

    def record_recovery_failure(self, operation_id: str, *, first_cause: str, error: Exception) -> None:
        """Persist failure of runtime retirement/start/admission after an inverse."""
        payload = self._read(operation_id)
        if payload["phase"] in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("terminal_transition")
        identity = current_process_identity()
        if identity is None or identity not in (payload.get("owner"), payload.get("recovery_owner")):
            raise TransitionError("recovery_owner_changed")
        payload["first_cause"] = payload.get("first_cause") or first_cause[:512]
        payload["phase"] = "RecoveryRequired"
        payload["recovery_causes"] = [
            *_record_objects(payload, "recovery_causes", maximum=8),
            {
                "code": error.reason if isinstance(error, TransitionError) else type(error).__name__,
                "errno": getattr(error, "errno", None),
            },
        ][-8:]
        self._write(payload)

    def retire(self, operation_id: str) -> None:
        payload = self._read(operation_id)
        phase = payload["phase"]
        if phase not in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("nonterminal_transition")
        self._compare(payload, "after" if phase == "Committed" else "before")
        self._compare_installs(payload, "after" if phase == "Committed" else "before")
        previous = self.path.with_name("runtime-transition.previous.json")
        if (previous.exists() or previous.is_symlink()) and read_private_regular_text(
            previous, max_bytes=_MAX_RECORD
        ) is None:
            raise TransitionError("previous_record_unsafe")
        # Keep one private terminal receipt; never delete a pending operation.
        os.replace(self.path, previous)
        fsync_directory(previous.parent)

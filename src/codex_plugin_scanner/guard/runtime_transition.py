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
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, cast

from .approval_gate import ApprovalGateGrant, public_config, validate_grant
from .codex_hook_recovery import _decode, _encode, _snapshot
from .live_process_identity import current_process_identity
from .native_owned import require_codex_install_owner
from .runtime_transition_modes import normalized_after_mode, publishes_user_file
from .runtime_transition_record import TransitionRecordRefusedError, record_request
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


def _cause(error: BaseException) -> dict[str, object]:
    """The `{code, errno}` cause a recovery record keeps for `error`."""

    errno = getattr(error, "errno", None)
    return {
        "code": error.reason if isinstance(error, TransitionError) else type(error).__name__,
        "errno": errno if isinstance(errno, int) and not isinstance(errno, bool) else None,
    }


@dataclass(frozen=True)
class TransitionStatus:
    operation_id: str
    phase: str
    first_cause: str | None
    recovery_causes: tuple[dict[str, object], ...]
    artifact_generation: str | None = None


#: Read flags for hashing an artifact: without O_BINARY Windows opens a text
#: descriptor that stops at the first Ctrl-Z byte and folds CRLF.
ARTIFACT_READ_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def descriptor_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    """The file identity a path's `lstat` and its open descriptor's `fstat` agree on.

    On Windows they disagree on two fields: `lstat` reports creation time as
    st_ctime where `fstat` reports change time, and only `lstat` adds execute
    bits for an executable extension.
    """
    windows = os.name == "nt"
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        0 if windows else metadata.st_ctime_ns,
        metadata.st_mode & ~0o111 if windows else metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


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
        # Normalize tuples to the same JSON shape returned by GuardStore; the
        # runtime checks the rows when the plan is checked.
        encoded = json.dumps(
            {"harness": self.harness, "before": self.before, "after": self.after},
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return json.loads(encoded)


def _record_installs(payload: Mapping[str, object]) -> list[TransitionInstall]:
    """The managed install rows of a record the runtime already checked."""
    rows = cast(list[dict[str, Any]], payload.get("managed_installs", []))
    return [TransitionInstall(row["harness"], row["before"], row["after"]) for row in rows]


def _record_request(op: str, *, deadline: float | None = None, **fields: object) -> dict[str, object]:
    try:
        return record_request(op, Path(), None, deadline=deadline, **fields)
    except TransitionRecordRefusedError as error:
        raise TransitionError(error.reason, error.detail) from error


def check_transition_files(changes: Sequence[Mapping[str, object]], *, each: bool = False) -> None:
    """The runtime refuses any planned change a transition may not record.

    ``each`` checks every change on its own; otherwise they form one record.
    """
    op = "files_check_each" if each else "files_check"
    _record_request(op, payload={"files": [dict(change) for change in changes]})


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
        compared: bool = True,
    ) -> TransitionFile:
        """Pin the exact artifact without journaling its bytes; batch callers compare later."""
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
        if compared:
            RuntimeTransition._compare({"files": [change.payload()]}, "before")
        return change

    def _raw(self) -> dict[str, object]:
        if not self.path.is_absolute() or self.path.is_symlink():
            raise TransitionError("file_target_invalid")
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
        return payload

    def payload(self) -> dict[str, object]:
        """The planned change; the runtime checks its shape where it is used."""
        return self._raw()

    def checked(self) -> dict[str, object]:
        payload = self._raw()
        check_transition_files([payload], each=True)
        return payload


def merge_transition_dependency(previous: TransitionFile, change: TransitionFile) -> TransitionFile:
    """Merge shared immutable bytes without weakening either invocation contract.

    Frozen roles share one executable. Their role names remain authenticated
    in the hook manifest; the transition needs one filesystem dependency with
    the strongest exact invocation contract, rather than duplicate targets.
    Mutable writes and authority-only dependencies never use this merge.
    """
    from .native_transition_files import merge_dependency

    merged = merge_dependency(previous.payload(), change.payload())
    if merged.get("same") is True:
        return previous
    artifact, invocation = merged.get("artifact_identity"), merged.get("invocation_identity")
    if not isinstance(artifact, dict) or not (invocation is None or isinstance(invocation, dict)):
        raise TransitionError("native_transition_invalid")
    return replace(
        previous,
        artifact_identity=cast(dict[str, object], artifact),
        invocation_identity=cast(dict[str, object] | None, invocation),
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

    def _raw(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "guard_home": str(self.guard_home.resolve(strict=False)),
            "predecessor": dict(self.predecessor),
            "candidate": dict(self.candidate),
            "files": [change._raw() for change in self.files],
            "deadline_epoch": self.deadline_epoch,
            "managed_installs": [change.payload() for change in self.managed_installs],
            "native_runtimes": dict(self.native_runtimes or {}),
        }

    def checked(self, *, deadline: float | None = None) -> tuple[dict[str, object], str]:
        """The plan the runtime accepted, and the subject its approval binds."""
        payload = self._raw()
        subject = _record_request("plan_check", deadline=deadline, payload=payload).get("subject")
        if not isinstance(subject, str):
            raise TransitionError("record_invalid")
        return payload, subject

    def payload(self) -> dict[str, object]:
        return self.checked()[0]

    def subject(self) -> str:
        return self.checked()[1]


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

    def _optional_key(self) -> tuple[bytes, str] | None:
        try:
            return self._key()
        except TransitionError:
            return None

    def _native(
        self, op: str, key: tuple[bytes, str] | None, *, deadline: float | None = None, **fields: object
    ) -> dict[str, object]:
        try:
            return record_request(op, self.home, key, deadline=deadline, **fields)
        except TransitionRecordRefusedError as error:
            raise TransitionError(error.reason, error.detail) from error

    def record_approval_refusal(self, plan: TransitionPlan, reason: str, *, deadline_monotonic: float) -> None:
        """Record only a refusal before begin; this is never a forward grant."""
        require_codex_install_owner(self.home)
        if plan.guard_home != self.home:
            raise TransitionError("refusal_context_invalid")
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("deadline_exceeded")
        # The runtime refuses while any journal exists, and writes the signed
        # receipt create-only. The shared home owner excludes a concurrent begin.
        self._native(
            "refusal_write",
            self._optional_key(),
            operation_id=plan.operation_id,
            artifact_generation=str(plan.candidate["generation"]),
            reason_code=reason,
            deadline=deadline_monotonic,
        )

    def refusal_status(self, operation_id: str) -> TransitionStatus:
        require_codex_install_owner(self.home)
        answer = self._native("refusal_read", self._optional_key(), operation_id=operation_id)
        reason, generation = answer.get("reason_code"), answer.get("artifact_generation")
        if not isinstance(reason, str) or not isinstance(generation, str):
            raise TransitionError("refusal_context_invalid")
        return TransitionStatus(operation_id, "NotStarted", reason, (), generation)

    def _write(self, payload: dict[str, object], *, deadline: float | None = None) -> None:
        require_codex_install_owner(self.home)
        self._native("write", self._key(), payload=payload, deadline=deadline)

    def _read(self, operation_id: str) -> dict[str, object]:
        return self._read_record(operation_id, previous=False)

    def _read_record(self, operation_id: str, *, previous: bool) -> dict[str, object]:
        require_codex_install_owner(self.home)
        answer = self._native("read", self._optional_key(), operation_id=operation_id, previous=previous)
        payload = answer.get("payload")
        if not isinstance(payload, dict):
            raise TransitionError("record_invalid")
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
        # The runtime refuses a refused operation, another home, a plan that
        # touches the journal or its authority, a pending transition and a
        # deadline outside the next minute, and answers the monotonic deadline.
        if deadline_monotonic is not None and not math.isfinite(deadline_monotonic):
            raise TransitionError("deadline_exceeded")
        payload, subject = plan.checked(deadline=deadline_monotonic)
        request: dict[str, Any] = {
            "payload": payload,
            "now": time.monotonic(),
            "now_epoch": time.time(),
            "deadline_monotonic": deadline_monotonic,
        }
        answer = self._native("begin_check", None, deadline=deadline_monotonic, **request)
        deadline = answer.get("deadline")
        if not isinstance(deadline, int | float):
            raise TransitionError("record_invalid")
        expected_authority_home = lifecycle_authority_home(
            self.home, requirement=LifecycleGateRequirement("runtime.transition", subject)
        )
        if authority_home.resolve(strict=False) != expected_authority_home.resolve(strict=False):
            raise TransitionError("approval_authority_mismatch")
        approval_required = public_config(authority_home).enabled
        if approval_required:
            self._validate_begin_grant(authority_home, grant, subject)
        elif grant is not None:
            raise TransitionError("unexpected_grant")
        identity = current_process_identity()
        if identity is None:
            raise TransitionError("owner_identity_unavailable")
        self._compare(payload, "before")
        self._compare_installs(payload, "before")
        if grant is not None:
            self._validate_begin_grant(authority_home, grant, subject)
        self._native(
            "begin_commit",
            self._key(),
            deadline=float(deadline),
            owner=identity,
            installer_operation_id=owner.operation_id,
            subject=subject,
            approval_required=approval_required,
            grant_expires_epoch=(
                datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00")).timestamp()
                if grant is not None
                else None
            ),
            **request,
        )
        self._forward_grant = grant

    @staticmethod
    def _validate_begin_grant(authority_home: Path, grant: ApprovalGateGrant | None, subject: str) -> None:
        validate_grant(
            authority_home,
            grant,
            purpose="protection_lifecycle",
            strict=True,
            action="runtime.transition",
            scope="local-protection",
            subject=subject,
        )

    def status(self, operation_id: str) -> TransitionStatus:
        payload = self._read(operation_id)
        return TransitionStatus(
            operation_id,
            str(payload["phase"]),
            str(payload["first_cause"]) if payload["first_cause"] is not None else None,
            tuple(cast(list[dict[str, object]], payload.get("recovery_causes", []))),
            str(cast(dict[str, object], payload["candidate"])["generation"]),
        )

    def archived_status(self, operation_id: str) -> TransitionStatus:
        require_codex_install_owner(self.home)
        if self.path.exists() or self.path.is_symlink():
            raise TransitionError("pending_transition")
        payload = self._read_record(operation_id, previous=True)
        if payload["phase"] not in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("nonterminal_transition")
        return TransitionStatus(
            operation_id,
            str(payload["phase"]),
            str(payload["first_cause"]) if payload["first_cause"] is not None else None,
            tuple(cast(list[dict[str, object]], payload.get("recovery_causes", []))),
            str(cast(dict[str, object], payload["candidate"])["generation"]),
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
            for change in cast(list[dict[str, object]], payload["files"])
        )
        plan = TransitionPlan(
            operation_id,
            self.home,
            cast(dict[str, object], payload["predecessor"]),
            cast(dict[str, object], payload["candidate"]),
            files,
            float(cast(float, payload["deadline_epoch"])),
            managed_installs=tuple(_record_installs(payload)),
            native_runtimes=cast(dict[str, object], payload.get("native_runtimes", {})),
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

    def _step(self, op: str, operation_id: str, step: str, **fields: object) -> dict[str, object]:
        """Ask the runtime to check or commit one phase step of the journal."""

        require_codex_install_owner(self.home)
        owner = current_process_identity()
        request: dict[str, Any] = {
            "operation_id": operation_id,
            "step": step,
            "owner": owner,
            "now": time.monotonic(),
            **fields,
        }
        try:
            return record_request(op, self.home, self._key(), **request)
        except TransitionRecordRefusedError as error:
            raise TransitionError(error.reason, error.detail) from error

    def _checked(self, operation_id: str, step: str, **fields: object) -> dict[str, object]:
        """Run the grant, install and file comparisons the runtime names."""

        answer = self._step("step_check", operation_id, step, **fields)
        payload = answer.get("payload")
        compares = answer.get("compare")
        if not isinstance(payload, dict) or not isinstance(compares, list):
            raise TransitionError("record_invalid")
        if answer.get("grant") is True:
            self._validate_forward_grant(payload)
        installs = answer.get("installs")
        if isinstance(installs, str):
            self._compare_installs(payload, installs)
        for item in compares:
            if not isinstance(item, dict) or not isinstance(item.get("generation"), str):
                raise TransitionError("record_invalid")
            self._compare({"files": item.get("files")}, str(item["generation"]))
        return answer

    def _commit(self, operation_id: str, step: str, **fields: object) -> str:
        return str(self._step("step_commit", operation_id, step, **fields).get("phase"))

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
        from .native_transition_files import write_file

        write_file(change, generation)

    @staticmethod
    def _compare(payload: dict[str, object], generation: str, *, inverse: bool = False) -> None:
        from .native_transition_files import compare_files

        changes = payload.get("files")
        if not isinstance(changes, list):
            raise TransitionError("files_invalid")
        compare_files(changes, generation, inverse=inverse)

    @contextmanager
    def _mutation_scope(self, operation_id: str):
        answer = self._checked(operation_id, "mutation_scope")
        expires, deadline = answer.get("forward_expires"), answer.get("sqlite_deadline")
        if not isinstance(expires, float | int) or not isinstance(deadline, float | int):
            raise TransitionError("deadline_invalid")
        token = _ACTIVE_TRANSITION.set((self.home, operation_id, float(expires)))
        try:
            with sqlite_operation_deadline(float(deadline)):
                yield
        finally:
            _ACTIVE_TRANSITION.reset(token)

    def _observation(self, proof: object) -> dict[str, object] | None:
        if proof is None:
            return None
        from .runtime_transition_admission import verified_admission_payload

        return verified_admission_payload(proof)

    def advance(self, operation_id: str, expected_phase: str, *, functional_proof: object = None) -> str:
        fields: dict[str, object] = {"expected_phase": expected_phase}
        if expected_phase in {"Switching", "CandidateFunctional"}:
            fields["observation"] = self._observation(functional_proof)
        self._checked(operation_id, "advance", **fields)
        return self._commit(operation_id, "advance", **fields)

    def authorize_runtime_step(self, operation_id: str, expected_phase: str) -> None:
        """Validate the live exact grant before a coordinator lifecycle call.

        This does not admit ordinary install/bootstrap writers or export a
        reusable capability to a child process.
        """
        self._checked(operation_id, "runtime_step", expected_phase=expected_phase)

    def authorize_daemon_step(self, operation_id: str, *, subject: str, side: str, action: str) -> None:
        """Admit only the planned lifecycle step, including its exact inverse."""
        self._checked(operation_id, "daemon_step", subject=subject, side=side, action=action)

    def publish(self, operation_id: str, expected_phase: str) -> str:
        answer = self._checked(operation_id, "publish", expected_phase=expected_phase)
        payload, selected = answer["payload"], answer.get("selected")
        expected = answer.get("installs_expected")
        if not isinstance(payload, dict) or not isinstance(selected, list) or not isinstance(expected, str):
            raise TransitionError("record_invalid")

        def publish_files():
            self._compare({"files": selected}, "before")
            for change in selected:
                _assert_publish_scope(self.home)
                self._validate_forward_grant(payload)
                self._write_file(change, "after")
            self._compare({"files": selected}, "after")

        with self._mutation_scope(operation_id):
            self._apply_installs(payload, expected, "after", publish_files)
            return self.advance(operation_id, expected_phase)

    def prepare_recovery(self, operation_id: str, *, first_cause: str) -> None:
        """Persist inverse ownership before retiring a partially started runtime."""
        self._commit(operation_id, "prepare_recovery", first_cause=first_cause)

    def restore_files(self, operation_id: str, *, first_cause: str) -> None:
        _check_inverse_deadline()
        self.prepare_recovery(operation_id, first_cause=first_cause)
        payload = self._read(operation_id)

        def restore():
            self._compare(payload, "before", inverse=True)
            for change in cast(list[dict[str, object]], payload["files"]):
                self._write_file(change, "before")
            self._compare(payload, "before")

        try:
            self._apply_installs(payload, "before", "before", restore, inverse=True)
            self._compare_installs(payload, "before")
            _check_inverse_deadline()
        except Exception as exc:
            self._commit(operation_id, "restore_failed", cause=_cause(exc))
            raise
        # File restoration alone never declares the previous daemon/protection
        # functional. The caller must supply a real protected-hook observation.
        self._commit(operation_id, "restored")

    def finish_rollback(self, operation_id: str, *, functional_proof: object) -> None:
        observation = self._observation(functional_proof)
        self._checked(operation_id, "finish_rollback", observation=observation)
        if self._commit(operation_id, "finish_rollback", observation=observation) == "PreviousFunctional":
            self._commit(operation_id, "finish_rollback", observation=observation)

    def record_recovery_failure(self, operation_id: str, *, first_cause: str, error: Exception) -> None:
        """Persist failure of runtime retirement/start/admission after an inverse."""
        self._commit(operation_id, "recovery_failure", first_cause=first_cause, cause=_cause(error))

    def retire(self, operation_id: str) -> None:
        payload = self._read(operation_id)
        phase = payload["phase"]
        if phase not in {"Committed", "FailedWithVerifiedRollback"}:
            raise TransitionError("nonterminal_transition")
        self._compare(payload, "after" if phase == "Committed" else "before")
        self._compare_installs(payload, "after" if phase == "Committed" else "before")
        # Keep one private terminal receipt; never delete a pending operation.
        self._native("retire", None)

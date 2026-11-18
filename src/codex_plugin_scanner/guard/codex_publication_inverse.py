"""Durable, provisionally restored Codex authority under exact local approval.

Interrupted explicit inverses remain recovery-required. Neither the old
installer grant nor a serialized native assertion can retire this journal.
"""

from __future__ import annotations

import base64
import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import native_transition_files
from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_recovery import _load_record, _remove_record
from .codex_hook_rollback import rollback_file_identity
from .codex_publication_inverse_authorization import CodexPublicationInverseAuthorization
from .codex_publication_inverse_plan import native_runtime_wire, workspace_wire
from .runtime_transition import RuntimeTransition, TransitionError, inverse_recovery_budget
from .runtime_transition_admission import verified_admission_payload

if TYPE_CHECKING:
    from .runtime_transition_admission import NativeProtectionAdmission
    from .store import GuardStore

_publications: dict[str, PendingCodexPublicationInverse] = {}
_publications_guard = threading.RLock()


def _after_fork_child() -> None:
    global _publications, _publications_guard
    _publications = {}
    _publications_guard = threading.RLock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


@dataclass(frozen=True, slots=True, repr=False)
class PendingCodexPublicationInverse:
    authorization: CodexPublicationInverseAuthorization
    publication_monotonic: float
    _record: dict[str, object]
    _journal_sha256: str
    _journal_identity: tuple[int, int, int, int, int]
    _identities: tuple[tuple[int, int, int, int, int] | None, ...]
    _restored: tuple[int, ...] = ()

    def compare(self) -> None:
        authorization, plan = self.authorization, self.authorization.plan
        authorization.check()
        with _publications_guard:
            if _publications.get(authorization.grant.grant_id) is not self:
                raise TransitionError("publication_inverse_publication_invalid")
        with (
            inverse_recovery_budget(authorization.deadline_monotonic),
            hook_validation_deadline(
                authorization.deadline_monotonic,
            ),
        ):
            native_transition_files.publication(
                "inverse_journal",
                plan.guard_home,
                journal_identity=list(self._journal_identity),
                journal_sha256=self._journal_sha256,
                record=self._record,
            )
            predecessor = plan.changes[1].after
            assert predecessor is not None
            native_transition_files.publication(
                "inverse_pinned",
                plan.guard_home,
                manifest_text=predecessor.decode("utf-8"),
                dependencies=[item.payload() for item in plan.dependencies],
                native_runtime=native_runtime_wire(plan.native_runtime),
                verification_workspace=workspace_wire(plan.verification_workspace),
            )
            for index, (change, identity) in enumerate(zip(plan.changes, self._identities, strict=True)):
                generation = "after" if index in self._restored else "before"
                if rollback_file_identity(change.path) != identity:
                    raise TransitionError("publication_inverse_generation_changed")
                RuntimeTransition._compare({"files": [change.payload()]}, generation)
                if rollback_file_identity(change.path) != identity:
                    raise TransitionError("publication_inverse_generation_changed")
        authorization.check()

    def guard(self) -> list[dict[str, object]]:
        """What ``compare`` checks, for the native op to repeat before it writes."""
        plan = self.authorization.plan
        entries: list[dict[str, object]] = [
            {"file": item.payload(), "generation": "before", "identity": None} for item in plan.dependencies
        ]
        for index, (change, identity) in enumerate(zip(plan.changes, self._identities, strict=True)):
            entries.append(
                {
                    "file": change.payload(),
                    "generation": "after" if index in self._restored else "before",
                    "identity": list(identity) if identity is not None else None,
                }
            )
        return entries

    def _write_record(self, *, phase: str, observation: dict[str, object] | None = None) -> None:
        self.compare()
        plan = self.authorization.plan
        marker: dict[str, object] = {
            "schema": "hol-guard.codex-explicit-publication-inverse.v1",
            "subject": self.authorization.approved_subject,
            "owner_operation_id": self.authorization.owner_operation_id,
            "owner_pid": self.authorization.owner_pid,
            "plan": plan.payload(),
            "phase": phase,
            "publication_monotonic": self.publication_monotonic,
            "restored": list(self._restored),
            "file_identities": [list(value) if value is not None else None for value in self._identities],
        }
        if observation is not None:
            marker["native_verification"] = observation
        self.compare()
        with (
            inverse_recovery_budget(self.authorization.deadline_monotonic),
            hook_validation_deadline(self.authorization.deadline_monotonic),
        ):
            answer = native_transition_files.publication(
                "inverse_record",
                plan.guard_home,
                record=self._record,
                marker=marker,
                journal_sha256=self._journal_sha256,
                journal_identity=list(self._journal_identity),
                signed_at=self.authorization.owner_operation_id,
                guard=self.guard(),
            )
        payload, sha256, identity = _record_answer(answer)
        object.__setattr__(self, "_record", payload)
        object.__setattr__(self, "_journal_sha256", sha256)
        object.__setattr__(self, "_journal_identity", identity)
        self.compare()


def _identity(value: object) -> tuple[int, int, int, int, int] | None:
    if (
        not isinstance(value, list)
        or len(value) != 5
        or not all(isinstance(item, int) and not isinstance(item, bool) for item in value)
    ):
        return None
    return (value[0], value[1], value[2], value[3], value[4])


def _record_answer(answer: object) -> tuple[dict[str, object], str, tuple[int, int, int, int, int]]:
    record = answer.get("record") if isinstance(answer, dict) else None
    sha256 = answer.get("sha256") if isinstance(answer, dict) else None
    identity = _identity(answer.get("identity") if isinstance(answer, dict) else None)
    if not isinstance(record, dict) or not isinstance(sha256, str) or identity is None:
        raise TransitionError("publication_inverse_journal_changed")
    return record, sha256, identity


def _encoded(value: bytes | None) -> str | None:
    return None if value is None else base64.b64encode(value).decode("ascii")


def publish_codex_publication_inverse(
    authorization: CodexPublicationInverseAuthorization,
) -> PendingCodexPublicationInverse:
    """Restore reviewed bindings once; keep the signed journal until proof."""
    authorization.compare_before()
    plan = authorization.plan
    with (
        inverse_recovery_budget(authorization.deadline_monotonic),
        hook_validation_deadline(
            authorization.deadline_monotonic,
        ),
    ):
        record = _load_record(plan.guard_home, live_config_conflict=True)
        authorization.compare_before()
        pending = PendingCodexPublicationInverse(
            authorization,
            time.monotonic(),
            record,
            plan.journal_sha256,
            plan.journal_identity,
            plan.change_identities,
        )
        with _publications_guard:
            # The runtime decides who is admitted; this keeps only the handles.
            for identifier in native_transition_files.register_inverse(
                authorization.grant.grant_id, authorization.deadline_monotonic
            ):
                _publications.pop(identifier, None)
            _publications[authorization.grant.grant_id] = pending
        # Persist the reviewed current generation before changing any target.
        pending._write_record(phase="restoring")
        # Restore authority before publishing its matching configuration.
        for index in (1, 2, 0):
            pending.compare()
            change = plan.changes[index]
            assert change.after is not None
            identity = pending._identities[index]
            with (
                inverse_recovery_budget(authorization.deadline_monotonic),
                hook_validation_deadline(authorization.deadline_monotonic),
            ):
                answer = native_transition_files.publication(
                    "inverse_restore",
                    plan.guard_home,
                    path=os.path.abspath(change.path),
                    after=base64.b64encode(change.after).decode("ascii"),
                    after_mode=change.after_mode,
                    identity=list(identity) if identity is not None else None,
                    guard=pending.guard(),
                )
            identity = _identity(answer.get("identity") if isinstance(answer, dict) else None)
            if identity is None:
                raise TransitionError("publication_inverse_generation_changed")
            identities = list(pending._identities)
            identities[index] = identity
            object.__setattr__(pending, "_identities", tuple(identities))
            object.__setattr__(pending, "_restored", (*pending._restored, index))
            # An exit before this record has an unknown inode and cannot replay.
            pending._write_record(phase="restoring")
        pending._write_record(phase="restored")
        return pending


def verify_and_retire_codex_publication_inverse(
    pending: PendingCodexPublicationInverse,
    *,
    receipt_store: GuardStore | None = None,
) -> NativeProtectionAdmission:
    """Retire only fresh sealed native allow/deny through the restored config."""
    from .runtime_transition_codex_observer import observe_configured_codex_hook

    authorization, plan = pending.authorization, pending.authorization.plan
    with (
        inverse_recovery_budget(authorization.deadline_monotonic),
        hook_validation_deadline(
            authorization.deadline_monotonic,
        ),
    ):
        pending.compare()
        generation = native_transition_files.artifact_generation(
            "inverse",
            plan.subject(),
            bound=plan.native_runtime is not None and plan.verification_workspace is not None,
            restored=pending._restored,
        )
        native_runtime, workspace = plan.native_runtime, plan.verification_workspace
        if native_runtime is None or workspace is None:
            raise TransitionError("publication_inverse_not_restored")
        started = time.monotonic()
        proof = observe_configured_codex_hook(
            operation_id=plan.operation_id,
            artifact_generation=generation,
            expected_runtime=native_runtime,
            guard_home=plan.guard_home,
            config_path=plan.config_path,
            workspace=workspace,
            deadline_monotonic=authorization.deadline_monotonic,
            receipt_store=receipt_store,
        )
        pending.compare()
        observation = verified_admission_payload(proof)
        # The runtime decides whether this proof is fresh and is this inverse's.
        native_transition_files.publication(
            "inverse_proof",
            plan.guard_home,
            observation=observation,
            publication=pending.publication_monotonic,
            started=started,
            now=time.monotonic(),
            operation_id=plan.operation_id,
            generation=generation,
            guard_home=str(plan.guard_home),
            runtime_identity=plan.payload()["native_runtime"],
            config_after=_encoded(plan.changes[0].after),
            manifest_after=_encoded(plan.changes[1].after),
        )
        pending._write_record(phase="verified", observation=observation)
        pending.compare()
        _remove_record(plan.guard_home)
        return proof

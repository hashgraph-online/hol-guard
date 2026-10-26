"""Durable, provisionally restored Codex authority under exact local approval.

Interrupted explicit inverses remain recovery-required. Neither the old
installer grant nor a serialized native assertion can retire this journal.
"""

from __future__ import annotations

import hashlib
import math
import os
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .codex_hook_file_integrity import hook_validation_deadline
from .codex_hook_integrity import atomic_write_bytes, canonical_manifest_bytes, load_hook_secret
from .codex_hook_recovery import _MAX_RECORD, _PURPOSE, _load_record, _record_path, _remove_record, _snapshot
from .codex_hook_rollback import rollback_file_identity
from .codex_install_transaction import record_codex_mutation
from .codex_publication_inverse_authorization import CodexPublicationInverseAuthorization
from .codex_publication_inverse_plan import _journal_bytes, _predecessor_dependencies, _with_native_dependency
from .local_authority_integrity import sign_local_authority_payload
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
            journal = _record_path(plan.guard_home)
            if (
                rollback_file_identity(journal) != self._journal_identity
                or hashlib.sha256(_journal_bytes(journal)).hexdigest() != self._journal_sha256
                or _load_record(plan.guard_home, live_config_conflict=True) != self._record
                or rollback_file_identity(journal) != self._journal_identity
            ):
                raise TransitionError("publication_inverse_journal_changed")
            predecessor = plan.changes[1].after
            assert predecessor is not None
            dependencies = _with_native_dependency(
                _predecessor_dependencies(plan.guard_home, predecessor),
                plan.native_runtime,
                plan.verification_workspace,
            )
            if [item.payload() for item in dependencies] != [item.payload() for item in plan.dependencies]:
                raise TransitionError("publication_inverse_dependencies_invalid")
            RuntimeTransition._compare({"files": [item.payload() for item in dependencies]}, "before")
            for index, (change, identity) in enumerate(zip(plan.changes, self._identities, strict=True)):
                generation = "after" if index in self._restored else "before"
                if rollback_file_identity(change.path) != identity:
                    raise TransitionError("publication_inverse_generation_changed")
                RuntimeTransition._compare({"files": [change.payload()]}, generation)
                if rollback_file_identity(change.path) != identity:
                    raise TransitionError("publication_inverse_generation_changed")
        authorization.check()

    def _write_record(self, *, phase: str, observation: dict[str, object] | None = None) -> None:
        self.compare()
        plan = self.authorization.plan
        payload = dict(self._record)
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
        payload["publication_inverse"] = marker
        secret = load_hook_secret(plan.guard_home)
        authentication = sign_local_authority_payload(
            payload,
            key=secret.key,
            key_id=secret.key_id,
            purpose=_PURPOSE,
            signed_at=self.authorization.owner_operation_id,
        )
        encoded = canonical_manifest_bytes({**payload, "authentication": authentication}) + b"\n"
        if len(encoded) > _MAX_RECORD:
            raise TransitionError("publication_inverse_record_too_large")
        self.compare()
        published: list[tuple[int, int, int, int, int]] = []
        atomic_write_bytes(
            _record_path(plan.guard_home),
            encoded,
            mode=0o600,
            private=True,
            on_publish=published.append,
            before_publish=self.compare,
        )
        identity = published[0] if len(published) == 1 else None
        if (
            identity is None
            or rollback_file_identity(_record_path(plan.guard_home)) != identity
            or _journal_bytes(_record_path(plan.guard_home)) != encoded
            or rollback_file_identity(_record_path(plan.guard_home)) != identity
        ):
            raise TransitionError("publication_inverse_journal_changed")
        object.__setattr__(self, "_record", payload)
        object.__setattr__(self, "_journal_sha256", hashlib.sha256(encoded).hexdigest())
        object.__setattr__(self, "_journal_identity", identity)
        self.compare()


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
            now = time.monotonic()
            for identifier, previous in tuple(_publications.items()):
                if previous.authorization.deadline_monotonic <= now:
                    del _publications[identifier]
            if authorization.grant.grant_id in _publications:
                raise TransitionError("publication_inverse_publication_claimed")
            if len(_publications) >= 128:
                raise TransitionError("publication_inverse_publication_capacity")
            _publications[authorization.grant.grant_id] = pending
        # Persist the reviewed current generation before changing any target.
        pending._write_record(phase="restoring")
        # Restore authority before publishing its matching configuration.
        for index in (1, 2, 0):
            pending.compare()
            change = plan.changes[index]
            assert change.after is not None
            identity = pending._identities[index]
            if _snapshot(change.path) != change.after or (
                os.name != "nt" and change.path.stat().st_mode & 0o777 != change.after_mode
            ):
                published: list[tuple[int, int, int, int, int]] = []
                atomic_write_bytes(
                    change.path,
                    change.after,
                    mode=0o600,
                    private=True,
                    on_publish=published.append,
                    before_publish=pending.compare,
                )
                identity = published[0] if len(published) == 1 else None
                record_codex_mutation("explicit_inverse_provisional", change.path, change.before, change.after)
            if (
                identity is None
                or rollback_file_identity(change.path) != identity
                or _snapshot(change.path) != change.after
                or rollback_file_identity(change.path) != identity
            ):
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
        if set(pending._restored) != {0, 1, 2} or plan.native_runtime is None or plan.verification_workspace is None:
            raise TransitionError("publication_inverse_not_restored")
        started = time.monotonic()
        generation = "codex-publication-inverse-" + plan.subject().rsplit(":", 1)[1]
        proof = observe_configured_codex_hook(
            operation_id=plan.operation_id,
            artifact_generation=generation,
            expected_runtime=plan.native_runtime,
            guard_home=plan.guard_home,
            config_path=plan.config_path,
            workspace=plan.verification_workspace,
            deadline_monotonic=authorization.deadline_monotonic,
            receipt_store=receipt_store,
        )
        pending.compare()
        observation = verified_admission_payload(proof)
        evidence = observation.get("installed_hook_evidence")
        observed = observation.get("observed_monotonic")
        if (
            not isinstance(observed, (int, float))
            or isinstance(observed, bool)
            or not math.isfinite(observed)
            or not pending.publication_monotonic <= started <= observed <= time.monotonic()
            or observation.get("operation_id") != plan.operation_id
            or observation.get("generation") != generation
            or observation.get("guard_home") != str(plan.guard_home)
            or observation.get("runtime_identity") != plan.payload()["native_runtime"]
            or not isinstance(evidence, dict)
            or evidence.get("harness") != "codex"
            or evidence.get("config_sha256") != hashlib.sha256(plan.changes[0].after or b"").hexdigest()
            or evidence.get("manifest_sha256") != hashlib.sha256(plan.changes[1].after or b"").hexdigest()
        ):
            raise TransitionError("publication_inverse_native_verification_invalid")
        pending._write_record(phase="verified", observation=observation)
        pending.compare()
        _remove_record(plan.guard_home)
        return proof

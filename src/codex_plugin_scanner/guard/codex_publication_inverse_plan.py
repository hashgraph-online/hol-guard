"""Read-only preparation of an exact inverse for unresolved Codex publication.

A plan conveys no mutation or lifecycle authority. Authentication of the old
journal is necessary but cannot authorize overwriting the current config. The
runtime does the whole preparation and every check; this sends the facts of
this process, keeps the answer as the plan, and settles each reply.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from contextlib import nullcontext
from dataclasses import dataclass, replace
from pathlib import Path

from .codex_hook_file_integrity import (
    active_hook_validation_deadline,
    check_hook_validation_deadline,
    hook_validation_deadline,
)
from .codex_hook_manifest import CodexHookManifestSpec, transition_file
from .codex_hook_recovery import _encode
from .native_owned import require_codex_install_owner
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import publication
from .runtime_transition import (
    TransitionError,
    TransitionFile,
    assert_transition_mutation_allowed,
    inverse_recovery_budget,
)

PUBLICATION_INVERSE_ACTION = "apps.repair.codex-publication-inverse"


def _inverse_budget():
    """The deadline of the validation in progress, carried to the runtime."""
    deadline = active_hook_validation_deadline()
    return inverse_recovery_budget(deadline) if deadline is not None else nullcontext()


def workspace_wire(workspace: Path | None) -> str | None:
    return None if workspace is None else str(workspace)


def native_runtime_wire(native: NativeRuntimeIdentity | None) -> dict[str, object] | None:
    if native is None:
        return None
    return {"path": str(native.path), "size": native.size, "mtime_ns": native.mtime_ns, "sha256": native.sha256}


def _reviewable_prior_inverse(home: Path, record: dict[str, object]) -> str | None:
    """Validate prior intent as review data, never as replay authority."""
    operation = publication("inverse_prior", home, record=record)
    if operation is not None and not isinstance(operation, str):
        raise TransitionError("publication_inverse_prior_record_invalid")
    return operation


def _change_shape(change: TransitionFile) -> dict[str, object]:
    """The captured target exactly as planned, unresolved, for the runtime to compare."""
    return {
        "path": str(change.path),
        "before": _encode(change.before),
        "after": _encode(change.after),
        "after_mode": change.after_mode,
        "kind": change.kind,
        "no_follow": change.no_follow,
        "expected_digest": change.expected_digest,
    }


@dataclass(frozen=True, slots=True, repr=False)
class PreparedCodexPublicationInverse:
    """Private snapshots and dependencies to review before exact authorization."""

    guard_home: Path
    config_path: Path
    operation_id: str
    interrupted_operation_id: str
    journal_sha256: str
    journal_identity: tuple[int, int, int, int, int]
    changes: tuple[TransitionFile, ...]
    change_identities: tuple[tuple[int, int, int, int, int] | None, ...]
    dependencies: tuple[TransitionFile, ...]
    resumed_inverse_operation_id: str | None = None
    native_runtime: NativeRuntimeIdentity | None = None
    verification_workspace: Path | None = None

    def _checked(self) -> tuple[dict[str, object], str]:
        answer = publication(
            "inverse_plan",
            self.guard_home,
            config=str(self.config_path),
            operation_id=self.operation_id,
            interrupted_operation_id=self.interrupted_operation_id,
            resumed_inverse_operation_id=self.resumed_inverse_operation_id,
            journal_sha256=self.journal_sha256,
            journal_identity=list(self.journal_identity),
            files=[change.payload() for change in self.changes],
            file_identities=[list(identity) if identity is not None else None for identity in self.change_identities],
            dependencies=[change.payload() for change in self.dependencies],
            native_runtime=native_runtime_wire(self.native_runtime),
            verification_workspace=None if self.verification_workspace is None else str(self.verification_workspace),
        )
        payload = answer.get("payload") if isinstance(answer, dict) else None
        subject = answer.get("subject") if isinstance(answer, dict) else None
        if not isinstance(payload, dict) or not isinstance(subject, str):
            raise TransitionError("publication_inverse_plan_invalid")
        return payload, subject

    def payload(self) -> dict[str, object]:
        """Private approval subject material; never a diagnostic summary."""
        return self._checked()[0]

    def subject(self) -> str:
        return self._checked()[1]

    def summary(self) -> dict[str, object]:
        """Expose target/digest changes without config bytes or authentication."""
        return {
            "action": PUBLICATION_INVERSE_ACTION,
            "operation_id": self.operation_id,
            "interrupted_operation_id": self.interrupted_operation_id,
            "resumed_inverse_operation_id": self.resumed_inverse_operation_id,
            "journal_sha256": self.journal_sha256,
            "files": [
                {
                    "path": str(change.path),
                    "before_sha256": None if change.before is None else hashlib.sha256(change.before).hexdigest(),
                    "after_sha256": None if change.after is None else hashlib.sha256(change.after).hexdigest(),
                }
                for change in self.changes
            ],
            "dependency_count": len(self.dependencies),
            "authorized": False,
            "verified": False,
        }

    def compare_before(self) -> None:
        require_codex_install_owner(self.guard_home)
        assert_transition_mutation_allowed(self.guard_home)
        check_hook_validation_deadline()
        with _inverse_budget():
            publication(
                "inverse_verify",
                self.guard_home,
                config=os.path.abspath(self.config_path),
                interrupted_operation_id=self.interrupted_operation_id,
                resumed_inverse_operation_id=self.resumed_inverse_operation_id,
                journal_sha256=self.journal_sha256,
                journal_identity=list(self.journal_identity),
                files=[_change_shape(change) for change in self.changes],
                file_identities=[list(item) if item is not None else None for item in self.change_identities],
                dependencies=[item.payload() for item in self.dependencies],
                native_runtime=native_runtime_wire(self.native_runtime),
                verification_workspace=workspace_wire(self.verification_workspace),
            )
        check_hook_validation_deadline()


def bind_codex_publication_inverse_verification(
    plan: PreparedCodexPublicationInverse,
    *,
    expected_runtime: NativeRuntimeIdentity,
    workspace: Path,
    deadline_monotonic: float,
) -> PreparedCodexPublicationInverse:
    """Pin comparison inputs before approval; never produce native admission."""
    if plan.native_runtime is not None or plan.verification_workspace is not None:
        raise TransitionError("publication_inverse_native_binding_already_prepared")
    with inverse_recovery_budget(deadline_monotonic), hook_validation_deadline(deadline_monotonic):
        plan.compare_before()
        answer = publication(
            "inverse_bind",
            plan.guard_home,
            dependencies=[item.payload() for item in plan.dependencies],
            native_runtime=native_runtime_wire(expected_runtime),
            verification_workspace=str(workspace),
        )
        bound = replace(
            plan,
            dependencies=_transition_files(answer.get("files") if isinstance(answer, dict) else None),
            native_runtime=expected_runtime,
            verification_workspace=workspace,
        )
        bound.compare_before()
    return bound


def _transition_files(value: object) -> tuple[TransitionFile, ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise TransitionError("native_transition_invalid")
    return tuple(transition_file(item) for item in value)


def _identity(value: object) -> tuple[int, int, int, int, int] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) != 5 or not all(type(item) is int for item in value):
        raise TransitionError("native_transition_invalid")
    return (value[0], value[1], value[2], value[3], value[4])


def prepare_authenticated_hook_publication_inverse(spec: CodexHookManifestSpec) -> PreparedCodexPublicationInverse:
    """Capture authenticated predecessor bindings without retiring the journal.

    A foreign config can be reviewed, but a competing authority generation is
    never adopted into this inverse. Completed and unprotected publications
    require their own reviewed recovery policy, not this protected inverse.
    The runtime reads the journal, authenticates it under its own key,
    captures and checks every participant, verifies the predecessor manifest,
    pins its dependencies and checks the plan. This sends the facts of this
    process and keeps the answer.
    """
    from .harness_context import HarnessContext
    from .native_harness_client import wire_context

    home = spec.guard_home.resolve(strict=False)
    require_codex_install_owner(home)
    assert_transition_mutation_allowed(home)
    check_hook_validation_deadline()
    context = HarnessContext(home_dir=spec.home_dir, workspace_dir=spec.workspace_dir, guard_home=spec.guard_home)
    operation_id = str(uuid.uuid4())
    answer = publication(
        "inverse_prepare",
        home,
        config=os.path.abspath(spec.config_path),
        operation_id=operation_id,
        spec=spec.payload(),
        context=wire_context(context),
    )
    prepared: dict[str, object] = answer if isinstance(answer, dict) else {}
    guard_home, config = prepared.get("guard_home"), prepared.get("config")
    interrupted, journal_sha256 = prepared.get("interrupted_operation_id"), prepared.get("journal_sha256")
    resumed, identities = prepared.get("resumed_inverse_operation_id"), prepared.get("change_identities")
    journal_identity = _identity(prepared.get("journal_identity"))
    if (
        not isinstance(guard_home, str)
        or not isinstance(config, str)
        or not isinstance(interrupted, str)
        or not isinstance(journal_sha256, str)
        or not (resumed is None or isinstance(resumed, str))
        or not isinstance(identities, list)
        or journal_identity is None
    ):
        raise TransitionError("native_transition_invalid")
    return PreparedCodexPublicationInverse(
        Path(guard_home),
        Path(config),
        operation_id,
        interrupted,
        journal_sha256,
        journal_identity,
        _transition_files(prepared.get("changes")),
        tuple(_identity(item) for item in identities),
        _transition_files(prepared.get("dependencies")),
        resumed_inverse_operation_id=resumed,
    )

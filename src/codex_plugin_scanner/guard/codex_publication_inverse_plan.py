"""Read-only preparation of an exact inverse for unresolved Codex publication.

A plan conveys no mutation or lifecycle authority. Authentication of the old
journal is necessary but cannot authorize overwriting the current config.
"""

from __future__ import annotations

import hashlib
import math
import os
import uuid
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass, replace
from pathlib import Path

from .codex_hook_compatibility import retained_launch_generations
from .codex_hook_file_integrity import (
    CodexHookIntegrityError,
    active_hook_validation_deadline,
    check_hook_validation_deadline,
    hook_validation_deadline,
    validate_regular_file,
)
from .codex_hook_integrity import (
    authenticate_hook_manifest_text,
    canonical_manifest_bytes,
    hook_secret_path,
)
from .codex_hook_manifest import CodexHookManifestSpec, _verify_hook_manifest
from .codex_hook_recovery import (
    _MAX_RECORD,
    _decode,
    _load_record,
    _record_authentication_targets,
    _record_path,
    _snapshot,
)
from .codex_hook_rollback import rollback_file_identity
from .codex_hook_runtime_trust import verify_captured_launch_generation
from .codex_hook_sources import parse_toml_object
from .codex_install_transaction import require_codex_install_owner
from .native_runtime import NativeRuntimeIdentity
from .private_file_io import read_private_regular_bytes
from .runtime_transition import (
    RuntimeTransition,
    TransitionError,
    TransitionFile,
    assert_transition_mutation_allowed,
    inverse_recovery_budget,
    merge_transition_dependency,
)

PUBLICATION_INVERSE_ACTION = "apps.repair.codex-publication-inverse"


def _journal_bytes(path: Path) -> bytes:
    check_hook_validation_deadline()
    raw = read_private_regular_bytes(path, max_bytes=_MAX_RECORD, require_private_parent=True)
    check_hook_validation_deadline()
    if raw is None:
        raise TransitionError("publication_inverse_journal_missing")
    return raw


def _predecessor_dependencies(home: Path, manifest_bytes: bytes) -> tuple[TransitionFile, ...]:
    # Artifact dependency construction validates eagerly, so the original
    # deadline must cover construction as well as the later comparison.
    deadline = active_hook_validation_deadline()
    with inverse_recovery_budget(deadline) if deadline is not None else nullcontext():
        return _capture_predecessor_dependencies(home, manifest_bytes)


def _capture_predecessor_dependencies(home: Path, manifest_bytes: bytes) -> tuple[TransitionFile, ...]:
    authenticated = authenticate_hook_manifest_text(home, manifest_bytes.decode("utf-8"))
    dependencies = {hook_secret_path(home): TransitionFile.identity_dependency(hook_secret_path(home))}
    try:
        for generation in (authenticated, *retained_launch_generations(authenticated)):
            check_hook_validation_deadline()
            interpreter, packaged = verify_captured_launch_generation(generation)
            items = [TransitionFile.artifact_dependency(identity) for identity in packaged.values()]
            target = interpreter.get("target")
            if not isinstance(target, dict):
                raise TransitionError("publication_inverse_predecessor_identity_invalid")
            items.append(TransitionFile.artifact_dependency(target, invocation=interpreter))
            for item in items:
                previous = dependencies.get(item.path)
                dependencies[item.path] = item if previous is None else merge_transition_dependency(previous, item)
    except ValueError as exc:
        raise CodexHookIntegrityError(
            "codex_publication_inverse_retained_identity_invalid",
            "Guard could not verify a retained Codex launch generation.",
        ) from exc
    return tuple(dependencies.values())


def _reviewable_prior_inverse(home: Path, record: dict[str, object]) -> str | None:
    """Validate prior intent as review data, never as replay authority."""
    if "publication_inverse" not in record:
        return None
    marker = record["publication_inverse"]
    if not isinstance(marker, dict):
        raise TransitionError("publication_inverse_prior_record_invalid")
    prior = marker.get("plan")
    if not isinstance(prior, dict):
        raise TransitionError("publication_inverse_prior_record_invalid")
    operation = prior.get("operation_id")
    try:
        if not isinstance(operation, str) or str(uuid.UUID(operation)) != operation:
            raise ValueError("invalid inverse identity")
    except ValueError as exc:
        raise TransitionError("publication_inverse_prior_record_invalid") from exc
    files, identities = prior.get("files"), marker.get("file_identities")
    restored, phase = marker.get("restored"), marker.get("phase")
    published, owner_pid = marker.get("publication_monotonic"), marker.get("owner_pid")
    manifest, receipt = _record_authentication_targets(home, record)
    targets = (
        (Path(str(record["config_path"])), "before_config"),
        (manifest, "before_manifest"),
        (receipt, "before_receipt"),
    )
    if (
        marker.get("schema") != "hol-guard.codex-explicit-publication-inverse.v1"
        or not isinstance(phase, str)
        or phase not in {"restoring", "restored", "verified"}
        or prior.get("schema") != "hol-guard.codex-publication-inverse-plan.v1"
        or prior.get("action") != PUBLICATION_INVERSE_ACTION
        or prior.get("guard_home") != str(home)
        or prior.get("config_path") != record["config_path"]
        or prior.get("interrupted_operation_id") != record["operation_id"]
        or marker.get("subject")
        != f"codex-publication-inverse:{operation}:" + hashlib.sha256(canonical_manifest_bytes(prior)).hexdigest()
        or type(owner_pid) is not int
        or owner_pid <= 0
        or not isinstance(marker.get("owner_operation_id"), str)
        or not marker["owner_operation_id"]
        or not isinstance(published, (float, int))
        or isinstance(published, bool)
        or not math.isfinite(published)
        or published <= 0
        or not isinstance(files, list)
        or len(files) != 3
        or not isinstance(identities, list)
        or len(identities) != 3
        or not isinstance(restored, list)
        or any(type(index) is not int for index in restored)
        or restored not in ([], [1], [1, 2], [1, 2, 0])
        or (phase in {"restored", "verified"} and restored != [1, 2, 0])
        or (phase == "verified" and not isinstance(marker.get("native_verification"), dict))
    ):
        raise TransitionError("publication_inverse_prior_record_invalid")
    for change, identity, (target, key) in zip(files, identities, targets, strict=True):
        if (
            not isinstance(change, dict)
            or change.get("path") != str(target)
            or change.get("kind") != "binding"
            or change.get("no_follow") is not True
            or type(change.get("after_mode")) is not int
            or change.get("after_mode") != 0o600
            or "expected_digest" in change
            or _decode(change.get("after")) != _decode(record.get(key))
            or (
                identity is not None
                and (
                    not isinstance(identity, list)
                    or len(identity) != 5
                    or any(type(value) is not int for value in identity)
                )
            )
        ):
            raise TransitionError("publication_inverse_prior_record_invalid")
    return operation


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

    def payload(self) -> dict[str, object]:
        """Private approval subject material; never a diagnostic summary."""
        return {
            "schema": "hol-guard.codex-publication-inverse-plan.v1",
            "action": PUBLICATION_INVERSE_ACTION,
            "guard_home": str(self.guard_home),
            "config_path": str(self.config_path),
            "operation_id": self.operation_id,
            "interrupted_operation_id": self.interrupted_operation_id,
            "resumed_inverse_operation_id": self.resumed_inverse_operation_id,
            "journal_sha256": self.journal_sha256,
            "journal_identity": list(self.journal_identity),
            "files": [change.payload() for change in self.changes],
            "file_identities": [
                list(identity) if identity is not None else None for identity in self.change_identities
            ],
            "dependencies": [dependency.payload() for dependency in self.dependencies],
            "native_runtime": None
            if self.native_runtime is None
            else {
                "path": str(self.native_runtime.path),
                "size": self.native_runtime.size,
                "mtime_ns": self.native_runtime.mtime_ns,
                "sha256": self.native_runtime.sha256,
            },
            "verification_workspace": None if self.verification_workspace is None else str(self.verification_workspace),
        }

    def subject(self) -> str:
        digest = hashlib.sha256(canonical_manifest_bytes(self.payload())).hexdigest()
        return f"codex-publication-inverse:{self.operation_id}:{digest}"

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
        journal = _record_path(self.guard_home)
        if (
            rollback_file_identity(journal) != self.journal_identity
            or hashlib.sha256(_journal_bytes(journal)).hexdigest() != self.journal_sha256
            or rollback_file_identity(journal) != self.journal_identity
        ):
            raise TransitionError("publication_inverse_journal_changed")
        record = _load_record(self.guard_home, live_config_conflict=True)
        manifest, receipt = _record_authentication_targets(self.guard_home, record)
        targets = ((self.config_path, "before_config"), (manifest, "before_manifest"), (receipt, "before_receipt"))
        if (
            record["phase"] not in {"prepared", "config_conflict"}
            or "repair_plan" in record
            or _reviewable_prior_inverse(self.guard_home, record) != self.resumed_inverse_operation_id
            or record["config_path"] != os.path.abspath(self.config_path)
            or record["operation_id"] != self.interrupted_operation_id
            or len(self.changes) != 3
            or len(self.change_identities) != 3
            or any(
                change.path != target
                or change.after != _decode(record.get(key))
                or change.after is None
                or not change.no_follow
                or change.after_mode != 0o600
                or change.kind != "binding"
                or change.expected_digest is not None
                for change, (target, key) in zip(self.changes, targets, strict=True)
            )
        ):
            raise TransitionError("publication_inverse_plan_invalid")
        for change, identity in zip(self.changes, self.change_identities, strict=True):
            check_hook_validation_deadline()
            if (
                rollback_file_identity(change.path) != identity
                or _snapshot(change.path) != change.before
                or rollback_file_identity(change.path) != identity
            ):
                raise TransitionError("publication_inverse_generation_changed")
        predecessor = _decode(record.get("before_manifest"))
        assert predecessor is not None
        expected = _predecessor_dependencies(self.guard_home, predecessor)
        if self.native_runtime is not None or self.verification_workspace is not None:
            expected = _with_native_dependency(expected, self.native_runtime, self.verification_workspace)
        if [item.payload() for item in self.dependencies] != [item.payload() for item in expected]:
            raise TransitionError("publication_inverse_dependencies_invalid")
        deadline = active_hook_validation_deadline()
        with inverse_recovery_budget(deadline) if deadline is not None else nullcontext():
            RuntimeTransition._compare({"files": [item.payload() for item in self.dependencies]}, "before")
        check_hook_validation_deadline()


def _with_native_dependency(
    dependencies: tuple[TransitionFile, ...],
    native: NativeRuntimeIdentity | None,
    workspace: Path | None,
) -> tuple[TransitionFile, ...]:
    deadline = active_hook_validation_deadline()
    with inverse_recovery_budget(deadline) if deadline is not None else nullcontext():
        return _capture_native_dependency(dependencies, native, workspace)


def _capture_native_dependency(
    dependencies: tuple[TransitionFile, ...],
    native: NativeRuntimeIdentity | None,
    workspace: Path | None,
) -> tuple[TransitionFile, ...]:
    if (
        native is None
        or workspace is None
        or not workspace.is_absolute()
        or workspace.resolve(strict=False) != workspace
        or not workspace.is_dir()
        or not native.path.is_absolute()
        or native.path.resolve(strict=False) != native.path
        or type(native.size) is not int
        or native.size <= 0
        or type(native.mtime_ns) is not int
        or len(native.sha256) != 64
        or any(char not in "0123456789abcdef" for char in native.sha256)
    ):
        raise TransitionError("publication_inverse_native_binding_invalid")
    metadata = validate_regular_file(native.path, role="artifact", executable_required=True)
    if metadata.st_mtime_ns != native.mtime_ns or metadata.st_size != native.size:
        raise TransitionError("native_runtime_generation_changed")
    item = TransitionFile.artifact_dependency(
        {
            "path": str(native.path),
            "size": native.size,
            "sha256": native.sha256,
            "mode": metadata.st_mode & 0o777,
            "owner_uid": metadata.st_uid,
            "role": "artifact",
        }
    )
    merged = {value.path: value for value in dependencies}
    previous = merged.get(item.path)
    merged[item.path] = item if previous is None else merge_transition_dependency(previous, item)
    return tuple(merged.values())


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
        dependencies = _with_native_dependency(plan.dependencies, expected_runtime, workspace)
        bound = replace(
            plan, dependencies=dependencies, native_runtime=expected_runtime, verification_workspace=workspace
        )
        bound.compare_before()
    return bound


def prepare_authenticated_hook_publication_inverse(spec: CodexHookManifestSpec) -> PreparedCodexPublicationInverse:
    """Capture authenticated predecessor bindings without retiring the journal.

    A foreign config can be reviewed, but a competing authority generation is
    never adopted into this inverse. Completed and unprotected publications
    require their own reviewed recovery policy, not this protected inverse.
    """
    home = spec.guard_home.resolve(strict=False)
    require_codex_install_owner(home)
    assert_transition_mutation_allowed(home)
    check_hook_validation_deadline()
    journal = _record_path(home)
    journal_identity = rollback_file_identity(journal)
    if journal_identity is None:
        raise TransitionError("publication_inverse_journal_missing")
    raw = _journal_bytes(journal)
    record = _load_record(home, live_config_conflict=True)
    if record["phase"] not in {"prepared", "config_conflict"} or "repair_plan" in record:
        raise TransitionError("publication_inverse_phase_invalid")
    resumed_operation = _reviewable_prior_inverse(home, record)
    config = spec.config_path.parent.resolve(strict=False) / spec.config_path.name
    if record["config_path"] != os.path.abspath(config):
        raise TransitionError("publication_inverse_target_mismatch")
    manifest, receipt = _record_authentication_targets(home, record)
    before_config, before_manifest = _decode(record.get("before_config")), _decode(record.get("before_manifest"))
    before_receipt = _decode(record.get("before_receipt"))
    if before_config is None or before_manifest is None or before_receipt is None:
        raise TransitionError("publication_inverse_predecessor_authority_missing")
    changes, identities = [], []
    for target, previous, before_key, after_key in (
        (config, before_config, "before_config", "after_config"),
        (manifest, before_manifest, "before_manifest", "after_manifest"),
        (receipt, before_receipt, "before_receipt", "after_receipt"),
    ):
        identity = rollback_file_identity(target)
        current = _snapshot(target)
        if rollback_file_identity(target) != identity:
            raise TransitionError("publication_inverse_generation_changed")
        if target != config and current not in (_decode(record.get(before_key)), _decode(record.get(after_key))):
            raise TransitionError("publication_inverse_authority_generation_changed")
        mode = 0o600 if identity is None else target.stat().st_mode & 0o777
        changes.append(TransitionFile(target, current, previous, before_mode=mode, no_follow=True))
        identities.append(identity)
    parsed = parse_toml_object(before_config, path=config, label="previous Codex config")
    features = parsed.get("features")
    if isinstance(features, Mapping) and features.get("hooks") is False:
        raise TransitionError("publication_inverse_predecessor_hooks_disabled")
    state = _verify_hook_manifest(spec, hooks=parsed.get("hooks"), captured_text=before_manifest.decode("utf-8"))
    if state.get("integrity_status") != "valid":
        raise CodexHookIntegrityError(str(state["integrity_reason"]), str(state["integrity_message"]))
    dependencies = _predecessor_dependencies(home, before_manifest)
    if _journal_bytes(journal) != raw or rollback_file_identity(journal) != journal_identity:
        raise TransitionError("publication_inverse_journal_changed")
    prepared = PreparedCodexPublicationInverse(
        home,
        config,
        str(uuid.uuid4()),
        str(record["operation_id"]),
        hashlib.sha256(raw).hexdigest(),
        journal_identity,
        tuple(changes),
        tuple(identities),
        dependencies,
        resumed_inverse_operation_id=resumed_operation,
    )
    prepared.compare_before()
    return prepared

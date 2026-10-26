"""Bounded daemon API service for extension-control inspection and mutation."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    consume_extension_control_grant,
    input_from_mapping,
    require_extension_control,
)
from ..catalog_delivery import lifecycle
from ..json_transport import escape_json_for_html
from ..native_command_control_authority_io import NativeCommandControlAuthorityUnavailableError
from ..native_extension_control import (
    PREVIEW_LIMIT_CODES,
    NativeExtensionControlError,
    compose_control_layers,
    mutability_validate,
    mutation_bounds,
    request_digest,
    request_json,
    validate_mutation,
)
from ..runtime import command_inspection
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
    layers_from_json,
)
from ..runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ExtensionControlLayer,
)
from ..runtime.extension_control_limits import (
    MAX_DAEMON_CATALOG_RESPONSE_BYTES,
    advertised_extension_control_limits,
)
from ..runtime.extension_control_proof import (
    ExtensionControlMutation,
    ExtensionControlProof,
    ExtensionControlProofError,
    issue_extension_control_proof,
)
from ..runtime.extension_control_runtime import (
    ExtensionControlRuntime,
    ExtensionControlRuntimeSnapshot,
    ExtensionControlSnapshotUnavailableError,
)
from .extension_control_errors import ExtensionControlApiError
from .extension_control_preparation_failure import preparation_unavailable
from .extension_control_prepared import (
    MAX_CANDIDATES,
    PreparedControlCandidate,
    PreparedControlCandidates,
    expire_leases,
    expired,
    prepare_candidate,
    release_all_leases,
)
from .extension_control_request import request_needs_proof, required_request_string
from .extension_control_semantic_preview import (
    build_extension_control_event_targets,
    build_extension_control_semantic_preview,
)
from .managed_controls_api import effective_controls_payload

if TYPE_CHECKING:
    from ..store import GuardStore
    from .extension_control_targets import TargetMetadata

_LOGGER = logging.getLogger(__name__)
EFFECTIVE_LOCK_WAIT_SECONDS = 0.5
_EXTENSION_CONTROL_API_SCHEMA = "guard.daemon.extension-controls.v1"
_MAX_PENDING_PROOFS = 128
_MAX_APPLIED_MUTATIONS = 128
_MAX_INSPECTION_COMMAND_CHARS = 4096
# Why the resident names no digest for an apply request itself: no preview was
# ever issued for a request that could not be encoded or sent whole.
_UNDIGESTABLE_REQUEST_CODES = frozenset(
    {"native_extension_control_too_large", "native_extension_control_invalid_digest_input"}
)
# The resident names why it refuses a draft; this maps each reason to the HTTP
# status the API has always answered it with.
_MUTATION_REFUSAL_STATUS = {
    "layer_limit_exceeded": 400,
    "layer_control_limit_exceeded": 400,
    "control_limit_exceeded": 400,
    "unknown_extension": 400,
    "unknown_permission": 400,
    "duplicate_control_target": 400,
    "invalid_mutation": 400,
    "managed_layer_mutation": 403,
    "immutable_extension": 403,
    "immutable_permission": 403,
    "catalog_conflict": 409,
}


def _refusal(code: str) -> ExtensionControlApiError:
    return ExtensionControlApiError(_MUTATION_REFUSAL_STATUS[code], code)


@dataclass(frozen=True, slots=True)
class _PendingMutation:
    mutation: ExtensionControlMutation
    proof: ExtensionControlProof
    request_digest: str = ""
    candidate: PreparedControlCandidate | None = None


@dataclass(frozen=True, slots=True)
class _AppliedMutation:
    request_json: str
    response: dict[str, object]


class ExtensionControlApiService:
    """Own private pending proofs and expose deterministic public DTOs."""

    def __init__(
        self,
        *,
        store: GuardStore,
        registry: CommandSafetyExtensionRegistry,
        runtime: ExtensionControlRuntime,
    ) -> None:
        self._store = store
        self._registry = registry
        self.catalog_digest = registry.catalog_digest
        self._runtime = runtime
        self._proof_lock = threading.Lock()
        self._apply_lock = threading.Lock()
        self._preview_lock = threading.Lock()
        self._candidates = PreparedControlCandidates()
        self._pending_proofs: OrderedDict[str, _PendingMutation] = OrderedDict()
        self._applied_mutations: OrderedDict[str, _AppliedMutation] = OrderedDict()

    def rebind_registry(
        self,
        registry: CommandSafetyExtensionRegistry,
        *,
        installed: ExtensionControlRuntimeSnapshot,
    ) -> bool:
        """Serve the registry whose view the runtime installed as `installed`.

        Proofs prepared against the previous registry name its catalog digest,
        and a preview in flight sees the registry change, so both fail as
        conflicts. A refresh rebinds after releasing the authority lease, so
        an apply can commit a newer activation in between. That apply binds
        its own registry and installs a newer snapshot, which this refuses to
        roll back.
        """

        with self._apply_lock:
            if self._runtime.current() is not installed:
                return False
            self._registry = registry
            self.catalog_digest = registry.catalog_digest
            return True

    def recommendation_inputs(self) -> tuple[CommandSafetyExtensionRegistry, ExtensionControlRuntimeSnapshot]:
        return self._registry, self._runtime.current()

    def catalog(self) -> dict[str, object]:
        limits = advertised_extension_control_limits()
        payload: dict[str, object] = {
            "schema_version": _EXTENSION_CONTROL_API_SCHEMA,
            "control_schema_version": CONTROL_SCHEMA_VERSION,
            "catalog_digest": self._registry.catalog_digest,
            "extensions": [extension.to_dict() for extension in self._registry.extensions],
            "limits": {
                **limits,
                "max_body_bytes": MAX_DAEMON_CATALOG_RESPONSE_BYTES,
                "max_controls": limits["max_controls_total"],
            },
        }
        # Measure the exact bytes the daemon writes, including its HTML-safe escaping.
        wire_body = escape_json_for_html(json.dumps(payload).encode("utf-8"))
        if len(wire_body) > MAX_DAEMON_CATALOG_RESPONSE_BYTES:
            raise ExtensionControlApiError(413, "catalog_payload_limit_exceeded")
        return payload

    def effective(self, *, reread: bool = True) -> dict[str, object]:
        # Reading the controls must stay a read. Committing a catalog migration
        # here would move the stored revision under every draft the dashboard
        # has open, which is the conflict this endpoint is polled to report.
        #
        # `reread=False` is for a caller that has just refreshed the runtime
        # itself. Re-reading durable authority there would take the authority
        # lease a second time for an answer the caller already installed, and
        # that second wait is the one a dashboard repair pays for.
        #
        # The dashboard polls this while the page is open, so it waits for a
        # busy authority lease only briefly and otherwise serves the snapshot
        # the runtime holds; the next poll reads the authority again.
        snapshot = (
            self._runtime.current()
            if not reread
            else self._live_snapshot(read_only=True, lock_timeout_seconds=EFFECTIVE_LOCK_WAIT_SECONDS)
        )
        return self._effective_payload(snapshot)

    def _effective_payload(self, snapshot: ExtensionControlRuntimeSnapshot) -> dict[str, object]:
        # The native runtime resolves the controls; without an answer there is no payload to serve.
        try:
            return effective_controls_payload(self._registry, snapshot, self._store)
        except NativeExtensionControlError as error:
            raise ExtensionControlApiError(503, "native_runtime_unavailable") from error

    def _live_snapshot(
        self,
        *,
        read_only: bool = False,
        apply_locked: bool = False,
        lock_timeout_seconds: float | None = None,
    ) -> ExtensionControlRuntimeSnapshot:
        """The snapshot a draft is built on, re-read from durable authority.

        The in-process snapshot only advances when this daemon commits, so a
        catalog migration or another writer moves the stored revision underneath
        it. A draft built on the stale revision can never be applied, because
        the commit checks its expected revision against the store rather than
        against this process. Re-reading keeps the revision the dashboard draws
        a draft from the one that commit will check.

        Only an authority that is protected and has moved forward replaces the
        snapshot. A read that comes back unenrolled, degraded, or behind this
        process must not take protection away from a running daemon; refreshing
        is here to catch up with another writer, not to downgrade. A protected
        read does replace a snapshot that is not protected, at any revision:
        that is the authority healing, not falling behind.

        A protected read for a catalog the snapshot was not built for also
        replaces it, whatever its revision says. The view was read for the
        registry this service serves, so keeping a snapshot from another
        catalog would publish controls under a catalog digest the catalog
        endpoint no longer names, and a reader comparing the two cannot settle
        that by reading again.

        `read_only` keeps the read on the shared lock and off the write path, so
        a caller that only renders the controls cannot settle a pending catalog
        migration on the operator's behalf.

        `apply_locked` is for a caller that already holds the apply lock. That
        lock is not reentrant, so taking it again here would deadlock the
        apply that asked for the snapshot.

        `lock_timeout_seconds` bounds the wait for the authority lease; a read
        that times out serves the snapshot the runtime already holds.
        """

        registry = self._registry
        current = self._runtime.current()
        try:
            view = self._store.read_extension_control_authority_for_registry(
                registry, read_only=read_only, lock_timeout_seconds=lock_timeout_seconds
            )
            if view.health is not AuthorityHealth.PROTECTED:
                return current
            if (
                current.health is AuthorityHealth.PROTECTED
                and view.catalog_digest == current.catalog_digest
                and (view.revision, view.managed_revision) <= (current.revision, current.managed_revision)
            ):
                return current
            if apply_locked:
                return self._runtime.refresh(view)
            with self._apply_lock:
                # The read above runs without the apply lock, so an apply or a
                # daemon refresh can install a newer snapshot, or rebind this
                # service to another registry, while it is in flight. Installing
                # this view anyway would roll the runtime back under the work
                # that just landed, and `rebind_registry` would then refuse the
                # rebind because the snapshot it installed is no longer current.
                # A reader that lost the race serves what the writer installed.
                if self._registry is not registry or self._runtime.current() is not current:
                    return self._runtime.current()
                return self._runtime.refresh(view)
        except (ExtensionControlAuthorityError, ValueError, OSError):
            # Authority that cannot be re-read or installed keeps serving the
            # snapshot the runtime already holds; mutations still fail closed.
            return current

    def refresh(self) -> dict[str, object]:
        try:
            view = self._store.read_extension_control_authority_for_registry(self._registry)
        except NativeCommandControlAuthorityUnavailableError:
            # A busy lease means this refresh read nothing, not that the route
            # failed. Serve the snapshot the runtime already holds rather than
            # retrying the read through effective(), which would wait again.
            return self._effective_payload(self._runtime.current())
        try:
            _ = self._runtime.refresh(view)
        except ExtensionControlSnapshotUnavailableError:
            # The native runtime gave no digest, so nothing new was installed;
            # serve the snapshot the runtime holds, as for a busy lease.
            return self._effective_payload(self._runtime.current())
        return self.effective()

    def test_command(self, payload: dict[str, object]) -> dict[str, object]:
        from .extension_control_test_api import evaluate_extension_control_test

        return evaluate_extension_control_test(
            registry=self._registry,
            runtime=self._runtime,
            payload=payload,
        )

    def inspect_command(self, payload: dict[str, object]) -> dict[str, object]:
        raw_command = payload.get("command")
        command = raw_command.strip() if isinstance(raw_command, str) else ""
        if not command or len(command) > _MAX_INSPECTION_COMMAND_CHARS or "\x00" in command:
            raise ExtensionControlApiError(400, "invalid_inspection_command")
        paths: dict[str, Path] = {}
        for field in ("cwd", "home_dir"):
            raw_path = payload.get(field)
            if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
                raise ExtensionControlApiError(400, f"invalid_{field}")
            path = Path(raw_path)
            if not path.is_absolute():
                raise ExtensionControlApiError(400, f"invalid_{field}")
            paths[field] = path
        try:
            return command_inspection.inspect_command(
                command,
                cwd=paths["cwd"],
                home_dir=paths["home_dir"],
                guard_home=self._store.guard_home,
                extension_control_snapshot=self._runtime.current(),
            )
        except ValueError as exc:
            raise ExtensionControlApiError(400, "invalid_inspection_command") from exc

    def history(self) -> dict[str, object]:
        current = self._runtime.current()
        try:
            items = self._store.list_extension_control_authority_history(
                catalog_digest=self._registry.catalog_digest,
                limit=20,
            )
        except ExtensionControlAuthorityError as exc:
            raise ExtensionControlApiError(409, "authority_history_unavailable") from exc
        return {
            "schema_version": "guard.daemon.extension-control-history.v1",
            "revision": current.revision,
            "catalog_digest": current.catalog_digest,
            "items": items,
        }

    def _require_action_grant(
        self,
        payload: dict[str, object],
        *,
        action: str,
        subject: str,
        require_fresh_totp: bool = False,
    ) -> None:
        session_nonce = required_request_string(payload, "session_nonce")
        gate_input = input_from_mapping(payload)
        if require_fresh_totp:
            gate_input = replace(gate_input or ApprovalGateInput(), require_fresh_totp=True)
        try:
            grant = require_extension_control(
                self._store.guard_home,
                approval_gate_input=gate_input,
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
            consume_extension_control_grant(
                self._store.guard_home,
                grant,
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
        except ApprovalGateError as exc:
            raise ExtensionControlApiError(exc.status, exc.code) from exc

    def recover_authority(self, payload: dict[str, object], *, require_fresh_totp: bool = False) -> dict[str, object]:
        current = self._store.read_extension_control_authority_for_registry(self._registry)
        if current.health not in {AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED}:
            runtime = self._runtime.current()
            if current.health is AuthorityHealth.PROTECTED and runtime.health is not AuthorityHealth.PROTECTED:
                try:
                    if runtime.health in {AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED}:
                        _ = self._runtime.replace_after_recovery(current)
                    else:
                        _ = self._runtime.refresh(current)
                except ValueError as exc:
                    raise ExtensionControlApiError(503, "authority_recovery_failed") from exc
                except ExtensionControlSnapshotUnavailableError as exc:
                    raise ExtensionControlApiError(503, "native_runtime_unavailable") from exc
                return self.effective()
            raise ExtensionControlApiError(409, "authority_not_recoverable")
        self._install_view(current)
        action = "recover-authority"
        subject = f"{action}:{current.health.value}:{current.revision}:{self._registry.catalog_digest}"
        self._require_action_grant(
            payload,
            action=action,
            subject=subject,
            require_fresh_totp=require_fresh_totp,
        )
        try:
            view = self._store.recover_extension_control_authority(
                catalog_digest=self._registry.catalog_digest,
                migration_registry=self._registry,
            )
        except ExtensionControlAuthorityError as exc:
            raise ExtensionControlApiError(503, "authority_recovery_failed") from exc
        if view.health is not AuthorityHealth.PROTECTED:
            raise ExtensionControlApiError(503, "authority_recovery_incomplete")
        try:
            _ = self._runtime.replace_after_recovery(view)
        except ValueError as exc:
            raise ExtensionControlApiError(503, "authority_recovery_failed") from exc
        except ExtensionControlSnapshotUnavailableError as exc:
            # The recovery is durable; the daemon's refresh installs it once
            # the native runtime answers again.
            raise ExtensionControlApiError(503, "native_runtime_unavailable") from exc
        return self.effective()

    def _install_view(self, view: ExtensionControlAuthorityView) -> None:
        try:
            _ = self._runtime.refresh(view)
        except ExtensionControlSnapshotUnavailableError as exc:
            # A change already committed stays durable; the daemon's refresh
            # installs it once the native runtime answers again.
            raise ExtensionControlApiError(503, "native_runtime_unavailable") from exc

    def acknowledge_degraded(self, payload: dict[str, object]) -> dict[str, object]:
        current_snapshot = self._runtime.current()
        if current_snapshot.unread:
            # The daemon started without reading the authority, so degraded mode
            # here is the absence of a reading. Acknowledging it would persist an
            # outage nobody observed and invalidate the native policy with it.
            raise ExtensionControlApiError(503, "authority_unread")
        if current_snapshot.health is not AuthorityHealth.DEGRADED_UNACKNOWLEDGED:
            raise ExtensionControlApiError(409, "authority_not_degraded")
        current = self._store.read_extension_control_authority_for_registry(self._registry)
        action = "acknowledge-degraded"
        subject = f"{action}:{current.health.value}:{current.revision}:{self._registry.catalog_digest}"
        self._require_action_grant(payload, action=action, subject=subject)
        view = self._store.acknowledge_extension_control_degraded_mode()
        self._install_view(view)
        return self.effective()

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        with self._preview_lock, lifecycle.session():
            try:
                return self._preview_locked(payload)
            except NativeExtensionControlError as error:
                if error.code in PREVIEW_LIMIT_CODES:
                    raise ExtensionControlApiError(400, "control_limit_exceeded") from error
                if error.code == "native_extension_control_invalid_digest_input":
                    raise ExtensionControlApiError(400, "invalid_mutation") from error
                raise ExtensionControlApiError(503, "native_runtime_unavailable") from error

    def _preview_locked(self, payload: dict[str, object]) -> dict[str, object]:
        from .extension_control_targets import request_metadata

        request_registry = self._registry
        raw_layers = payload.get("layers")
        if not isinstance(raw_layers, list):
            raise ExtensionControlApiError(400, "invalid_layers")
        try:
            raw = layers_from_json(json.dumps(raw_layers, separators=(",", ":")))
        except (TypeError, ValueError, ExtensionControlAuthorityError) as exc:
            raise ExtensionControlApiError(400, "invalid_mutation") from exc
        # Bound the draft before metadata preparation can perform transfer IO.
        if (refusal := mutation_bounds(raw, guard_home=self._store.guard_home)) is not None:
            raise _refusal(refusal)
        # Resolve authority before metadata preparation can perform transfer IO.
        current = self._live_snapshot(read_only=True)
        if current.health is not AuthorityHealth.PROTECTED:
            # A shared read cannot roll back a transition an earlier failed
            # save left prepared, so read once more as the writer before
            # refusing this one.
            current = self._live_snapshot()
        if current.health is not AuthorityHealth.PROTECTED:
            raise ExtensionControlApiError(423, "authority_unavailable")
        try:
            targets = request_metadata(self._store, request_registry, raw)
        except (ValueError, OSError) as exc:
            raise preparation_unavailable(exc, stage="target-metadata") from exc
        mutation = self._mutation_from_payload(payload, targets=targets)
        proposed_layers = self._effective_layers_for_local_mutation(mutation.layers)
        if mutation.previous_revision != current.revision:
            raise ExtensionControlApiError(409, "revision_conflict")
        candidate = self._candidates.get_or_prepare(
            f"{mutation.canonical_digest}:{current.managed_revision}",
            lambda: prepare_candidate(
                self._store, targets, mutation, proposed_layers, managed_revision=current.managed_revision
            ),
        )
        if self._registry is not request_registry or self._live_snapshot(read_only=True) != current:
            raise ExtensionControlApiError(409, "revision_conflict")
        registry = self._registry if candidate is None else candidate.registry
        if candidate is not None:
            refusal = mutability_validate(
                registry,
                self._runtime.current().layers,
                proposed_layers,
                guard_home=self._store.guard_home,
            )
            if refusal is not None:
                raise _refusal(refusal)
            mutation = candidate.mutation
            proposed_layers = tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in proposed_layers)
        composed = compose_control_layers(proposed_layers, guard_home=self._store.guard_home)
        if composed.failures:
            raise ExtensionControlApiError(400, composed.failures[0].code.value.replace("_", "-"))
        response: dict[str, object] = {
            "schema_version": _EXTENSION_CONTROL_API_SCHEMA,
            "previous_revision": mutation.previous_revision,
            "next_revision": mutation.previous_revision + 1,
            "catalog_digest": mutation.catalog_digest,
            "canonical_diff_digest": mutation.canonical_digest,
            "global_lockdown": composed.global_lockdown,
            "controls": len(composed.controls),
            "semantic_preview": build_extension_control_semantic_preview(
                registry,
                tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in current.layers),
                proposed_layers,
                guard_home=self._store.guard_home,
            ),
        }
        if request_needs_proof(payload):
            session_nonce = required_request_string(payload, "session_nonce")
            # Ask the resident before the approval is spent, so an unreachable
            # runtime refuses the preview instead of issuing a proof nobody can
            # apply.
            digest = request_digest(payload, guard_home=self._store.guard_home)
            try:
                proof = issue_extension_control_proof(
                    self._store.guard_home,
                    mutation,
                    approval_gate_input=input_from_mapping(payload),
                    session_nonce=session_nonce,
                )
            except (ApprovalGateError, ExtensionControlProofError) as exc:
                raise ExtensionControlApiError(423, "approval_required") from exc
            self._remember_proof(mutation, proof, request_digest=digest, candidate=candidate)
            response["proof_id"] = proof.proof_id
        return response

    def expire_prepared_cache_leases(self):
        expire_leases(self)

    def release_prepared_cache_leases(self):
        return release_all_leases(self)

    def apply(self, payload: dict[str, object]) -> dict[str, object]:
        with self._apply_lock:
            try:
                # One verified native executable serves every request of this mutation.
                with lifecycle.session():
                    return self._apply_locked(payload)
            except ExtensionControlApiError:
                raise
            except Exception as exc:
                # Report a stable error instead of dropping the connection.
                _LOGGER.error("Extension-control apply failed: %s", type(exc).__name__, exc_info=exc)
                raise ExtensionControlApiError(503, "authority_apply_failed") from exc

    def _apply_locked(self, payload: dict[str, object]) -> dict[str, object]:
        proof_id = required_request_string(payload, "proof_id")
        pending = self._proof_state(proof_id)
        try:
            original_request = request_json(payload)
        except NativeExtensionControlError as error:
            raise ExtensionControlApiError(409, "proof_mismatch") from error
        if isinstance(pending, _AppliedMutation):
            if pending.request_json != original_request:
                raise ExtensionControlApiError(409, "proof_mismatch")
            return dict(pending.response)
        original_digest = self._apply_request_digest(payload)
        if pending.request_digest != original_digest:
            raise ExtensionControlApiError(409, "proof_mismatch")
        mutation = pending.mutation
        candidate = pending.candidate
        if candidate is not None and expired((candidate,)):
            raise ExtensionControlApiError(409, "prepared_preview_expired")
        registry = self._registry if candidate is None else candidate.registry
        current = self._live_snapshot(read_only=True, apply_locked=True)
        if candidate is not None and (
            current.managed_revision != candidate.managed_revision
            or tuple(layer for layer in current.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
            != candidate.managed_layers
        ):
            raise ExtensionControlApiError(409, "managed_layer_conflict")
        proposed_layers = self._effective_layers_for_local_mutation(mutation.layers)
        proposed_layers = tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in proposed_layers)
        # The resident projects the audit event before anything is committed, so
        # a runtime that cannot answer stops the apply instead of leaving a
        # committed change without its event.
        semantic_targets = build_extension_control_event_targets(
            registry,
            tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in current.layers),
            proposed_layers,
            guard_home=self._store.guard_home,
        )
        try:
            _ = self._store.commit_extension_control_layers(
                mutation.layers,
                catalog_digest=mutation.catalog_digest,
                actor_id=mutation.actor_id,
                expected_revision=mutation.previous_revision,
                idempotency_key=mutation.idempotency_key,
                nonce=mutation.nonce,
                proof=pending.proof,
                migration_registry=registry,
                pack_activation=None if candidate is None else candidate.draft,
                expected_managed_revision=None if candidate is None else candidate.managed_revision,
                expected_managed_layers=None if candidate is None else candidate.managed_layers,
                managed_registry=None if candidate is None else self._registry,
            )
        except ExtensionControlProofError as exc:
            raise ExtensionControlApiError(409, "proof_invalid") from exc
        except (ExtensionControlAuthorityError, ValueError) as exc:
            # Name the refusal without a traceback: the daemon log must not
            # carry paths from the store.
            _LOGGER.warning("Extension-control apply refused: %s", type(exc).__name__, exc_info=False)
            raise ExtensionControlApiError(409, "authority_conflict") from exc
        self._registry = registry
        self.catalog_digest = registry.catalog_digest
        composed_view = self._store.read_extension_control_authority_for_registry(registry)
        revision, catalog_digest = composed_view.revision, composed_view.catalog_digest
        # The mutation is committed. If the native runtime gives no digest, the
        # daemon's refresh installs it once it answers again; the audit event
        # and the replay record below still belong to the committed change.
        with suppress(ExtensionControlSnapshotUnavailableError):
            _ = self._runtime.refresh(composed_view)
        self._store.add_event(
            "extension_control_authority_changed",
            {
                "revision": revision,
                "previous_revision": mutation.previous_revision,
                "catalog_digest": catalog_digest,
                "actor_ref": hashlib.sha256(f"actor-ref\u0000{mutation.actor_id}".encode()).hexdigest(),
                "mutation_ref": mutation.canonical_digest,
                "semantic_targets": semantic_targets,
            },
            datetime.now(timezone.utc).isoformat(),
        )
        response: dict[str, object] = {
            "schema_version": _EXTENSION_CONTROL_API_SCHEMA,
            "status": "applied",
            "revision": revision,
            "catalog_digest": catalog_digest,
        }
        with self._proof_lock:
            _ = self._pending_proofs.pop(proof_id, None)
            self._applied_mutations[proof_id] = _AppliedMutation(original_request, response)
            self._applied_mutations.move_to_end(proof_id)
            while len(self._applied_mutations) > _MAX_APPLIED_MUTATIONS:
                _ = self._applied_mutations.popitem(last=False)
        return dict(response)

    def _apply_request_digest(self, payload: dict[str, object]) -> str:
        try:
            return request_digest(payload, guard_home=self._store.guard_home)
        except NativeExtensionControlError as error:
            # A request the resident cannot digest names no preview's request.
            if error.code in _UNDIGESTABLE_REQUEST_CODES:
                raise ExtensionControlApiError(409, "proof_mismatch") from error
            raise

    def _mutation_from_payload(
        self, payload: dict[str, object], *, targets: TargetMetadata | None = None
    ) -> ExtensionControlMutation:
        previous_revision = payload.get("previous_revision")
        raw_layers = payload.get("layers")
        if isinstance(previous_revision, bool) or not isinstance(previous_revision, int):
            raise ExtensionControlApiError(400, "invalid_previous_revision")
        if not isinstance(raw_layers, list):
            raise ExtensionControlApiError(400, "invalid_layers")
        # The resident judges the draft against the catalog served now: the
        # request-local metadata overlay is consulted only after that catalog.
        registry = self._registry if targets is None else targets.active
        overlay = () if targets is None else tuple(targets.extensions.values())
        try:
            catalog_digest = required_request_string(payload, "catalog_digest")
            actor_id = required_request_string(payload, "actor_id")
            idempotency_key = required_request_string(payload, "idempotency_key")
            nonce = required_request_string(payload, "nonce")
            layers = layers_from_json(json.dumps(raw_layers, separators=(",", ":")))
            verdict = validate_mutation(
                registry,
                overlay,
                catalog_digest=self._registry.catalog_digest,
                requested_catalog_digest=catalog_digest,
                current_layers=self._runtime.current().layers,
                layers=layers,
                guard_home=self._store.guard_home,
            )
            if verdict.refusal is not None:
                raise _refusal(verdict.refusal)
            mutation = ExtensionControlMutation(
                previous_revision=previous_revision,
                catalog_digest=catalog_digest,
                layers=verdict.layers,
                actor_id=actor_id,
                idempotency_key=idempotency_key,
                nonce=nonce,
            )
        except ExtensionControlApiError:
            raise
        except NativeExtensionControlError as exc:
            if exc.code in PREVIEW_LIMIT_CODES:
                raise ExtensionControlApiError(400, "control_limit_exceeded") from exc
            # The resident judges the mutation and computes its digest; without
            # it there is no mutation to preview or apply.
            raise ExtensionControlApiError(503, "native_runtime_unavailable") from exc
        except (
            TypeError,
            ValueError,
            ExtensionControlProofError,
            ExtensionControlAuthorityError,
        ) as exc:
            raise ExtensionControlApiError(400, "invalid_mutation") from exc
        local_layers = tuple(layer for layer in mutation.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
        raw_authority = self._store.read_extension_control_authority_for_registry(
            self._registry,
            include_managed_controls=False,
            read_only=True,
        )
        persisted_signed_layers = tuple(
            layer for layer in raw_authority.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD
        )
        return replace(mutation, layers=(*local_layers, *persisted_signed_layers))

    def _effective_layers_for_local_mutation(
        self,
        persisted_layers: tuple[ExtensionControlLayer, ...],
    ) -> tuple[ExtensionControlLayer, ...]:
        local_layers = tuple(layer for layer in persisted_layers if layer.kind is ControlLayerKind.LOCAL_ADMIN)
        managed_layers = tuple(
            layer for layer in self._runtime.current().layers if layer.kind is ControlLayerKind.SIGNED_CLOUD
        )
        return (*local_layers, *managed_layers)

    def _remember_proof(
        self, mutation: ExtensionControlMutation, proof: ExtensionControlProof, *, request_digest="", candidate=None
    ) -> None:
        with self._proof_lock:
            self._pending_proofs[proof.proof_id] = _PendingMutation(mutation, proof, request_digest, candidate)
            self._pending_proofs.move_to_end(proof.proof_id)
            while len(self._pending_proofs) > _MAX_PENDING_PROOFS:
                _ = self._pending_proofs.popitem(last=False)
            while sum(item.candidate is not None for item in self._pending_proofs.values()) > MAX_CANDIDATES:
                oldest = next(key for key, item in self._pending_proofs.items() if item.candidate is not None)
                del self._pending_proofs[oldest]

    def _proof_state(self, proof_id: str) -> _PendingMutation | _AppliedMutation:
        with self._proof_lock:
            applied = self._applied_mutations.get(proof_id)
            if applied is not None:
                self._applied_mutations.move_to_end(proof_id)
                return applied
            pending = self._pending_proofs.get(proof_id)
        if pending is None:
            raise ExtensionControlApiError(409, "proof_not_found")
        return pending

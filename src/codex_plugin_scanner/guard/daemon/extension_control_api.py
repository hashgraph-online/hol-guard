"""Bounded daemon API service for extension-control inspection and mutation."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
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
from ..runtime import command_inspection
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    layers_from_json,
)
from ..runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from ..runtime.extension_control_limits import (
    MAX_CONTROL_LAYERS,
    MAX_CONTROLS_PER_LAYER,
    MAX_CONTROLS_TOTAL,
    MAX_DAEMON_CATALOG_RESPONSE_BYTES,
    advertised_extension_control_limits,
)
from ..runtime.extension_control_proof import (
    ExtensionControlMutation,
    ExtensionControlProof,
    ExtensionControlProofError,
    issue_extension_control_proof,
)
from ..runtime.extension_control_resolver import compose_control_layers
from ..runtime.extension_control_runtime import ExtensionControlRuntime, ExtensionControlRuntimeSnapshot
from .extension_control_errors import ExtensionControlApiError
from .extension_control_prepared import (
    MAX_CANDIDATES,
    PreparedControlCandidate,
    PreparedControlCandidates,
    expire_leases,
    expired,
    prepare_candidate,
    release_all_leases,
    request_digest,
)
from .extension_control_request import request_needs_proof, required_request_string
from .extension_control_semantic_preview import build_extension_control_semantic_preview
from .managed_controls_api import effective_controls_payload

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
_EXTENSION_CONTROL_API_SCHEMA = "guard.daemon.extension-controls.v1"
_MAX_PENDING_PROOFS = 128
_MAX_APPLIED_MUTATIONS = 128
_MAX_EVENT_TARGETS = 512
_MAX_EVENT_RULE_IDS = 1024
_MAX_INSPECTION_COMMAND_CHARS = 4096


@dataclass(frozen=True, slots=True)
class _PendingMutation:
    mutation: ExtensionControlMutation
    proof: ExtensionControlProof
    request_digest: str = ""
    candidate: PreparedControlCandidate | None = None


@dataclass(frozen=True, slots=True)
class _AppliedMutation:
    canonical_digest: str
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

    def rebind_registry(self, registry: CommandSafetyExtensionRegistry) -> None:
        """Serve a registry the daemon recovered after starting on another.

        Proofs prepared against the previous registry name its catalog digest,
        and a preview in flight sees the registry change, so both fail as
        conflicts.
        """

        with self._apply_lock:
            self._registry = registry
            self.catalog_digest = registry.catalog_digest

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

    def effective(self) -> dict[str, object]:
        # Reading the controls must stay a read. Committing a catalog migration
        # here would move the stored revision under every draft the dashboard
        # has open, which is the conflict this endpoint is polled to report.
        return effective_controls_payload(self._registry, self._live_snapshot(read_only=True), self._store)

    def _live_snapshot(self, *, read_only: bool = False) -> ExtensionControlRuntimeSnapshot:
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
        is here to catch up with another writer, not to downgrade.

        `read_only` keeps the read on the shared lock and off the write path, so
        a caller that only renders the controls cannot settle a pending catalog
        migration on the operator's behalf.
        """

        current = self._runtime.current()
        try:
            view = self._store.read_extension_control_authority_for_registry(self._registry, read_only=read_only)
            if view.health is not AuthorityHealth.PROTECTED or (view.revision, view.managed_revision) <= (
                current.revision,
                current.managed_revision,
            ):
                return current
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
            return effective_controls_payload(self._registry, self._runtime.current(), self._store)
        _ = self._runtime.refresh(view)
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
                return self.effective()
            raise ExtensionControlApiError(409, "authority_not_recoverable")
        _ = self._runtime.refresh(current)
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
        return self.effective()

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
        _ = self._runtime.refresh(view)
        return self.effective()

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        with self._preview_lock, lifecycle.session():
            return self._preview_locked(payload)

    def _preview_locked(self, payload: dict[str, object]) -> dict[str, object]:
        from .extension_control_targets import request_metadata

        request_registry = self._registry
        raw_layers = payload.get("layers")
        if not isinstance(raw_layers, list):
            raise ExtensionControlApiError(400, "invalid_layers")
        if len(raw_layers) > MAX_CONTROL_LAYERS:
            raise ExtensionControlApiError(400, "layer_limit_exceeded")
        try:
            raw = layers_from_json(json.dumps(raw_layers, separators=(",", ":")))
        except (TypeError, ValueError, ExtensionControlAuthorityError) as exc:
            raise ExtensionControlApiError(400, "invalid_mutation") from exc
        if any(len(layer.controls) > MAX_CONTROLS_PER_LAYER for layer in raw):
            raise ExtensionControlApiError(400, "layer_control_limit_exceeded")
        if sum(len(layer.controls) for layer in raw) > MAX_CONTROLS_TOTAL:
            raise ExtensionControlApiError(400, "control_limit_exceeded")
        # Resolve authority before metadata preparation can perform transfer IO.
        current = self._live_snapshot(read_only=True)
        if current.health is not AuthorityHealth.PROTECTED:
            raise ExtensionControlApiError(423, "authority_unavailable")
        try:
            targets = request_metadata(self._store, request_registry, raw)
        except (ValueError, OSError) as exc:
            raise ExtensionControlApiError(503, "pack_preparation_unavailable") from exc
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
            self._validate_authority_mutability(proposed_layers, registry=registry)
            mutation = candidate.mutation
            proposed_layers = tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in proposed_layers)
        composed = compose_control_layers(proposed_layers)
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
            ),
        }
        if request_needs_proof(payload):
            session_nonce = required_request_string(payload, "session_nonce")
            try:
                proof = issue_extension_control_proof(
                    self._store.guard_home,
                    mutation,
                    approval_gate_input=input_from_mapping(payload),
                    session_nonce=session_nonce,
                )
            except (ApprovalGateError, ExtensionControlProofError) as exc:
                raise ExtensionControlApiError(423, "approval_required") from exc
            self._remember_proof(mutation, proof, request_digest=request_digest(payload), candidate=candidate)
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
        original_digest = request_digest(payload)
        if isinstance(pending, _AppliedMutation):
            if pending.canonical_digest != original_digest:
                raise ExtensionControlApiError(409, "proof_mismatch")
            return dict(pending.response)
        if pending.request_digest != original_digest:
            raise ExtensionControlApiError(409, "proof_mismatch")
        mutation = pending.mutation
        candidate = pending.candidate
        if candidate is not None and expired((candidate,)):
            raise ExtensionControlApiError(409, "prepared_preview_expired")
        registry = self._registry if candidate is None else candidate.registry
        current = self._live_snapshot(read_only=True)
        if candidate is not None and (
            current.managed_revision != candidate.managed_revision
            or tuple(layer for layer in current.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
            != candidate.managed_layers
        ):
            raise ExtensionControlApiError(409, "managed_layer_conflict")
        proposed_layers = self._effective_layers_for_local_mutation(mutation.layers)
        proposed_layers = tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in proposed_layers)
        semantic_preview = build_extension_control_semantic_preview(
            registry,
            tuple(replace(layer, catalog_digest=registry.catalog_digest) for layer in current.layers),
            proposed_layers,
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
            raise ExtensionControlApiError(409, "authority_conflict") from exc
        self._registry = registry
        self.catalog_digest = registry.catalog_digest
        composed_view = self._store.read_extension_control_authority_for_registry(registry)
        snapshot = self._runtime.refresh(composed_view)
        self._store.add_event(
            "extension_control_authority_changed",
            {
                "revision": snapshot.revision,
                "previous_revision": mutation.previous_revision,
                "catalog_digest": snapshot.catalog_digest,
                "actor_ref": hashlib.sha256(f"actor-ref\u0000{mutation.actor_id}".encode()).hexdigest(),
                "mutation_ref": mutation.canonical_digest,
                "semantic_targets": self._semantic_event_targets(semantic_preview),
            },
            datetime.now(timezone.utc).isoformat(),
        )
        response: dict[str, object] = {
            "schema_version": _EXTENSION_CONTROL_API_SCHEMA,
            "status": "applied",
            "revision": snapshot.revision,
            "catalog_digest": snapshot.catalog_digest,
        }
        with self._proof_lock:
            _ = self._pending_proofs.pop(proof_id, None)
            self._applied_mutations[proof_id] = _AppliedMutation(original_digest, response)
            self._applied_mutations.move_to_end(proof_id)
            while len(self._applied_mutations) > _MAX_APPLIED_MUTATIONS:
                _ = self._applied_mutations.popitem(last=False)
        return dict(response)

    def _canonicalize_extension_ids(
        self,
        layers: tuple[ExtensionControlLayer, ...],
        *,
        targets=None,
    ) -> tuple[ExtensionControlLayer, ...]:
        canonical_layers: list[ExtensionControlLayer] = []
        for layer in layers:
            canonical_controls: list[ExtensionControl] = []
            seen_targets: set[tuple[ControlTargetKind, str]] = set()
            for control in layer.controls:
                if control.target.kind is ControlTargetKind.EXTENSION:
                    extension = (targets or self._registry).get(control.target.target_id)
                    if extension is None:
                        raise ExtensionControlApiError(400, "unknown_extension")
                    control = replace(
                        control,
                        target=replace(control.target, target_id=extension.extension_id),
                    )
                target_key = (control.target.kind, control.target.target_id)
                if target_key in seen_targets:
                    raise ExtensionControlApiError(400, "duplicate_control_target")
                seen_targets.add(target_key)
                canonical_controls.append(control)
            canonical_layers.append(replace(layer, controls=tuple(canonical_controls)))
        return tuple(canonical_layers)

    def _validate_authority_mutability(
        self, layers: tuple[ExtensionControlLayer, ...], *, registry: CommandSafetyExtensionRegistry | None = None
    ) -> None:
        registry = self._registry if registry is None else registry
        current = self._runtime.current()
        current_managed = tuple(layer for layer in current.layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
        proposed_managed = tuple(layer for layer in layers if layer.kind is ControlLayerKind.SIGNED_CLOUD)
        if proposed_managed != current_managed:
            raise ExtensionControlApiError(403, "managed_layer_mutation")

        current_local = next((layer for layer in current.layers if layer.kind is ControlLayerKind.LOCAL_ADMIN), None)
        current_states = {
            (control.target.kind, control.target.target_id): control.state
            for control in (() if current_local is None else current_local.controls)
        }
        proposed_local = next((layer for layer in layers if layer.kind is ControlLayerKind.LOCAL_ADMIN), None)
        for control in () if proposed_local is None else proposed_local.controls:
            target_id = control.target.target_id
            immutable = False
            error_code = "immutable_permission"
            if control.target.kind is ControlTargetKind.EXTENSION:
                extension = registry.get(target_id)
                immutable = extension is not None and extension.required
                error_code = "immutable_extension"
            else:
                permission = registry.permission(target_id)
                immutable = permission is not None and not permission.configurable
            if immutable and current_states.get((control.target.kind, target_id)) != control.state:
                # Preserve unchanged legacy authority, but do not permit creation or
                # modification of immutable controls. Omitting a legacy immutable
                # control remains allowed because that restores canonical behavior.
                raise ExtensionControlApiError(403, error_code)

    def _mutation_from_payload(self, payload: dict[str, object], *, targets=None) -> ExtensionControlMutation:
        targets = targets or self._registry
        previous_revision = payload.get("previous_revision")
        raw_layers = payload.get("layers")
        if isinstance(previous_revision, bool) or not isinstance(previous_revision, int):
            raise ExtensionControlApiError(400, "invalid_previous_revision")
        if not isinstance(raw_layers, list):
            raise ExtensionControlApiError(400, "invalid_layers")
        if len(raw_layers) > MAX_CONTROL_LAYERS:
            raise ExtensionControlApiError(400, "layer_limit_exceeded")
        try:
            layers = layers_from_json(json.dumps(raw_layers, separators=(",", ":")))
            layers = self._canonicalize_extension_ids(layers, targets=targets)
            if any(len(layer.controls) > MAX_CONTROLS_PER_LAYER for layer in layers):
                raise ExtensionControlApiError(400, "layer_control_limit_exceeded")
            if sum(len(layer.controls) for layer in layers) > MAX_CONTROLS_TOTAL:
                raise ExtensionControlApiError(400, "control_limit_exceeded")
            mutation = ExtensionControlMutation(
                previous_revision=previous_revision,
                catalog_digest=required_request_string(payload, "catalog_digest"),
                layers=layers,
                actor_id=required_request_string(payload, "actor_id"),
                idempotency_key=required_request_string(payload, "idempotency_key"),
                nonce=required_request_string(payload, "nonce"),
            )
            _ = mutation.canonical_digest
        except ExtensionControlApiError:
            raise
        except (
            TypeError,
            ValueError,
            ExtensionControlProofError,
            ExtensionControlAuthorityError,
        ) as exc:
            raise ExtensionControlApiError(400, "invalid_mutation") from exc
        if mutation.catalog_digest != self._registry.catalog_digest:
            raise ExtensionControlApiError(409, "catalog_conflict")
        if any(layer.catalog_digest != self._registry.catalog_digest for layer in mutation.layers):
            raise ExtensionControlApiError(409, "catalog_conflict")
        for layer in mutation.layers:
            for control in layer.controls:
                target_id = control.target.target_id
                if control.target.kind is ControlTargetKind.EXTENSION:
                    if targets.get(target_id) is None:
                        raise ExtensionControlApiError(400, "unknown_extension")
                elif targets.permission(target_id) is None:
                    raise ExtensionControlApiError(400, "unknown_permission")
        self._validate_authority_mutability(mutation.layers, registry=targets)
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

    def _semantic_event_targets(self, semantic_preview: dict[str, object]) -> list[dict[str, object]]:
        raw_targets = semantic_preview.get("changed_targets")
        if not isinstance(raw_targets, list):
            return []
        event_targets: list[dict[str, object]] = []
        for raw in raw_targets[:_MAX_EVENT_TARGETS]:
            if not isinstance(raw, dict):
                continue
            target = raw.get("target")
            if not isinstance(target, dict):
                continue
            kind = target.get("kind")
            target_id = target.get("target_id")
            if not isinstance(kind, str) or not isinstance(target_id, str):
                continue
            rule_ids = raw.get("affected_rule_ids")
            safe_rule_ids = (
                [value for value in rule_ids[:_MAX_EVENT_RULE_IDS] if isinstance(value, str)]
                if isinstance(rule_ids, list)
                else []
            )
            event_targets.append(
                {
                    "kind": kind,
                    "target_ref": hashlib.sha256(
                        f"extension-control-target-ref\u0000{kind}\u0000{target_id}".encode()
                    ).hexdigest(),
                    "before_explicit": raw.get("before_explicit"),
                    "after_explicit": raw.get("after_explicit"),
                    "before_effective": raw.get("before_effective"),
                    "after_effective": raw.get("after_effective"),
                    "affected_rule_ids": safe_rule_ids,
                }
            )
        return event_targets

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

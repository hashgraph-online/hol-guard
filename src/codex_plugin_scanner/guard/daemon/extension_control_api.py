"""Bounded daemon API service for extension-control inspection and mutation."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, cast

from ..approval_gate import (
    ApprovalGateError,
    consume_extension_control_grant,
    input_from_mapping,
    require_extension_control,
)
from ..runtime.command_extensions import CommandSafetyExtensionRegistry
from ..runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    layers_from_json,
    layers_to_json,
)
from ..runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from ..runtime.extension_control_proof import (
    ExtensionControlMutation,
    ExtensionControlProof,
    ExtensionControlProofError,
    issue_extension_control_proof,
)
from ..runtime.extension_control_resolver import compose_control_layers
from ..runtime.extension_control_runtime import ExtensionControlRuntime

if TYPE_CHECKING:
    from ..store import GuardStore

_EXTENSION_CONTROL_API_SCHEMA = "guard.daemon.extension-controls.v1"
_MAX_PENDING_PROOFS = 128
_MAX_APPLIED_MUTATIONS = 128
_MAX_CONTROLS = 4096
_MAX_LAYERS = 2
_MAX_OBSERVATIONS = 2048
_RECOVERY_ACTIONS = {
    "approval_required": "provide_local_approval",
    "authority_conflict": "refresh_effective_controls",
    "authority_unavailable": "enroll_or_repair_authority",
    "catalog_conflict": "refresh_catalog",
    "proof_invalid": "request_new_proof",
    "proof_mismatch": "request_new_proof",
    "proof_not_found": "request_new_proof",
    "revision_conflict": "refresh_effective_controls",
}


@dataclass(frozen=True, slots=True)
class ExtensionControlApiError(Exception):
    status: int
    code: str

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"error": self.code}
        action = _RECOVERY_ACTIONS.get(self.code)
        if action is not None:
            payload["recovery"] = {"action": action}
        return payload


@dataclass(frozen=True, slots=True)
class _PendingMutation:
    mutation: ExtensionControlMutation
    proof: ExtensionControlProof


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
        self._runtime = runtime
        self._proof_lock = threading.Lock()
        self._apply_lock = threading.Lock()
        self._pending_proofs: OrderedDict[str, _PendingMutation] = OrderedDict()
        self._applied_mutations: OrderedDict[str, _AppliedMutation] = OrderedDict()

    def catalog(self) -> dict[str, object]:
        return {
            "schema_version": _EXTENSION_CONTROL_API_SCHEMA,
            "control_schema_version": CONTROL_SCHEMA_VERSION,
            "catalog_digest": self._registry.catalog_digest,
            "extensions": [extension.to_dict() for extension in self._registry.extensions],
            "limits": {
                "max_body_bytes": 1_000_000,
                "max_controls": _MAX_CONTROLS,
                "max_observations": _MAX_OBSERVATIONS,
            },
        }

    def effective(self) -> dict[str, object]:
        snapshot = self._runtime.current()
        composed = compose_control_layers(snapshot.layers)
        return {
            "schema_version": _EXTENSION_CONTROL_API_SCHEMA,
            "health": snapshot.health.value,
            "revision": snapshot.revision,
            "catalog_digest": snapshot.catalog_digest,
            "global_lockdown": composed.global_lockdown,
            "controls": [
                {
                    "target": {
                        "kind": control.target.kind.value,
                        "target_id": control.target.target_id,
                    },
                    "state": control.state.value,
                }
                for control in composed.controls
            ],
            "layers": cast(list[object], json.loads(layers_to_json(snapshot.layers))),
            "failures": [
                {
                    "code": failure.code.value,
                    **({"layer_kind": failure.layer_kind.value} if failure.layer_kind is not None else {}),
                }
                for failure in composed.failures
            ],
        }

    def refresh(self) -> dict[str, object]:
        view = self._store.read_extension_control_authority(
            catalog_digest=self._registry.catalog_digest,
        )
        _ = self._runtime.refresh(view)
        return self.effective()

    def acknowledge_degraded(self, payload: dict[str, object]) -> dict[str, object]:
        if self._runtime.current().health is not AuthorityHealth.DEGRADED_UNACKNOWLEDGED:
            raise ExtensionControlApiError(409, "authority_not_degraded")
        session_nonce = self._required_string(payload, "session_nonce")
        current = self._store.read_extension_control_authority(catalog_digest=self._registry.catalog_digest)
        action = "acknowledge-degraded"
        subject = f"{action}:{current.health.value}:{current.revision}:{self._registry.catalog_digest}"
        try:
            grant = require_extension_control(
                self._store.guard_home,
                approval_gate_input=input_from_mapping(payload),
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
        view = self._store.acknowledge_extension_control_degraded_mode()
        _ = self._runtime.refresh(view)
        return self.effective()

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        current = self._runtime.current()
        mutation = self._mutation_from_payload(payload)
        if current.health is not AuthorityHealth.PROTECTED:
            raise ExtensionControlApiError(423, "authority_unavailable")
        if mutation.previous_revision != current.revision:
            raise ExtensionControlApiError(409, "revision_conflict")
        composed = compose_control_layers(mutation.layers)
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
        }
        if self._payload_requests_proof(payload):
            session_nonce = self._required_string(payload, "session_nonce")
            try:
                proof = issue_extension_control_proof(
                    self._store.guard_home,
                    mutation,
                    approval_gate_input=input_from_mapping(payload),
                    session_nonce=session_nonce,
                )
            except (ApprovalGateError, ExtensionControlProofError) as exc:
                raise ExtensionControlApiError(423, "approval_required") from exc
            self._remember_proof(mutation, proof)
            response["proof_id"] = proof.proof_id
        return response

    def apply(self, payload: dict[str, object]) -> dict[str, object]:
        with self._apply_lock:
            return self._apply_locked(payload)

    def _apply_locked(self, payload: dict[str, object]) -> dict[str, object]:
        proof_id = self._required_string(payload, "proof_id")
        mutation = self._mutation_from_payload(payload)
        pending = self._proof_state(proof_id)
        if isinstance(pending, _AppliedMutation):
            if pending.canonical_digest != mutation.canonical_digest:
                raise ExtensionControlApiError(409, "proof_mismatch")
            return dict(pending.response)
        if pending.mutation.canonical_digest != mutation.canonical_digest:
            raise ExtensionControlApiError(409, "proof_mismatch")
        try:
            view = self._store.commit_extension_control_layers(
                mutation.layers,
                catalog_digest=mutation.catalog_digest,
                actor_id=mutation.actor_id,
                expected_revision=mutation.previous_revision,
                idempotency_key=mutation.idempotency_key,
                nonce=mutation.nonce,
                proof=pending.proof,
            )
        except ExtensionControlProofError as exc:
            raise ExtensionControlApiError(409, "proof_invalid") from exc
        except (ExtensionControlAuthorityError, ValueError) as exc:
            raise ExtensionControlApiError(409, "authority_conflict") from exc
        snapshot = self._runtime.refresh(view)
        self._store.add_event(
            "extension_control_authority_changed",
            {
                "revision": snapshot.revision,
                "catalog_digest": snapshot.catalog_digest,
                "actor_ref": hashlib.sha256(f"actor-ref\u0000{mutation.actor_id}".encode()).hexdigest(),
                "mutation_ref": mutation.canonical_digest,
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
            self._applied_mutations[proof_id] = _AppliedMutation(mutation.canonical_digest, response)
            self._applied_mutations.move_to_end(proof_id)
            while len(self._applied_mutations) > _MAX_APPLIED_MUTATIONS:
                _ = self._applied_mutations.popitem(last=False)
        return dict(response)

    def _canonicalize_extension_ids(
        self,
        layers: tuple[ExtensionControlLayer, ...],
    ) -> tuple[ExtensionControlLayer, ...]:
        canonical_layers: list[ExtensionControlLayer] = []
        for layer in layers:
            canonical_controls: list[ExtensionControl] = []
            seen_targets: set[tuple[ControlTargetKind, str]] = set()
            for control in layer.controls:
                if control.target.kind is ControlTargetKind.EXTENSION:
                    extension = self._registry.get(control.target.target_id)
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

    def _mutation_from_payload(self, payload: dict[str, object]) -> ExtensionControlMutation:
        previous_revision = payload.get("previous_revision")
        raw_layers = payload.get("layers")
        if isinstance(previous_revision, bool) or not isinstance(previous_revision, int):
            raise ExtensionControlApiError(400, "invalid_previous_revision")
        if not isinstance(raw_layers, list):
            raise ExtensionControlApiError(400, "invalid_layers")
        if len(raw_layers) > _MAX_LAYERS:
            raise ExtensionControlApiError(400, "layer_limit_exceeded")
        try:
            layers = layers_from_json(json.dumps(raw_layers, separators=(",", ":")))
            layers = self._canonicalize_extension_ids(layers)
            if sum(len(layer.controls) for layer in layers) > _MAX_CONTROLS:
                raise ExtensionControlApiError(400, "control_limit_exceeded")
            mutation = ExtensionControlMutation(
                previous_revision=previous_revision,
                catalog_digest=self._required_string(payload, "catalog_digest"),
                layers=layers,
                actor_id=self._required_string(payload, "actor_id"),
                idempotency_key=self._required_string(payload, "idempotency_key"),
                nonce=self._required_string(payload, "nonce"),
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
                    if self._registry.get(target_id) is None:
                        raise ExtensionControlApiError(400, "unknown_extension")
                elif self._registry.permission(target_id) is None:
                    raise ExtensionControlApiError(400, "unknown_permission")
        return mutation

    @staticmethod
    def _required_string(payload: dict[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise ExtensionControlApiError(400, f"invalid_{key}")
        return value

    @staticmethod
    def _payload_requests_proof(payload: dict[str, object]) -> bool:
        return any(
            key in payload
            for key in (
                "approval_gate",
                "approval_password",
                "approval_totp_code",
                "session_nonce",
            )
        )

    def _remember_proof(self, mutation: ExtensionControlMutation, proof: ExtensionControlProof) -> None:
        with self._proof_lock:
            self._pending_proofs[proof.proof_id] = _PendingMutation(mutation, proof)
            self._pending_proofs.move_to_end(proof.proof_id)
            while len(self._pending_proofs) > _MAX_PENDING_PROOFS:
                _ = self._pending_proofs.popitem(last=False)

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

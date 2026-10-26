"""Headless policy sync, MCP policy and approval-gate route handlers for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

from typing import Any, cast

from ..adapters import get_adapter
from ..approval_gate import (
    ApprovalGateError,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..approval_gate import public_config as approval_gate_public_config
from ..approval_gate import (
    revoke_cooldown as revoke_approval_gate_cooldown,
)
from ..config import (
    VALID_RECEIPT_REDACTION_LEVELS,
    editable_guard_settings,
    load_guard_config,
)
from ..managed_controls_policy_fields import ParsedManagedControlsPolicy
from ..native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
    native_rejection_code,
)
from ..policy_bundle_activation import activate_with_reason
from ..policy_bundle_delivery import policy_bundle_acknowledgement_payload
from ..policy_bundle_parser import policy_bundle_is_enforceable, policy_bundle_rejection_message
from ..policy_bundle_trusted_keys import (
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from ..runtime.extension_control_authority import ExtensionControlAuthorityError
from ..runtime.runner import (
    _build_policy_bundle_decisions,
    _daemon_version_supported,
    _guard_device_metadata,
    _persist_cloud_receipt_redaction_level,
    _policy_bundle_acceptance_checkpoint,
    _policy_bundle_cloud_exception_items,
    _policy_bundle_downgrade_reference,
    _policy_bundle_is_version_downgrade,
    _reset_cloud_receipt_redaction_authority,
    _validate_cached_policy_bundle,
)
from .managed_policy_delivery import daemon_managed_controls_candidate
from .server_common import (
    _now,
    _settings_response_payload,
)
from .server_control_cloud_sync import (
    _managed_controls_publish_for,
)


def _safe_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value if value >= 0 else 0
    return 0


class _ControlSyncRoutes:
    """Handler methods for control-plane routes."""

    def _handle_headless_policy_sync(self, payload: dict[str, object]) -> None:
        try:
            self._handle_headless_policy_sync_checked(payload)
        except PolicyBundleNativeUnavailableError:
            # The resident owns policy bundle authority. Without its verdict
            # nothing is accepted, activated, or acknowledged, and the caller
            # gets an explicit retryable outage rather than a policy verdict.
            self._write_native_policy_bundle_unavailable()
        except PolicyBundleNativeError as error:
            # A native verdict or input rejection is final for this bundle;
            # report its code instead of a retryable outage.
            self._write_native_policy_bundle_rejection(native_rejection_code(error))

    def _write_native_policy_bundle_rejection(self, code: str) -> None:
        error_payload: dict[str, object] = {"error": code}
        remediation = policy_bundle_rejection_message(code)
        if remediation is not None:
            error_payload["message"] = remediation
        self._write_json(error_payload, status=400)

    def _write_native_policy_bundle_unavailable(self) -> None:
        self._write_json(
            {
                "error": NATIVE_UNAVAILABLE_REJECTION,
                "message": policy_bundle_rejection_message(NATIVE_UNAVAILABLE_REJECTION),
            },
            status=503,
        )

    def _handle_headless_policy_sync_checked(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        if harness is None:
            self._write_json({"error": "missing_harness"}, status=400)
            return
        try:
            adapter = get_adapter(harness)
        except ValueError:
            self._write_json({"error": "unknown_harness"}, status=404)
            return
        try:
            approval_gate_grant = require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="policy_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        policy_memory = self._policy_memory_payload(payload.get("policy_memory"))
        policy_bundle = self._policy_memory_payload(payload.get("policy_bundle") or payload.get("policyBundle"))
        validated_policy_bundle: dict[str, object] | None = None
        validated_policy_bundle_delivery: dict[str, object] | None = None
        managed_controls_policy: ParsedManagedControlsPolicy | None = None
        managed_controls_capabilities = frozenset[str]()
        applied_bundle_hash = applied_bundle_version = cast(str | None, None)
        if not policy_memory and not policy_bundle:
            self._write_json({"error": "missing_policy_memory"}, status=400)
            return
        if policy_memory:
            self._write_json({"error": "unsupported_policy_memory_contract"}, status=400)
            return
        if policy_bundle:
            validated_policy_bundle, rejection_reason, trusted_policy_bundle_keys = validate_synced_policy_bundle(
                policy_bundle,
                stored_keyring=self.server.store.get_sync_payload("policy_bundle_keyring"),  # type: ignore[attr-defined]
                sync_payload=payload if isinstance(payload, dict) else None,
                supply_chain_keyring=self.server.store.get_sync_payload("supply_chain_bundle_keyring"),  # type: ignore[attr-defined]
                managed_keyring_provenance=self.server.store.get_sync_payload(  # type: ignore[attr-defined]
                    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
                ),
                expected_workspace_id=self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
            )
            existing_policy_bundle, _existing_bundle_error = _validate_cached_policy_bundle(
                self.server.store,  # type: ignore[attr-defined]
                self.server.store.get_sync_payload("policy_bundle"),  # type: ignore[attr-defined]
            )
            if (
                rejection_reason == NATIVE_UNAVAILABLE_REJECTION
                or _existing_bundle_error == NATIVE_UNAVAILABLE_REJECTION
            ):
                self._write_native_policy_bundle_unavailable()
                return
            if validated_policy_bundle is None:
                resolved_reason = rejection_reason or "invalid_policy_bundle"
                error_payload: dict[str, object] = {"error": resolved_reason}
                remediation = policy_bundle_rejection_message(resolved_reason)
                if remediation is not None:
                    error_payload["message"] = remediation
                self._write_json(error_payload, status=400)
                return
            if not _daemon_version_supported(validated_policy_bundle):
                self._write_json({"error": "unsupported_daemon_version"}, status=400)
                return
            if not policy_bundle_is_enforceable(validated_policy_bundle):
                self._write_json(
                    {
                        "error": "inactive_rollout_state",
                        "message": policy_bundle_rejection_message("inactive_rollout_state"),
                    },
                    status=400,
                )
                return
            if _policy_bundle_is_version_downgrade(
                _policy_bundle_downgrade_reference(self.server.store, existing_policy_bundle),  # type: ignore[attr-defined]
                validated_policy_bundle,
            ):
                self._write_json({"error": "bundle_version_downgrade"}, status=400)
                return
            device_id, device_name = _guard_device_metadata(self.server.store)  # type: ignore[attr-defined]
            if validated_policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
                (
                    managed_controls_policy,
                    managed_controls_capabilities,
                    validated_policy_bundle_delivery,
                    managed_error,
                ) = daemon_managed_controls_candidate(
                    store=self.server.store,  # type: ignore[attr-defined]
                    payload=payload,
                    policy_bundle=validated_policy_bundle,
                    device_id=device_id,
                )
                if managed_error is not None:
                    self._write_json({"error": managed_error}, status=400)
                    return
            applied_at = _now()
            signed_remote_decisions = _build_policy_bundle_decisions(
                validated_policy_bundle,
                device_id=device_id,
                device_name=device_name,
            )
            policy_bundle_ack = policy_bundle_acknowledgement_payload(
                device_id=device_id,
                device_name=device_name,
                policy_bundle=validated_policy_bundle,
                synced_at=applied_at,
                delivery=validated_policy_bundle_delivery,
            )
            cloud_exception_items = _policy_bundle_cloud_exception_items(
                self.server.store,  # type: ignore[attr-defined]
                sync_exceptions=[],
                policy_bundle=validated_policy_bundle,
                policy_bundle_ack=policy_bundle_ack,
                device_id=device_id,
            )
            try:
                activated, activation_rejection_reason = activate_with_reason(
                    self.server.store.apply_policy_bundle_authority,  # type: ignore[attr-defined]
                    signed_remote_decisions,
                    applied_at,
                    policy_bundle=validated_policy_bundle,
                    policy_bundle_keyring=policy_bundle_keyring_payload(
                        trusted_policy_bundle_keys,
                        workspace_id=self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
                    ),
                    cloud_exceptions=cloud_exception_items,
                    policy_bundle_ack=policy_bundle_ack,
                    policy_bundle_checkpoint=_policy_bundle_acceptance_checkpoint(validated_policy_bundle),
                    update_last_good=True,
                    policy_bundle_last_error={},
                    managed_controls_policy=managed_controls_policy,
                    managed_controls_negotiated_capabilities=managed_controls_capabilities,
                    managed_controls_delivery=validated_policy_bundle_delivery,
                    managed_controls_publish=_managed_controls_publish_for(self.server),
                    approval_gate_grant=approval_gate_grant,
                    remote_write_authorized=True,
                )
            except PolicyBundleNativeError:
                raise
            except (ExtensionControlAuthorityError, ValueError):
                self._write_json({"error": "managed_runtime_publish_failed"}, status=503)
                return
            if activated is None:
                self._write_json({"error": activation_rejection_reason}, status=400)
                return
            receipt_redaction_level = validated_policy_bundle.get("receiptRedactionLevel")
            if isinstance(receipt_redaction_level, str) and receipt_redaction_level in VALID_RECEIPT_REDACTION_LEVELS:
                _persist_cloud_receipt_redaction_level(
                    self.server.store,  # type: ignore[attr-defined]
                    level=receipt_redaction_level,
                    synced_at=applied_at,
                )
            else:
                _reset_cloud_receipt_redaction_authority(  # type: ignore[arg-type]
                    self.server.store,  # type: ignore[attr-defined]
                    synced_at=applied_at,
                )
            applied_bundle_hash = str(validated_policy_bundle["bundleHash"])
            applied_bundle_version = str(validated_policy_bundle["bundleVersion"])
        self._write_json(
            {
                "bundle_hash": applied_bundle_hash,
                "bundle_version": applied_bundle_version,
                "harness": adapter.harness,
                "operation": "policy_sync",
                "status": "completed",
            }
        )

    def _handle_approval_gate_cooldown_revoke(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        gate = revoke_approval_gate_cooldown(guard_home).to_dict()
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = gate
        self._write_json(_settings_response_payload(guard_home, settings))

    def _handle_approval_gate_totp_enroll(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        device_label = self._optional_string(payload.get("device_label")) or "local-device"
        try:
            enrollment = begin_totp_enrollment(
                guard_home,
                approval_gate_input=approval_gate_input_from_mapping(payload),
                device_label=device_label,
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = approval_gate_public_config(guard_home).to_dict()
        response = _settings_response_payload(guard_home, settings)
        response["enrollment"] = enrollment
        self._write_json(response)

    def _handle_approval_gate_totp_verify(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            gate = confirm_totp_enrollment(
                guard_home,
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = gate.to_dict()
        self._write_json(_settings_response_payload(guard_home, settings))

    def _handle_approval_gate_totp_disable(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            gate = disable_totp(
                guard_home,
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        config = load_guard_config(guard_home)
        settings = editable_guard_settings(config)
        settings["approval_gate"] = gate.to_dict()
        self._write_json(_settings_response_payload(guard_home, settings))

    def _handle_mcp_policy_decision(self, request_id: str, payload: dict[str, object]) -> None:
        from .mcp_policy_decisions import handle_mcp_policy_decision

        handle_mcp_policy_decision(cast(Any, self), request_id, payload)

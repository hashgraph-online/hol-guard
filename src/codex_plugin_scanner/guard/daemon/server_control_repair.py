"""Protection repair and settings route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone

from ..approval_gate import (
    ApprovalGateError,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..approval_gate import public_config as approval_gate_public_config
from ..approval_gate import (
    update_settings as update_approval_gate_settings,
)
from ..approval_gate import (
    validate_settings_update as validate_approval_gate_settings,
)
from ..cli.update_commands import build_guard_update_status_payload
from ..config import (
    editable_guard_settings,
    load_guard_config,
    reset_guard_settings,
    update_guard_settings,
    update_guard_update_channel,
)
from ..models import (
    GuardRuntimeRegistration,
)
from ..package_firewall_entitlement import (
    resolve_package_firewall_entitlement,
)
from ..runtime.runner import (
    _requeue_cloud_review_privacy_projection,
)
from ..runtime_artifact_reconciliation import (
    repair_failing_managed_harness_hooks,
)
from . import repair_api
from .protection_repair_retry import containment_repair_outcome, incomplete_protection_repair_payload
from .protection_repair_stages import (
    harness_hooks_repair_reason,
    integrity_repair_reasons,
    record_incomplete_protection_repair,
    repair_daemon_registration,
)
from .server_common import (
    _now,
    _settings_response_payload,
)
from .server_control_connect_flow import (
    _repair_command_activity_persistence_health,
)


class _RepairSettingsRoutes:
    """Handler methods for control-plane routes."""

    def _record_incomplete_protection_repair(self, check_reasons: Mapping[str, str]) -> None:
        record_incomplete_protection_repair(self._daemon_server().diagnostics, check_reasons)

    def _handle_repair_api(self, path: str, payload: dict[str, object]) -> None:
        server = self._daemon_server()
        handler = repair_api.repair_request if path == "/v1/repair" else repair_api.removal_request
        try:
            result = handler(server.store, payload, home_dir=server.home_dir, workspace_dir=server.workspace_dir)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except repair_api.RemovalConfirmationError:
            self._write_json(
                {"error": "confirmation_required", "confirm": repair_api.REMOVE_CONFIRMATION},
                status=400,
            )
            return
        self._write_json(result, extra_headers={"Cache-Control": "no-store, max-age=0"})

    def _handle_protection_repair(self, payload: dict[str, object]) -> None:
        check_id = self._optional_string(payload.get("check_id"))
        store = self.server.store  # type: ignore[attr-defined]
        if check_id in {"all", "policy_engine", "rule_packs", "tamper_checks"}:
            repaired_check_ids: list[str] = []
            pending_check_ids: list[str] = []
            failed_check_ids: list[str] = []
            check_reasons: dict[str, str] = {}
            if check_id == "all":
                daemon_server = self._daemon_server()
                registration_reason = repair_daemon_registration(
                    store,
                    session_id=daemon_server.runtime_session_id,
                    registration=GuardRuntimeRegistration(
                        daemon_host=daemon_server.runtime_host,
                        daemon_port=daemon_server.daemon_port(),
                        started_at=daemon_server.runtime_started_at,
                    ),
                    last_heartbeat_at=_now(),
                )
                if registration_reason is None:
                    repaired_check_ids.append("daemon")
                else:
                    failed_check_ids.append("daemon")
                    check_reasons["daemon"] = registration_reason
            try:
                status = store.setup_policy_integrity(now=_now(), include_items=False)
                if status.get("mode") != "protected":
                    status = store.repair_policy_integrity(
                        clear_invalid=False,
                        now=_now(),
                        include_items=False,
                    )
            except (OSError, RuntimeError, TypeError, ValueError):
                check_reasons.update(integrity_repair_reasons(restored=False))
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "error": "protection_repair_failed",
                        "message": "Guard could not restore integrity protection automatically.",
                        "check_reasons": check_reasons,
                    },
                    status=409,
                )
                return
            repaired = status.get("mode") == "protected"
            degraded_reasons = status.get("degraded_reasons")
            reason_count = len(degraded_reasons) if isinstance(degraded_reasons, list) else 0
            if repaired:
                repaired_check_ids.extend(["policy_engine", "rule_packs", "tamper_checks"])
            else:
                failed_check_ids.extend(["policy_engine", "rule_packs", "tamper_checks"])
                check_reasons.update(integrity_repair_reasons(restored=False))
            hook_failures: list[str] | tuple[str, ...] = []
            if check_id == "all":
                hook_repair_unknown = False
                try:
                    _, hook_failures = repair_failing_managed_harness_hooks(store)
                except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                    hook_failures = []
                    hook_repair_unknown = True
                has_active_hooks = any(
                    isinstance(install.get("harness"), str) and install.get("active") is True
                    for install in store.list_managed_installs()
                )
                if hook_failures or hook_repair_unknown or not has_active_hooks:
                    failed_check_ids.append("harness_hooks")
                    check_reasons["harness_hooks"] = harness_hooks_repair_reason(
                        has_active_hooks=has_active_hooks,
                        hook_failures=hook_failures,
                        hook_repair_unknown=hook_repair_unknown,
                    )
                else:
                    repaired_check_ids.append("harness_hooks")
                if repaired:
                    (
                        containment_repaired,
                        containment_failed,
                        containment_reasons,
                    ) = containment_repair_outcome(lambda: self._containment_health_payload(force_refresh=True))
                    repaired_check_ids.extend(containment_repaired)
                    failed_check_ids.extend(containment_failed)
                    for failed_check_id in containment_failed:
                        check_reasons[failed_check_id] = containment_reasons[failed_check_id]
                    try:
                        config = load_guard_config(store.guard_home)
                        probe_reason = _repair_command_activity_persistence_health(store)
                        store.maintain_command_activity(
                            now=datetime.now(timezone.utc),
                            detail_retain_days=config.evidence_retain_days,
                        )
                        evidence_health = store.get_command_activity_persistence_health()
                        if evidence_health.active_error_count > 0:
                            failed_check_ids.append("decision_stream")
                            check_reasons["decision_stream"] = "decision_stream_degraded"
                        elif probe_reason is not None:
                            pending_check_ids.append("decision_stream")
                            check_reasons["decision_stream"] = probe_reason
                        else:
                            repaired_check_ids.append("decision_stream")
                    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                        failed_check_ids.append("decision_stream")
                        check_reasons["decision_stream"] = "decision_stream_health_unavailable"
                if repaired and (failed_check_ids or pending_check_ids):
                    self._record_incomplete_protection_repair(check_reasons)
                    self._write_json(
                        incomplete_protection_repair_payload(
                            repaired_check_ids=repaired_check_ids,
                            failed_check_ids=failed_check_ids,
                            failed_harnesses=hook_failures,
                            pending_check_ids=pending_check_ids,
                            has_active_hooks=has_active_hooks,
                            hook_failures=hook_failures,
                            hook_repair_unknown=hook_repair_unknown,
                            check_reasons=check_reasons,
                        ),
                        status=409,
                    )
                    return
            if not repaired or failed_check_ids or pending_check_ids:
                self._record_incomplete_protection_repair(check_reasons)
            self._write_json(
                {
                    **({"error": "local_integrity_repair_incomplete"} if not repaired else {}),
                    "repaired": repaired,
                    "repair_scope": "local_integrity",
                    "check_ids": repaired_check_ids,
                    **({"failed_check_ids": failed_check_ids} if failed_check_ids else {}),
                    "pending_check_ids": pending_check_ids,
                    "check_reasons": check_reasons,
                    "message": (
                        "Integrity protection restored."
                        if repaired
                        else (
                            "Guard could not establish a local integrity proof. "
                            "Unverified local rules remain disabled. Local repair did not change Guard Cloud policy "
                            "availability. Retry local repair from Protect; "
                            f"Guard will keep the remaining {reason_count or 1} issue isolated."
                        )
                    ),
                },
                status=200 if repaired else 409,
            )
            return
        if check_id == "decision_stream":
            check_reasons: dict[str, str] = {}
            try:
                config = load_guard_config(store.guard_home)
                probe_reason = _repair_command_activity_persistence_health(store)
            except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                check_reasons["decision_stream"] = "decision_stream_health_unavailable"
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "error": "protection_repair_failed",
                        "message": "Guard could not verify the command evidence store.",
                        "check_reasons": check_reasons,
                    },
                    status=409,
                )
                return
            if probe_reason is not None:
                check_reasons["decision_stream"] = probe_reason
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "repaired": False,
                        "repair_scope": "local_integrity",
                        "check_ids": [],
                        "pending_check_ids": ["decision_stream"],
                        "check_reasons": check_reasons,
                        "message": (
                            "Guard could not run the native policy engine to prove command evidence. "
                            "Existing evidence was not changed."
                        ),
                    },
                    status=409,
                )
                return
            try:
                store.maintain_command_activity(
                    now=datetime.now(timezone.utc),
                    detail_retain_days=config.evidence_retain_days,
                )
                health = store.get_command_activity_persistence_health()
            except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
                check_reasons["decision_stream"] = "decision_stream_health_unavailable"
                self._record_incomplete_protection_repair(check_reasons)
                self._write_json(
                    {
                        "error": "protection_repair_failed",
                        "message": "Guard could not verify the command evidence store.",
                        "check_reasons": check_reasons,
                    },
                    status=409,
                )
                return
            repaired = health.active_error_count == 0
            if not repaired:
                check_reasons["decision_stream"] = "decision_stream_degraded"
                self._record_incomplete_protection_repair(check_reasons)
            self._write_json(
                {
                    "repaired": repaired,
                    "repair_scope": "local_integrity",
                    "check_ids": ["decision_stream"] if repaired else [],
                    **({"failed_check_ids": ["decision_stream"]} if not repaired else {}),
                    "check_reasons": check_reasons,
                    "message": (
                        "Command evidence is healthy."
                        if repaired
                        else "Guard could not restore command evidence persistence."
                    ),
                },
                status=200 if repaired else 409,
            )
            return
        self._write_json({"error": "unsupported_protection_check"}, status=400)

    def _handle_settings_update(self, payload: dict[str, object]) -> None:
        self._apply_settings_payload(payload, missing_error="invalid_settings")

    def _handle_protection_repair_approval_gate_setup(self, payload: dict[str, object]) -> None:
        if not self._protection_repair_approval_gate_setup_payload_is_allowed(payload):
            self._write_json({"error": "invalid_settings"}, status=400)
            return
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        gate_config = approval_gate_public_config(guard_home)
        if gate_config.configured or gate_config.enabled:
            self._write_json({"error": "approval_gate_setup_unavailable"}, status=409)
            return
        self._apply_settings_payload(payload, missing_error="invalid_settings")

    def _protection_repair_approval_gate_setup_payload_is_allowed(self, payload: object) -> bool:
        if not isinstance(payload, dict) or set(payload) != {"settings"}:
            return False
        settings = payload.get("settings")
        if not isinstance(settings, dict) or set(settings) != {"approval_gate"}:
            return False
        gate_payload = settings.get("approval_gate")
        return (
            isinstance(gate_payload, dict)
            and set(gate_payload) == {"enabled", "new_password", "confirm_password"}
            and gate_payload.get("enabled") is True
        )

    def _apply_settings_payload(self, payload: dict[str, object], *, missing_error: str) -> None:
        settings = payload.get("settings")
        if not isinstance(settings, dict):
            self._write_json({"error": missing_error}, status=400)
            return
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        previous_redaction_level = load_guard_config(guard_home).receipt_redaction_level
        gate_payload = settings.get("approval_gate")
        gate_input = (
            approval_gate_input_from_mapping({"approval_gate": gate_payload})
            if isinstance(gate_payload, dict)
            else None
        )
        if payload.get("approval_password") or payload.get("approval_totp_code"):
            proof_input = approval_gate_input_from_mapping(payload)
            if proof_input is not None:
                gate_input = proof_input
        presentation_only_keys = {
            "presentation_mode",
            "presentation_mode_explicit",
            "presentation_schema_version",
            "presentation_revision",
        }
        presentation_only = gate_payload is None and bool(settings) and set(settings).issubset(presentation_only_keys)
        try:
            approval_gate_grant = (
                None
                if presentation_only
                else require_high_risk(
                    guard_home,
                    purpose="settings_write",
                    approval_gate_input=gate_input,
                )
            )
            if isinstance(gate_payload, dict):
                validate_approval_gate_settings(
                    guard_home,
                    gate_payload,
                    approval_gate_grant=approval_gate_grant,
                )
            config_settings = {key: value for key, value in settings.items() if key != "approval_gate"}
            entitlement = resolve_package_firewall_entitlement(self.server.store)  # type: ignore[attr-defined]
            config = update_guard_settings(
                guard_home,
                config_settings,
                approval_gate_grant=approval_gate_grant,
                cloud_sync_entitled=bool(entitlement.get("allowed")),
                skip_approval_gate=presentation_only,
            )
            if isinstance(gate_payload, dict):
                update_approval_gate_settings(
                    guard_home,
                    gate_payload,
                    approval_gate_grant=approval_gate_grant,
                )
                config = load_guard_config(guard_home)
            if config.receipt_redaction_level != previous_redaction_level:
                _requeue_cloud_review_privacy_projection(  # type: ignore[arg-type]
                    self.server.store,
                    level=config.receipt_redaction_level,
                    changed_at=_now(),
                )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": "invalid_settings", "message": str(error)}, status=400)
            return
        self._write_json(_settings_response_payload(guard_home, editable_guard_settings(config)))

    def _handle_update_channel(self, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        try:
            approval_gate_grant = require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            update_guard_update_channel(
                guard_home,
                payload.get("update_channel"),
                approval_gate_grant=approval_gate_grant,
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": "invalid_update_channel", "message": str(error)}, status=400)
            return
        self._write_json(
            build_guard_update_status_payload(guard_home=guard_home),
            extra_headers={"Cache-Control": "no-store, max-age=0"},
        )

    def _handle_settings_import(self, payload: dict[str, object]) -> None:
        self._apply_settings_payload(payload, missing_error="invalid_settings_import")

    def _handle_settings_reset(self, payload: dict[str, object]) -> None:
        confirm = payload.get("confirm")
        if confirm != "reset-local-settings":
            self._write_json({"error": "confirmation_required", "confirm": "reset-local-settings"}, status=400)
            return
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        previous_redaction_level = load_guard_config(guard_home).receipt_redaction_level
        try:
            approval_gate_grant = require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            config = reset_guard_settings(guard_home, approval_gate_grant=approval_gate_grant)
            if config.receipt_redaction_level != previous_redaction_level:
                _requeue_cloud_review_privacy_projection(  # type: ignore[arg-type]
                    self.server.store,
                    level=config.receipt_redaction_level,
                    changed_at=_now(),
                )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        self._write_json(_settings_response_payload(guard_home, editable_guard_settings(config)))

"""Headless app and receipt route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import platform
import uuid
from typing import Any

from ...version import __version__
from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approval_gate import (
    ApprovalGateError,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_verification,
    uninstall_confirmation_token,
)
from ..harness_disconnect_gate import require_harness_disconnect_gate
from ..headless_receipts import record_headless_receipt
from ..native_daemon_handler import (
    NativeDaemonHandlerError,
    native_headless_action_error,
    native_headless_action_state,
    native_headless_cursor_surface_error,
)
from ..native_hook_artifact_compose import NativeHookComposeError
from ..native_runner_authority import NativeRunnerAuthorityError
from ..package_firewall_entitlement import (
    PACKAGE_FIREWALL_AUTHORITY_UNAVAILABLE,
    PACKAGE_FIREWALL_AUTHORITY_UNAVAILABLE_MESSAGE,
    PackageFirewallAccess,
    package_firewall_access,
)
from ..package_firewall_receipts import package_firewall_receipt_metadata
from ..shims import (
    activate_package_shims,
    package_shim_status,
    package_shim_supported_managers,
)
from .server_common import (
    _NATIVE_HANDLER_UNAVAILABLE,
    _is_string_object_dict,
    _now,
)
from .server_control_cloud_sync import (
    _headless_failure,
    _managed_controls_publish_for,
    _queue_headless_cloud_sync_with_optional_publish,
    _receipt_summary,
)

_HEADLESS_APP_ACTIONS = {
    "connect": ("install", "install"),
    "repair": ("repair", "repair"),
    "disconnect": ("remove", "uninstall"),
    "status": ("status", "verify"),
    "test": ("scan", "verify"),
}


class _HeadlessRoutes:
    """Handler methods for control-plane routes."""

    def _headless_reconnect_payload(
        self,
        *,
        cloud_sync: dict[str, object],
        location_id: str | None,
    ) -> dict[str, object]:
        runtime_summary = self.server.store.get_sync_payload("runtime_session_summary")  # type: ignore[attr-defined]
        runtime = runtime_summary if isinstance(runtime_summary, dict) else {}
        latest_cloud_sync = self._latest_cloud_sync_snapshot()
        cloud_sync_status = self._optional_string(cloud_sync.get("status")) or "unknown"
        if cloud_sync_status in {"queued", "in_progress"}:
            reconciliation_status = cloud_sync_status
        elif cloud_sync_status == "auth_expired":
            reconciliation_status = "auth_expired"
        elif cloud_sync_status == "not_configured":
            reconciliation_status = "not_configured"
        elif cloud_sync_status == "synced":
            reconciliation_status = "synced"
        else:
            reconciliation_status = "pending"
        return {
            "correlation_id": str(uuid.uuid4()),
            "freshness": {
                "last_receipt_sync_at": self._optional_string(latest_cloud_sync.get("synced_at")),
                "last_runtime_sync_at": (
                    self._optional_string(runtime.get("runtime_session_synced_at"))
                    or self._optional_string(runtime.get("synced_at"))
                ),
                "local_guard_online_at": self._optional_string(runtime.get("local_guard_online_at")),
            },
            "latest_cloud_sync": latest_cloud_sync,
            "local_identity": {
                "daemon_id": self._optional_string(runtime.get("runtime_device_id")),
                "daemon_version": __version__,
                "hostname": platform.node() or None,
                "ip_address": None,
                "private_ip_address": None,
                "public_ip_address": None,
            },
            "location_id": location_id,
            "reconciliation_status": reconciliation_status,
        }

    def _latest_cloud_sync_snapshot(self) -> dict[str, object]:
        latest_payload = self.server.store.get_sync_payload("headless_app_sync_summary")  # type: ignore[attr-defined]
        if not isinstance(latest_payload, dict):
            latest_payload = self.server.store.get_sync_payload("sync_summary")  # type: ignore[attr-defined]
        if isinstance(latest_payload, dict):
            return dict(latest_payload)
        return {}

    def _headless_app_action_payload(
        self,
        *,
        action_path: str,
        payload: dict[str, object],
    ) -> tuple[int, dict[str, object]]:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]

        def failure(operation: str, error_code: str) -> tuple[int, dict[str, object]]:
            return _headless_failure(lambda: native_headless_action_error(operation, error_code, guard_home=guard_home))

        try:
            mapping = _HEADLESS_APP_ACTIONS[action_path]
        except KeyError:
            return failure(action_path, "unsupported_operation")
        operation, harness_action = mapping
        harness = self._optional_string(payload.get("harness"))
        if harness is None:
            return failure(operation, "missing_harness")
        try:
            adapter = get_adapter(harness)
        except ValueError:
            return failure(operation, "unknown_harness")
        try:
            surface = self._cursor_headless_surface(payload) if adapter.harness == "cursor" else None
        except ValueError:
            status, error_payload = _headless_failure(
                lambda: native_headless_cursor_surface_error(guard_home=guard_home)
            )
            error = error_payload.get("error")
            if status == 400 and isinstance(error, dict):
                error["surface"] = self._optional_string(payload.get("surface")) or ""
            return status, error_payload
        context = self._harness_context(payload)
        try:
            if harness_action == "verify":
                verification_action = "status" if action_path == "status" else "test"
                result = build_harness_verification(
                    adapter.harness,
                    context,
                    self.server.store,  # type: ignore[attr-defined]
                    surface=surface,
                    action=verification_action,
                )
            else:
                result = self._run_headless_managed_action(adapter.harness, harness_action, payload, context)
        except ApprovalGateError as error:
            return error.status, error.to_payload()
        except ValueError as error:
            return failure(operation, str(error))
        location_id = self._optional_string(payload.get("location_id")) or self._optional_string(
            payload.get("locationId")
        )
        receipt = self._record_headless_receipt(
            harness=adapter.harness,
            operation=operation,
            payload=payload,
            result=result,
            location_id=location_id,
            workspace_id=self._optional_string(payload.get("workspace_id")),
            cloud_sync={"status": "pending"},
        )
        cloud_sync = _queue_headless_cloud_sync_with_optional_publish(
            store=self.server.store,
            managed_controls_publish=_managed_controls_publish_for(self.server),
        )
        receipt["cloud_sync"] = cloud_sync
        try:
            state = native_headless_action_state(adapter.harness, operation, result, guard_home=guard_home)
        except NativeDaemonHandlerError:
            # The action already ran and its receipt is recorded; say so, so a client does not blindly retry.
            return 503, {
                **_NATIVE_HANDLER_UNAVAILABLE[1],
                "action_applied": True,
                "cloud_sync": cloud_sync,
                "harness": adapter.harness,
                "operation": operation,
                "receipt": receipt,
            }
        return 200, {
            "cloud_sync": cloud_sync,
            "harness": adapter.harness,
            "operation": operation,
            "result": result,
            "receipt": receipt,
            "state": {**state, "receipt_summary": _receipt_summary(receipt)},
            "reconnect": self._headless_reconnect_payload(
                cloud_sync=cloud_sync,
                location_id=location_id,
            ),
            "status": "completed",
        }

    def _handle_cloud_app_handoff(self, harness: str, query_string: str) -> None:
        _ = (harness, query_string)
        self._write_legacy_cloud_handoff_disabled()

    def _handle_headless_app_action(self, action_path: str, payload: dict[str, object]) -> None:
        status, payload = self._headless_app_action_payload(action_path=action_path, payload=payload)
        self._write_json(payload, status=status)

    def _run_headless_managed_action(
        self,
        harness: str,
        action: str,
        payload: dict[str, object],
        context: HarnessContext,
    ) -> dict[str, object]:
        surface = self._cursor_headless_surface(payload) if harness == "cursor" else None
        if action == "uninstall":
            expected_confirmation = uninstall_confirmation_token(harness)
            confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
                payload.get("confirmation_token")
            )
            if confirmation != expected_confirmation:
                raise ValueError("confirmation_required")
            require_harness_disconnect_gate(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                payload,
                harness=harness,
            )
        install_command = "uninstall" if action == "uninstall" else "install"
        return apply_managed_install(
            install_command,
            harness,
            False,
            context,
            self.server.store,  # type: ignore[attr-defined]
            self._optional_string(payload.get("workspace_id")),
            _now(),
            surface=surface,
        )

    def _handle_audit_remediation(self, action: str, payload: dict[str, object]) -> None:
        if action != "package_shim_path":
            self._write_json({"error": "unsupported_remediation", "operation": action}, status=404)
            return
        manager = self._optional_string(payload.get("manager"))
        if manager is None:
            self._write_json({"error": "missing_manager", "operation": action}, status=400)
            return
        managers, manager_error = self._supply_chain_managers({"managers": [manager]})
        if manager_error is not None:
            self._write_json({"error": manager_error, "operation": action}, status=400)
            return
        entitlement = self._supply_chain_entitlement()
        if not bool(entitlement["allowed"]):
            try:
                current_status = package_shim_status(self._supply_chain_context(payload))
            except NativeRunnerAuthorityError:
                self._write_supply_chain_workspace_unavailable(action)
                return
            access = self._package_firewall_access(
                entitlement,
                operation=None,
                has_installed_managers=bool(current_status.get("installed_managers")),
                reported_operation=action,
            )
            if access is None:
                return
            status, error_code, message = access.block
            self._write_json(
                {
                    "available_actions": access.available_actions,
                    "entitlement": entitlement,
                    "error": error_code,
                    "message": message,
                    "operation": action,
                },
                status=status,
            )
            return
        try:
            context = self._supply_chain_context(payload)
        except NativeRunnerAuthorityError:
            self._write_supply_chain_workspace_unavailable(action)
            return
        try:
            require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="supply_chain_firewall",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
            activation_result = activate_package_shims(context, managers=managers)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json({"error": str(error), "operation": action}, status=400)
            return
        result = {
            "manager": manager,
            **activation_result,
        }
        receipt_overrides = package_firewall_receipt_metadata(
            operation=action,
            result=result,
            managers=(manager,),
            workspace_dir=context.workspace_dir,
        )
        scanner_evidence = receipt_overrides.get("scanner_evidence")
        receipt = self._record_headless_receipt(
            harness="package-firewall",
            operation=action,
            payload=payload,
            result=result,
            workspace_id=self._optional_string(payload.get("workspace_id"))
            or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
            policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
            capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
            artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
            scanner_evidence_extra=scanner_evidence if _is_string_object_dict(scanner_evidence) else None,
        )
        self._write_json(
            {
                "entitlement": entitlement,
                "operation": action,
                "receipt": receipt,
                "result": result,
                "status": "completed",
            }
        )

    def _record_headless_receipt(self, **kwargs: Any) -> dict[str, object]:
        return record_headless_receipt(self.server.store, **kwargs)  # type: ignore[attr-defined]

    def _cursor_headless_surface(self, payload: dict[str, object]) -> str | None:
        surface = self._optional_string(payload.get("surface")) or self._optional_string(payload.get("editor_or_cli"))
        if surface is None:
            return None
        if surface not in {"editor", "cli"}:
            raise ValueError("invalid_cursor_surface")
        return surface

    def _approval_with_extension_recommendation(self, approval: dict[str, object]) -> dict[str, object]:
        from .approval_extension_recommendation import (
            with_approval_extension_coverage,
            with_approval_extension_recommendation,
        )

        include = not self._is_hosted_dashboard_origin()
        api = getattr(self._daemon_server(), "extension_control_api", None)
        if not include or api is None:
            return with_approval_extension_recommendation(approval, registry=None, snapshot=None, include=False)
        registry, snapshot = api.recommendation_inputs()
        store = self._daemon_server().store
        from .native_review_allow_hint import recovered_approval_extension_hint

        # Rows queued before the hints existed, and rows whose queue-time
        # re-review ran out of budget or stored coverage alone, still get what
        # one read-time review can recover.
        hint = recovered_approval_extension_hint(
            store.get_approval_extension_allow_hint(str(approval.get("request_id", ""))),
            approval,
            guard_home=store.guard_home,
            snapshot=snapshot,
        )
        hinted = {**approval, "extension_allow_hint": hint}
        payload = with_approval_extension_recommendation(
            hinted,
            registry=registry,
            snapshot=snapshot,
            include=True,
            guard_home=store.guard_home,
        )
        payload = with_approval_extension_coverage(payload, hinted, include=True, guard_home=store.guard_home)
        from ..approval_gate import public_config
        from .approval_connector_recommendation import safe_connector_recommendation

        connector = safe_connector_recommendation(
            hinted,
            store=store,
            snapshot=snapshot,
            approval_gate_configured=lambda: (gate := public_config(store.guard_home)).configured and gate.enabled,
        )
        if connector is not None:
            payload["connector_recommendation"] = connector
        return payload

    def _supply_chain_entitlement(self) -> dict[str, object]:
        from ..routes.supply_chain_calls import supply_chain_entitlement

        return supply_chain_entitlement(self.server)  # type: ignore[attr-defined]

    def _supply_chain_context(self, payload: dict[str, object]) -> HarnessContext:
        from ..routes.supply_chain_calls import supply_chain_context

        return supply_chain_context(self.server.store, payload)  # type: ignore[attr-defined]

    def _write_supply_chain_workspace_unavailable(self, operation: str) -> None:
        """The native runtime could not resolve the workspace; not a bad folder."""

        self._write_json(  # type: ignore[attr-defined]
            {
                "error": "supply_chain_workspace_unavailable",
                "message": "Guard could not check the project folder right now. Try again in a moment.",
                "operation": operation,
            },
            status=503,
        )

    @staticmethod
    def _supply_chain_managers(payload: dict[str, object]) -> tuple[tuple[str, ...] | None, str | None]:
        managers_value = payload.get("managers")
        if managers_value is None:
            return None, None
        if not isinstance(managers_value, list) or not all(isinstance(manager, str) for manager in managers_value):
            return None, "invalid_managers"
        normalized = [manager.strip().lower() for manager in managers_value if manager.strip()]
        if len(normalized) != len(set(normalized)):
            return None, "duplicate_manager"
        managers = tuple(normalized)
        if not managers:
            return None, "invalid_managers"
        if not set(managers).issubset(set(package_shim_supported_managers())):
            return None, "unsupported_manager"
        return managers, None

    def _package_firewall_access(
        self,
        entitlement: dict[str, object],
        *,
        operation: str | None,
        has_installed_managers: bool,
        reported_operation: str,
    ) -> PackageFirewallAccess | None:
        """What the entitlement permits, or a fail-closed reply and ``None``."""

        try:
            return package_firewall_access(
                entitlement,
                operation=operation,
                has_installed_managers=has_installed_managers,
                guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
            )
        except NativeHookComposeError:
            self._write_json(  # type: ignore[attr-defined]
                {
                    "available_actions": [],
                    "entitlement": entitlement,
                    "error": PACKAGE_FIREWALL_AUTHORITY_UNAVAILABLE,
                    "message": PACKAGE_FIREWALL_AUTHORITY_UNAVAILABLE_MESSAGE,
                    "operation": reported_operation,
                },
                status=503,
            )
            return None

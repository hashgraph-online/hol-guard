"""Supply-chain control-plane route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import tempfile
from datetime import datetime, timezone
from functools import partial
from pathlib import Path

from ..adapters.base import HarnessContext
from ..approval_gate import (
    ApprovalGateError,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..config import (
    load_guard_config,
)
from ..local_supply_chain import (
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_package_firewall_entitlement_with_refresh,
    resolve_supply_chain_audit_workspace_dir,
)
from ..native_daemon_handler import (
    native_supply_chain_error,
)
from ..package_firewall_entitlement import (
    package_firewall_action_states,
    package_firewall_available_actions,
    package_firewall_block_details,
    package_firewall_operation_allowed,
    resolve_package_firewall_entitlement,
)
from ..package_firewall_receipts import package_firewall_receipt_metadata
from ..package_shim_status import record_package_shim_audit_result
from ..project_folder_picker import (
    ProjectFolderPickerBusyError,
    ProjectFolderPickerUnavailableError,
    choose_project_folder,
)
from ..shims import (
    activate_package_shims,
    package_shim_dashboard_status,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    uninstall_package_shims,
)
from ..supply_chain_repair import (
    coordinate_supply_chain_repair,
    repair_sync_intelligence,
)
from .server_common import (
    _is_string_object_dict,
)
from .server_control_cloud_sync import (
    _headless_failure,
    _managed_controls_publish_for,
    _queue_headless_cloud_sync_with_optional_publish,
    _sync_supply_chain_cloud_state_with_optional_auth_context,
)
from .server_control_connect_state import (
    _activate_package_firewall_runtime,
    _copy_guard_cloud_connect_state,
    _copy_package_firewall_connect_state,
    _guard_cloud_connect_state_is_in_flight,
    _repair_detected_package_shims,
    _resolve_package_firewall_connect_flow,
)


class _SupplyChainRoutes:
    """Handler methods for control-plane routes."""

    def _handle_supply_chain_package_firewall_status(self) -> None:
        entitlement = self._supply_chain_entitlement()
        status = package_shim_dashboard_status(self._harness_context({}))
        audit_workspace_dir = self._resolve_supply_chain_workspace_dir({})
        self._write_json(
            {
                "actions": package_firewall_action_states(
                    entitlement,
                    has_installed_managers=bool(status.get("installed_managers")),
                ),
                "audit_workspace_dir": (str(audit_workspace_dir) if audit_workspace_dir is not None else None),
                "cli_fallback": {
                    "connect": "hol-guard connect",
                    "install": "hol-guard package-shims install --json",
                    "status": "hol-guard package-shims status --json",
                    "remove": "hol-guard package-shims uninstall --json",
                },
                "connect_flow": self._supply_chain_connect_flow(entitlement),
                "entitlement": entitlement,
                "operation": "status",
                "status": "completed",
                "supported_managers": list(package_shim_supported_managers()),
                "package_shims": status,
            }
        )

    def _handle_supply_chain_repair(self, payload: dict[str, object]) -> None:
        if not self._enforce_package_firewall_rate_limit("repair", payload):
            return

        entitlement = self._supply_chain_entitlement()
        context = self._supply_chain_context(payload)
        current_status = package_shim_status(context)
        if not package_firewall_operation_allowed(
            entitlement,
            "repair",
            has_installed_managers=bool(current_status.get("installed_managers")),
        ):
            status, error_code, message = package_firewall_block_details(entitlement)
            self._write_json(
                {
                    "entitlement": entitlement,
                    "error": error_code,
                    "message": message,
                    "operation": "repair_all",
                },
                status=status,
            )
            return
        try:
            require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="supply_chain_firewall",
                approval_gate_input=approval_gate_input_from_mapping(payload),
            )
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return

        result = coordinate_supply_chain_repair(
            repair_package_shims=lambda: _repair_detected_package_shims(
                context,
                install_missing=bool(entitlement.get("allowed")),
            ),
            activate_runtime=lambda: _activate_package_firewall_runtime(context),
            sync_intelligence=lambda: repair_sync_intelligence(
                self.server.store,  # type: ignore[attr-defined]
                workspace_dir=context.workspace_dir,
            ),
        )
        receipt = self._record_headless_receipt(
            harness="package-firewall",
            operation="repair_all",
            payload=payload,
            result=result,
            workspace_id=self._optional_string(payload.get("workspace_id"))
            or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
        )
        self._write_json(
            {
                "entitlement": entitlement,
                "operation": "repair_all",
                "receipt": receipt,
                "result": result,
                "status": "completed" if result["repaired"] is True else "incomplete",
            }
        )

    def _handle_supply_chain_package_firewall_action(self, action: str, payload: dict[str, object]) -> None:
        if action == "connect":
            self._handle_supply_chain_package_firewall_connect()
            return
        operation = "remove" if action == "uninstall" else action
        if operation == "open-shell":
            operation = "activate"
        if not self._enforce_package_firewall_rate_limit(operation, payload):
            return
        entitlement = self._supply_chain_entitlement()
        try:
            context = self._supply_chain_context(
                payload,
                reject_invalid_explicit=operation == "audit",
            )
        except ValueError as error:
            self._write_json(self._supply_chain_value_error_payload(operation, str(error)), status=400)
            return
        current_status = package_shim_status(context)
        if not package_firewall_operation_allowed(
            entitlement,
            operation,
            has_installed_managers=bool(current_status.get("installed_managers")),
        ):
            status, error_code, message = package_firewall_block_details(entitlement)
            self._write_json(
                {
                    "available_actions": package_firewall_available_actions(
                        entitlement,
                        has_installed_managers=bool(current_status.get("installed_managers")),
                    ),
                    "entitlement": entitlement,
                    "error": error_code,
                    "message": message,
                    "operation": operation,
                },
                status=status,
            )
            return
        managers, manager_error = self._supply_chain_managers(payload)
        if manager_error is not None:
            self._write_json({"error": manager_error, "operation": operation}, status=400)
            return
        try:
            if operation in {"install", "repair", "remove", "test", "sync"}:
                require_high_risk(
                    self.server.store.guard_home,  # type: ignore[attr-defined]
                    purpose="supply_chain_firewall",
                    approval_gate_input=approval_gate_input_from_mapping(payload),
                )
            if operation == "activate":
                status, response = _activate_package_firewall_runtime(context)
                self._write_json(response, status=status)
                return
            result = self._run_supply_chain_package_action(operation, context, managers)
        except ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
        except ValueError as error:
            self._write_json(self._supply_chain_value_error_payload(operation, str(error)), status=400)
            return
        except Exception as error:
            status, error_payload = _headless_failure(
                partial(
                    native_supply_chain_error,
                    operation,
                    error,
                    guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
                )
            )
            self._write_json(error_payload, status=status)
            return
        receipt_overrides = package_firewall_receipt_metadata(
            operation=operation,
            result=result,
            managers=managers,
            workspace_dir=context.workspace_dir,
            store=self.server.store,  # type: ignore[attr-defined]
        )
        scanner_evidence = receipt_overrides.get("scanner_evidence")
        receipt = self._record_headless_receipt(
            harness="package-firewall",
            operation=operation,
            payload=payload,
            result=result,
            workspace_id=self._optional_string(payload.get("workspace_id"))
            or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
            policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
            capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
            artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
            scanner_evidence_extra=scanner_evidence if _is_string_object_dict(scanner_evidence) else None,
        )
        response_status = "completed"
        if operation == "audit":
            audit_status = result.get("audit_status")
            if audit_status == "incomplete":
                response_status = "incomplete"
        response_payload: dict[str, object] = {
            "entitlement": entitlement,
            "operation": operation,
            "receipt": receipt,
            "result": result,
            "status": response_status,
        }
        if operation == "audit":
            cloud_sync = _queue_headless_cloud_sync_with_optional_publish(
                store=self.server.store,
                managed_controls_publish=_managed_controls_publish_for(self.server),
            )
            receipt["cloud_sync"] = cloud_sync
            response_payload["cloud_sync"] = cloud_sync
        self._write_json(response_payload)

    def _run_supply_chain_package_action(
        self,
        operation: str,
        context: HarnessContext,
        managers: tuple[str, ...] | None,
    ) -> dict[str, object]:
        store = self.server.store  # type: ignore[attr-defined]
        if operation == "install":
            return activate_package_shims(context, managers=managers)
        if operation == "repair":
            return activate_package_shims(context, managers=managers, repair=True)
        if operation == "remove":
            return uninstall_package_shims(context, managers=managers)
        if operation == "test":
            return probe_package_shim_intercepts(
                context,
                managers=managers,
                workspace_dir=context.workspace_dir,
                project_shell_profile=True,
            )
        if operation == "audit":
            if context.workspace_dir is None:
                raise ValueError("workspace_dir_required")
            config = load_guard_config(store.guard_home)
            now = datetime.now(timezone.utc).isoformat()
            audit_payload, exit_code = build_workspace_audit_payload(
                command_name="audit",
                config=config,
                now=now,
                sbom_paths=(),
                store=store,
                workspace_dir=context.workspace_dir,
            )
            audit_payload["exit_code"] = exit_code
            if exit_code == 0:
                record_package_shim_audit_result(context, audited_at=now)
            return audit_payload
        if operation == "sync":
            return _sync_supply_chain_cloud_state_with_optional_auth_context(
                self.server.store,  # type: ignore[attr-defined]
                None,
                workspace_dir=context.workspace_dir,
            )
        raise ValueError("unsupported_supply_chain_operation")

    def _handle_supply_chain_choose_folder(self) -> None:
        try:
            selected = choose_project_folder()
        except ProjectFolderPickerBusyError:
            self._write_json(
                {
                    "error": "folder_picker_busy",
                    "message": "A folder selection is already open.",
                    "operation": "choose-folder",
                },
                status=409,
            )
            return
        except ProjectFolderPickerUnavailableError:
            self._write_json(
                {
                    "error": "folder_picker_unavailable",
                    "message": "Folder selection is unavailable. Paste a project folder path instead.",
                    "operation": "choose-folder",
                },
                status=503,
            )
            return
        if selected is None:
            self._write_json({"cancelled": True, "operation": "choose-folder", "workspace_dir": None})
            return
        try:
            resolved = self._resolve_supply_chain_workspace_dir(
                {"workspace_dir": selected},
                reject_invalid_explicit=True,
            )
        except ValueError as error:
            self._write_json(self._supply_chain_value_error_payload("choose-folder", str(error)), status=400)
            return
        if resolved is None:
            self._write_json(
                self._supply_chain_value_error_payload("choose-folder", "workspace_dir_invalid"),
                status=400,
            )
            return
        self._write_json(
            {
                "cancelled": False,
                "operation": "choose-folder",
                "workspace_dir": str(resolved),
            }
        )

    def _resolve_supply_chain_workspace_dir(
        self,
        payload: dict[str, object],
        *,
        reject_invalid_explicit: bool = False,
    ) -> Path | None:
        allowed_roots = (
            Path.home().resolve(),
            Path.cwd().resolve(),
            Path(tempfile.gettempdir()).resolve(),
        )
        managed_workspace_dirs = managed_install_audit_workspace_dirs(self.server.store)  # type: ignore[attr-defined]
        return resolve_supply_chain_audit_workspace_dir(
            workspace_dir_value=payload.get("workspace_dir"),
            workspace_value=payload.get("workspace"),
            allowed_roots=allowed_roots,
            managed_workspace_dirs=managed_workspace_dirs,
            reject_invalid_explicit=reject_invalid_explicit,
        )

    def _supply_chain_context(
        self,
        payload: dict[str, object],
        *,
        reject_invalid_explicit: bool = False,
    ) -> HarnessContext:
        workspace_dir = self._resolve_supply_chain_workspace_dir(
            payload,
            reject_invalid_explicit=reject_invalid_explicit,
        )
        return HarnessContext(
            home_dir=Path.home().resolve(),
            workspace_dir=workspace_dir,
            guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
        )

    @staticmethod
    def _supply_chain_value_error_payload(operation: str, error_code: str) -> dict[str, object]:
        error_payload: dict[str, object] = {"error": error_code, "operation": operation}
        if error_code == "workspace_dir_required":
            error_payload["message"] = (
                "Guard needs a project folder with package manifests before it can run the workspace audit. "
                "Choose a local project folder and try again."
            )
        elif error_code == "workspace_dir_invalid":
            error_payload["message"] = (
                "Guard could not use the selected project folder. Choose an existing local folder and try again."
            )
        return error_payload

    @staticmethod
    def _supply_chain_managers(payload: dict[str, object]) -> tuple[tuple[str, ...] | None, str | None]:
        managers_value = payload.get("managers")
        if managers_value is None:
            return None, None
        if not isinstance(managers_value, list) or not all(isinstance(manager, str) for manager in managers_value):
            return None, "invalid_managers"
        supported = set(package_shim_supported_managers())
        normalized = [manager.strip().lower() for manager in managers_value if manager.strip()]
        if len(normalized) != len(set(normalized)):
            return None, "duplicate_manager"
        managers = tuple(normalized)
        if not managers:
            return None, "invalid_managers"
        if not set(managers).issubset(supported):
            return None, "unsupported_manager"
        return managers, None

    def _supply_chain_entitlement(self) -> dict[str, object]:
        server = self.server  # type: ignore[attr-defined]
        with server.guard_cloud_browser_session_lock:
            cloud_connect = _copy_guard_cloud_connect_state(server)
            package_connect = _copy_package_firewall_connect_state(server)
            if _guard_cloud_connect_state_is_in_flight(cloud_connect) or _guard_cloud_connect_state_is_in_flight(
                package_connect
            ):
                return resolve_package_firewall_entitlement(server.store)
            return resolve_package_firewall_entitlement_with_refresh(server.store)

    def _handle_get_supply_chain_bundle(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        workspace_id = store.get_cloud_workspace_id()
        wrapper = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id is not None else None
        bundle = wrapper.get("bundle") if isinstance(wrapper, dict) else None
        self._write_json({"bundle": bundle})

    def _supply_chain_connect_flow(self, entitlement: dict[str, object]) -> dict[str, object] | None:
        return _resolve_package_firewall_connect_flow(server=self.server, entitlement=entitlement)  # type: ignore[arg-type]

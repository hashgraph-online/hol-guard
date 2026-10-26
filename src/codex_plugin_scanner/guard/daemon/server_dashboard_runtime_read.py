"""Dashboard runtime, inventory and settings read routes for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import time
from urllib.parse import ParseResult

from ..approvals import build_runtime_snapshot
from ..cli.install_commands import list_harness_setup_items
from ..cli.update_commands import build_guard_update_status_payload
from ..config import editable_guard_settings, load_guard_config
from ..models import format_local_http_origin
from ..native_daemon_handler import native_events_cursor
from ..runtime.network_status import build_network_status
from ..store import GuardStore
from .command_activity_health_repair import auto_repair_command_activity_health_if_degraded
from .dashboard_update import merge_dashboard_update_progress
from .extension_control_api import ExtensionControlApiError
from .harness_version_api import attach_version_compatibility
from .local_cli_http import handle_local_cli_list
from .plugin_updates_http import handle_plugin_updates_read
from .server_common import _now, _ServerProxy, _settings_export_payload, _settings_response_payload
from .server_control_cloud_sync import _managed_controls_publish_for, _maybe_queue_first_cloud_sync
from .workspace_assessment_api import handle_workspace_assessment_get

m = _ServerProxy()


class _DashboardRuntimeReadRoutes:
    def _serve_dashboard_runtime_read(self, parsed: ParseResult, path_parts: list[str], store: GuardStore) -> bool:
        """Serve a dashboard read route; return True when the route was handled."""
        if parsed.path == "/v1/extension-controls/catalog":
            try:
                catalog = self._daemon_server().extension_control_api.catalog()
            except ExtensionControlApiError as error:
                self._write_json(error.to_payload(), status=error.status)
                return True
            self._write_json(catalog, extra_headers={"Cache-Control": "no-store"})
            return True
        if parsed.path == "/v1/extension-controls/effective":
            try:
                effective = self._daemon_server().extension_control_api.effective()
            except ExtensionControlApiError as error:
                self._write_json(error.to_payload(), status=error.status)
                return True
            self._write_json(effective, extra_headers={"Cache-Control": "no-store"})
            return True
        if parsed.path == "/v1/extension-controls/history":
            try:
                history = self._daemon_server().extension_control_api.history()
            except ExtensionControlApiError as error:
                self._write_json(error.to_payload(), status=error.status)
                return True
            self._write_json(history, extra_headers={"Cache-Control": "no-store"})
            return True
        if parsed.path == "/v1/local-clis":
            handle_local_cli_list(self, parsed.query)
            return True
        if parsed.path == "/v1/capabilities":
            self._handle_capabilities()
            return True
        if parsed.path == "/v1/network/status":
            self._write_json(
                build_network_status(
                    supervisor_health=self._daemon_server().network_supervisor.health(
                        now_epoch_ms=int(time.time() * 1000)
                    )
                ),
                extra_headers={"Cache-Control": "no-store"},
            )
            return True
        if parsed.path == "/v1/runtime/containment-health":
            self._write_json(
                {"containment_health": self._containment_health_payload(force_refresh=True)},
                extra_headers={"Cache-Control": "no-store"},
            )
            return True
        if parsed.path == "/v1/sessions":
            self._write_json({"items": store.list_guard_sessions(limit=200)})
            return True
        if parsed.path == "/v1/runtime":
            _maybe_queue_first_cloud_sync(
                store=store,
                managed_controls_publish=_managed_controls_publish_for(self._daemon_server()),
            )
            auto_repair_command_activity_health_if_degraded(store)
            config = load_guard_config(store.guard_home)
            daemon_server = self._daemon_server()
            include_receipts = self._query_bool(parsed.query, "include_receipts", default=True)
            snapshot = build_runtime_snapshot(
                store=store,
                approval_center_url=format_local_http_origin(
                    daemon_server.daemon_host(),
                    daemon_server.daemon_port(),
                ),
                active_request_id=self._query_string(parsed.query, "active_request_id"),
                include_items=self._query_bool(parsed.query, "include_items", default=True),
                receipt_limit=25 if include_receipts else 0,
                containment_health=self._containment_health_payload(),
                serving_runtime={
                    "session_id": daemon_server.runtime_session_id,
                    "daemon_host": daemon_server.runtime_host,
                    "daemon_port": daemon_server.daemon_port(),
                    "started_at": daemon_server.runtime_started_at,
                    "last_heartbeat_at": _now(),
                },
            )
            self._write_json(
                {
                    **snapshot,
                    "security_level": config.security_level,
                    "operator_health": self._operator_health_payload(),
                }
            )
            return True
        if parsed.path == "/v1/harnesses":
            context = self._harness_context({})
            items = list_harness_setup_items(context, self.server.store)  # type: ignore[attr-defined]
            self._write_json({"items": attach_version_compatibility(items, context)})
            return True
        if parsed.path == "/v1/supply-chain/package-shims":
            self._handle_supply_chain_package_firewall_status()
            return True
        if parsed.path == "/v1/cloud/connect":
            self._handle_guard_cloud_connect_status()
            return True
        if parsed.path == "/v1/supply-chain/entitlement":
            self._write_json(self._supply_chain_entitlement())
            return True
        if parsed.path == "/v1/supply-chain/bundle":
            self._handle_get_supply_chain_bundle()
            return True
        if handle_workspace_assessment_get(self, parsed.path, parsed.query):
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "apps"] and path_parts[3] == "cloud":
            self._handle_cloud_app_handoff(path_parts[2], parsed.query)
            return True
        if parsed.path == "/v1/inventory":
            from ..adapters.contracts import HARNESS_CONTRACTS

            inventory_items = store.list_inventory()
            installed_harnesses = {str(item.get("harness", "")) for item in inventory_items}
            from ..protection_capabilities import capability_for

            contracts_index: dict[str, dict[str, object]] = {}
            for contract in HARNESS_CONTRACTS:
                payload: dict[str, object] = {
                    "install_aliases": list(contract.install_aliases),
                    "event_surfaces": list(contract.event_surfaces),
                    "native_approval": contract.native_approval,
                    "browser_fallback": contract.browser_fallback,
                    "resume_support": contract.resume_support,
                    "known_blind_spots": contract.known_blind_spots,
                }
                capability = capability_for(contract.harness)
                if capability is not None:
                    payload.update(capability.to_dict())
                contracts_index[contract.harness] = payload
            enriched: list[dict[str, object]] = []
            for item in inventory_items:
                harness_name = str(item.get("harness", ""))
                contract = contracts_index.get(harness_name, {})
                enriched.append({**item, "contract": contract})
            uninstalled = [
                {
                    "harness": c.harness,
                    "status": "unknown",
                    "contract": contracts_index[c.harness],
                }
                for c in HARNESS_CONTRACTS
                if c.harness not in installed_harnesses
            ]
            self._write_json({"items": enriched, "available": uninstalled})
            return True
        if parsed.path == "/v1/settings/export":
            config = load_guard_config(store.guard_home)
            self._write_json(_settings_export_payload(config))
            return True
        if parsed.path == "/v1/settings":
            from ..config import maybe_auto_revert_watch

            config = maybe_auto_revert_watch(store.guard_home)
            self._write_json(_settings_response_payload(store.guard_home, editable_guard_settings(config)))
            return True
        if parsed.path == "/v1/cloud-review":
            from .cloud_review_settings import cloud_review_settings_status

            self._write_json(cloud_review_settings_status(store), extra_headers={"Cache-Control": "no-store"})
            return True
        if parsed.path == "/v1/plugins/updates":
            handle_plugin_updates_read(self)
            return True
        if parsed.path == "/v1/update/status":
            self._write_json(
                merge_dashboard_update_progress(
                    store.guard_home,
                    build_guard_update_status_payload(guard_home=store.guard_home),
                ),
                extra_headers={"Cache-Control": "no-store, max-age=0"},
            )
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "sessions"] and path_parts[3] == "resume":
            self._handle_session_resume(path_parts[2])
            return True
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "resume":
            if not self._header_token_is_valid():
                self._write_json(
                    {"error": "unauthorized"},
                    status=401,
                    extra_headers=self._cors_headers_for_request(),
                )
                return True
            self._handle_request_resume_read(path_parts[2])
            return True
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "operations"]:
            operation = store.get_guard_operation(path_parts[2])
            if operation is None:
                self._write_json({"error": "not_found"}, status=404)
                return True
            self._write_json(operation)
            return True
        if len(path_parts) == 4 and path_parts[:3] == ["v1", "mcp-policy", "requests"]:
            self._handle_mcp_policy_request_get(path_parts[3])
            return True
        if parsed.path == "/v1/events":
            cursor_decision = self._native_handler_decision(
                lambda: native_events_cursor(parsed.query, guard_home=store.guard_home)
            )
            if cursor_decision is None:
                return True
            self._write_json({"items": store.list_events_after(cursor_decision.fields["cursor"], limit=200)})
            return True
        return False

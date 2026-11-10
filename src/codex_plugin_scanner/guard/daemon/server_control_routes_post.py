"""Control-plane POST routes the native daemon still hands to Python."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

from typing import Any

_AUDIT_REMEDIATION_ACTIONS = {"package_shim_path"}


_SUPPLY_CHAIN_PACKAGE_ACTIONS = {
    "activate",
    "install",
    "repair",
    "test",
    "audit",
    "sync",
    "remove",
    "uninstall",
    "connect",
    "open-shell",
}


class _ControlPostRoutes:
    """Control-plane route dispatch for the daemon handler."""

    def _dispatch_control_post(self, parsed: Any, path_parts: list[str], payload: dict[str, Any], route: Any) -> None:
        del route
        if parsed.path == "/v1/supply-chain/repair":
            self._run_package_firewall_mutation("repair_all", lambda: self._handle_supply_chain_repair(payload))
            return
        if parsed.path == "/v1/cloud/connect":
            self._handle_guard_cloud_connect_start()
            return
        if parsed.path == "/v1/update":
            self._handle_dashboard_update(payload)
            return
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "audit", "remediations"]
            and path_parts[3] in _AUDIT_REMEDIATION_ACTIONS
        ):
            self._handle_audit_remediation(path_parts[3], payload)
            return
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "supply-chain", "package-shims"]
            and path_parts[3] in _SUPPLY_CHAIN_PACKAGE_ACTIONS
        ):
            action = path_parts[3]

            def handle_package_action() -> None:
                self._handle_supply_chain_package_firewall_action(action, payload)

            if action in {"install", "repair", "uninstall", "remove", "activate", "open-shell", "sync"}:
                self._run_package_firewall_mutation(action, handle_package_action)
            else:
                handle_package_action()
            return
        if parsed.path == "/v1/supply-chain/choose-folder":
            self._handle_supply_chain_choose_folder()
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "supply-chain"] and path_parts[2] in {"audit", "sync"}:
            action = path_parts[2]
            if action == "sync":
                self._run_package_firewall_mutation(
                    action,
                    lambda: self._handle_supply_chain_package_firewall_action(action, payload),
                )
            else:
                self._handle_supply_chain_package_firewall_action(action, payload)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"]:
            self._handle_headless_app_action(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "live-decision":
            self._handle_codex_live_decision(path_parts[2], payload)
            return
        self.send_response(404)
        self.end_headers()

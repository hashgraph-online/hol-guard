"""Control-plane POST routes the native daemon still hands to Python."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

from typing import Any

_AUDIT_REMEDIATION_ACTIONS = {"package_shim_path"}


class _ControlPostRoutes:
    """Control-plane route dispatch for the daemon handler."""

    def _dispatch_control_post(self, parsed: Any, path_parts: list[str], payload: dict[str, Any], route: Any) -> None:
        del route
        if (
            len(path_parts) == 4
            and path_parts[:3] == ["v1", "audit", "remediations"]
            and path_parts[3] in _AUDIT_REMEDIATION_ACTIONS
        ):
            self._handle_audit_remediation(path_parts[3], payload)
            return
        if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"]:
            self._handle_headless_app_action(path_parts[2], payload)
            return
        if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "live-decision":
            self._handle_codex_live_decision(path_parts[2], payload)
            return
        self.send_response(404)
        self.end_headers()

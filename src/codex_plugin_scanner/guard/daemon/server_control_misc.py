"""Harness, notification, insights and read-state route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..approval_gate import (
    ApprovalGateError,
)
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    uninstall_confirmation_token,
)
from ..cli.update_commands import build_guard_update_status_payload
from ..cloud_exception_requests import (
    CloudExceptionRequestError,
    fetch_cloud_exception_requests,
    submit_cloud_exception_request,
)
from ..desktop_notifications import (
    desktop_notification_setup_payload,
    ensure_desktop_notification_setup,
    macos_notification_guidance,
)
from ..harness_disconnect_gate import require_harness_disconnect_gate
from ..insights_share import publish_insights_share
from ..native_daemon_handler import (
    native_harness_action,
)
from .dashboard_update import schedule_guard_dashboard_update
from .server_common import (
    _LOGGER,
    _build_local_url,
    _now,
)


class _ControlMiscRoutes:
    """Handler methods for control-plane routes."""

    def _harness_context(self, payload: dict[str, object]) -> HarnessContext:
        del payload
        return HarnessContext(
            home_dir=Path.home().resolve(),
            workspace_dir=None,
            guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
        )

    def _handle_harness_action(self, harness: str, action: str, payload: dict[str, object]) -> None:
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        verdict = self._native_handler_decision(lambda: native_harness_action(action, payload, guard_home=guard_home))
        if verdict is None:
            return
        context = self._harness_context(payload)
        if action == "verify":
            try:
                self._write_json(build_harness_verification(harness, context, self.server.store))  # type: ignore[attr-defined]
            except ValueError as error:
                self._write_json({"error": str(error)}, status=404)
            return
        dry_run = verdict.fields["dry_run"]
        try:
            adapter = get_adapter(harness)
        except ValueError as error:
            self._write_json({"error": str(error)}, status=404)
            return
        if action == "uninstall":
            expected_confirmation = uninstall_confirmation_token(adapter.harness)
            confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
                payload.get("confirmation_token")
            )
            if confirmation != expected_confirmation:
                self._write_json(
                    {
                        "error": "confirmation_required",
                        "harness": adapter.harness,
                        "confirmation_phrase": expected_confirmation,
                        "confirm_command": (
                            f"hol-guard apps disconnect {adapter.harness} --confirm {expected_confirmation}"
                        ),
                    },
                    status=400,
                )
                return
        if dry_run:
            self._write_json(build_harness_setup_plan(action, adapter.harness, context, dry_run=True))
            return
        if action == "uninstall":
            try:
                require_harness_disconnect_gate(
                    self.server.store.guard_home,  # type: ignore[attr-defined]
                    payload,
                    harness=adapter.harness,
                )
            except ApprovalGateError as error:
                self._write_approval_gate_error(error)
                return
        install_command = "uninstall" if action == "uninstall" else "install"
        try:
            result = apply_managed_install(
                install_command,
                adapter.harness,
                False,
                context,
                self.server.store,  # type: ignore[attr-defined]
                str(context.workspace_dir) if context.workspace_dir is not None else None,
                _now(),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        except RuntimeError:
            _LOGGER.exception("Guard could not complete %s repair for %s", action, adapter.harness)
            self._write_json(
                {
                    "error": "harness_repair_failed",
                    "harness": adapter.harness,
                    "message": (
                        f"Guard could not repair {adapter.harness} protection. "
                        "Open this app's repair details and retry that protection layer. "
                        "Your existing protection settings were preserved."
                    ),
                },
                status=409,
            )
            return
        self._write_json({"harness": adapter.harness, "action": action, "dry_run": False, **result})

    def _handle_notification_setup(self, payload: dict[str, object]) -> None:
        del payload
        host = self._daemon_server().daemon_host()
        port = self._daemon_server().daemon_port()
        approval_url = _build_local_url(host, port, "/approvals/notification-preview")
        try:
            result = ensure_desktop_notification_setup(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                approval_url=approval_url,
                force=True,
            )
        except Exception as error:
            self._write_json({"error": str(error)}, status=500)
            return
        guidance = macos_notification_guidance(result.notifier_path) if result.platform == "Darwin" else None
        self._write_json(desktop_notification_setup_payload(result, guidance=guidance))

    def _handle_insights_share_publish(self, payload: dict[str, object]) -> None:
        include_top_artifacts = self._optional_bool(payload.get("includeTopArtifacts"), default=False)
        show_display_name = self._optional_bool(payload.get("showDisplayName"), default=False)
        display_name_value = payload.get("displayName")
        display_name = display_name_value.strip()[:120] if isinstance(display_name_value, str) else None
        store = self.server.store  # type: ignore[attr-defined]
        try:
            result = publish_insights_share(
                store,
                include_top_artifacts=include_top_artifacts,
                show_display_name=show_display_name,
                display_name=display_name,
            )
        except Exception as error:
            message = str(error).strip() or "Unable to publish Guard insights share."
            self._write_json({"error": "insights_share_failed", "message": message}, status=502)
            return
        self._write_json(result)

    def _handle_cloud_exception_request_list(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        try:
            result = fetch_cloud_exception_requests(store)
        except CloudExceptionRequestError as error:
            message = str(error).strip() or "Unable to load Guard Cloud exception requests."
            self._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=error.status)
            return
        except Exception as error:
            message = str(error).strip() or "Unable to load Guard Cloud exception requests."
            self._write_json({"error": "cloud_exception_request_list_failed", "message": message}, status=502)
            return
        self._write_json(result)

    def _handle_cloud_exception_request_create(self, payload: dict[str, object]) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        try:
            result = submit_cloud_exception_request(store, payload)
        except ValueError as error:
            message = str(error).strip() or "Invalid Guard exception request payload."
            self._write_json({"error": "invalid_payload", "message": message}, status=400)
            return
        except CloudExceptionRequestError as error:
            message = str(error).strip() or "Unable to create Guard Cloud exception request."
            self._write_json({"error": "cloud_exception_request_failed", "message": message}, status=error.status)
            return
        except Exception as error:
            message = str(error).strip() or "Unable to create Guard Cloud exception request."
            self._write_json({"error": "cloud_exception_request_failed", "message": message}, status=502)
            return
        self._write_json(result)

    def _handle_read_state_update(self, payload: dict[str, object]) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        action = str(payload.get("action") or "mark_read")
        if action == "mark_all_read":
            request_ids = payload.get("request_ids")
            if not isinstance(request_ids, list):
                self._write_json({"error": "invalid_request_ids"}, status=400)
                return
            store.mark_requests_read([str(rid) for rid in request_ids if isinstance(rid, str)])
            self._write_json({"ok": True, "ids": store.get_read_state()})
            return
        if action == "mark_unread":
            request_id = payload.get("request_id")
            if not isinstance(request_id, str):
                self._write_json({"error": "invalid_request_id"}, status=400)
                return
            store.mark_request_unread(request_id)
            self._write_json({"ok": True, "ids": store.get_read_state()})
            return
        request_id = payload.get("request_id")
        if isinstance(request_id, str):
            store.mark_requests_read([request_id])
            self._write_json({"ok": True, "ids": store.get_read_state()})
            return
        self._write_json({"error": "invalid_action"}, status=400)

    def _read_delete_body(self) -> dict[str, object] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > self._MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _handle_dashboard_update(self, payload: dict[str, object]) -> None:
        force_pypi_reinstall = bool(payload.get("force_pypi_reinstall"))
        guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
        status_payload = build_guard_update_status_payload(guard_home=guard_home)
        if status_payload.get("python_update_required") is True:
            self._write_json(
                {
                    "error": "update_not_supported",
                    "message": status_payload.get("blocked_reason") or "Update requires a different Python runtime.",
                },
                status=400,
            )
            return
        recovery_reinstall_available = bool(status_payload.get("recovery_reinstall_available"))
        if force_pypi_reinstall and not recovery_reinstall_available:
            self._write_json(
                {
                    "error": "update_not_supported",
                    "message": status_payload.get("blocked_reason") or "Reinstall is not available for this install.",
                },
                status=400,
            )
            return
        if status_payload.get("auto_updatable") is not True and not force_pypi_reinstall:
            self._write_json(
                {
                    "error": "update_not_supported",
                    "message": status_payload.get("blocked_reason") or "Automatic update is not available.",
                },
                status=400,
            )
            return
        if status_payload.get("update_available") is not True and not force_pypi_reinstall:
            self._write_json(
                {
                    "error": "update_not_available",
                    "message": "Guard is already on the latest version.",
                },
                status=400,
            )
            return
        self._write_json(
            schedule_guard_dashboard_update(
                guard_home,
                daemon_pid=os.getpid(),
                daemon_port=self._daemon_server().daemon_port(),
                force_pypi_reinstall=force_pypi_reinstall,
                include_alpha=status_payload.get("release_channel") == "alpha",
                status_payload=status_payload,
            )
        )

    def _handle_cloud_review_settings(self, payload: dict[str, object]) -> None:
        from .cloud_review_settings_route import handle_cloud_review_settings

        lifecycle = self.server.command_queue_lifecycle  # type: ignore[attr-defined]
        handle_cloud_review_settings(
            self.server.store,
            payload,
            refresh_workers=lifecycle.refresh_command_queue_worker if lifecycle is not None else None,
            write_json=self._write_json,
            write_approval_gate_error=self._write_approval_gate_error,
        )

    def _handle_command_queue_worker_refresh(self) -> None:
        lifecycle = self.server.command_queue_lifecycle  # type: ignore[attr-defined]
        if lifecycle is None:
            self._write_json({"error": "command_queue_lifecycle_unavailable"}, status=503)
            return
        self._write_json(
            lifecycle.refresh_command_queue_worker(),
            extra_headers={"Cache-Control": "no-store"},
        )

    def _enforce_package_firewall_rate_limit(
        self,
        operation: str,
        payload: dict[str, object],
    ) -> bool:
        workspace_id = (
            self._optional_string(payload.get("workspace_id"))
            or self._optional_string(payload.get("workspaceId"))
            or self.server.store.get_cloud_workspace_id()  # type: ignore[attr-defined]
            or "local"
        )
        rate_key = f"{workspace_id}:{operation}"
        allowed, retry_after = self.server.package_firewall_action_rate_limiter.allow(rate_key)  # type: ignore[attr-defined]
        if allowed:
            return True
        self._write_json(
            {
                "error": "rate_limited",
                "message": "Package firewall actions are temporarily rate limited.",
                "operation": operation,
                "retry_after_seconds": retry_after,
            },
            status=429,
        )
        return False

    def _run_package_firewall_mutation(self, operation: str, action: Callable[[], None]) -> None:
        lock = self.server.package_firewall_mutation_lock  # type: ignore[attr-defined]
        if not lock.acquire(blocking=False):
            self._write_json(
                {
                    "error": "operation_in_progress",
                    "message": (
                        "Guard is still finishing a package protection change. Check its status before retrying."
                    ),
                    "operation": operation,
                },
                status=409,
            )
            return
        try:
            action()
        finally:
            lock.release()

"""Harness, notification, insights and read-state route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

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
from ..harness_versions.service import invalidate as invalidate_harness_versions
from ..insights_share import publish_insights_share
from ..native_daemon_handler import (
    native_harness_action,
)
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
        # A reinstall or repair may change which harness build is in use.
        invalidate_harness_versions(context.guard_home, adapter.harness)
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

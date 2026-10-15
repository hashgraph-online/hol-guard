"""Cloud connect and dashboard reconnect route handlers for the daemon."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import os
import platform
import threading
import time
import uuid

from ...version import __version__
from ..browser_opener import open_browser_url
from ..cli.connect_flow import (
    start_guard_browser_session,
)
from ..cli.connect_sync_result import (
    failed_browser_connect_flow_state,
)
from ..package_firewall_entitlement import (
    resolve_package_firewall_entitlement,
)
from ..runtime.runner import (
    prepare_guard_cloud_connect_authorization,
)
from .dashboard_reconnect import (
    DASHBOARD_RECONNECT_PROTOCOL_VERSION,
    consume_dashboard_reconnect_challenge,
    dashboard_reconnect_challenge_identity,
    issue_dashboard_reconnect_challenge,
    prepare_dashboard_reconnect_authorization,
)
from .discovery import (
    load_authenticated_daemon_state,
)
from .server_common import (
    _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
    _is_string_object_dict,
)
from .server_control_cloud_sync import (
    _managed_controls_publish_for,
)
from .server_control_connect_flow import (
    _complete_browser_oauth_connect,
)
from .server_control_connect_state import (
    _begin_guard_cloud_connect_state,
    _begin_package_firewall_connect_state,
    _default_guard_cloud_connect_flow,
    _default_package_firewall_connect_flow,
    _guard_cloud_connect_repair_mode,
    _guard_cloud_connect_required_for_insights,
    _guard_cloud_connect_succeeded,
    _package_firewall_connect_action_label,
    _package_firewall_connect_needs_repair,
    _package_firewall_connect_url,
    _resolve_guard_cloud_connect_flow,
    _set_guard_cloud_connect_state,
    _set_package_firewall_connect_state,
)


class _CloudConnectRoutes:
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

    def _handle_supply_chain_package_firewall_connect(self) -> None:
        entitlement = self._supply_chain_entitlement()
        reason = str(entitlement.get("reason") or "").strip().lower()
        if reason not in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
            self._write_json(
                {
                    "error": "guard_cloud_connect_not_required",
                    "entitlement": entitlement,
                    "message": "Guard Cloud connect is not required for package firewall on this machine.",
                },
                status=409,
            )
            return
        store = self.server.store  # type: ignore[attr-defined]
        connect_url = _package_firewall_connect_url(store)
        action_label = _package_firewall_connect_action_label(
            reason,
            repair_copy=_package_firewall_connect_needs_repair(store, reason),
        )
        request_id = f"guard-connect-{uuid.uuid4().hex}"
        starting_state = {
            **_default_package_firewall_connect_flow(store=store, reason=reason),
            "state": "starting",
            "title": "Opening Guard Cloud sign-in",
            "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
            "action_label": action_label,
            "authorize_url": None,
            "browser_opened": None,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        started, current = _begin_package_firewall_connect_state(  # type: ignore[arg-type]
            self.server,
            starting_state,
        )
        if not started:
            self._write_json(current, status=202)
            return
        try:
            prepare_guard_cloud_connect_authorization(store)
            device = store.get_device_metadata()
            session = start_guard_browser_session(
                connect_url=connect_url,
                machine_id=str(device["installation_id"]),
                machine_label=str(device["device_label"]),
            )
            browser_opened = open_browser_url(session.authorize_url)
        except Exception as error:
            failure = {
                **_default_package_firewall_connect_flow(store=store, reason=reason),
                "state": "failed",
                "detail": str(error),
                "browser_opened": False,
                "poll_after_ms": None,
            }
            _set_package_firewall_connect_state(self.server, failure)  # type: ignore[arg-type]
            self._write_json(failure, status=500)
            return

        running_state = {
            **_default_package_firewall_connect_flow(store=store, reason=reason),
            "state": "running",
            "title": "Finish Guard Cloud sign-in in your browser",
            "detail": (
                "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this page will "
                "unlock package-firewall controls automatically."
                if browser_opened
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            ),
            "action_label": action_label,
            "authorize_url": session.authorize_url,
            "browser_opened": browser_opened,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        _set_package_firewall_connect_state(self.server, running_state)  # type: ignore[arg-type]

        def _complete_connect() -> None:
            try:
                payload = _complete_browser_oauth_connect(
                    store=store,
                    session=session,
                    connect_url=connect_url,
                    browser_opened=browser_opened,
                    managed_controls_publish=_managed_controls_publish_for(self.server),
                )
                resolved_entitlement = resolve_package_firewall_entitlement(store)
                resolved_reason = str(resolved_entitlement.get("reason") or "")
                if bool(resolved_entitlement.get("allowed")) or resolved_reason == "paid_guard_cloud_required":
                    _set_package_firewall_connect_state(self.server, None)  # type: ignore[arg-type]
                    return
                repair_message = str(
                    payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
                )
                _set_package_firewall_connect_state(  # type: ignore[arg-type]
                    self.server,
                    failed_browser_connect_flow_state(running_state, detail=repair_message),
                )
            except Exception as error:
                _set_package_firewall_connect_state(  # type: ignore[arg-type]
                    self.server,
                    failed_browser_connect_flow_state(running_state, detail=str(error)),
                )
            finally:
                session.close()

        threading.Thread(
            target=_complete_connect,
            daemon=True,
            name="guard-package-firewall-connect",
        ).start()
        self._write_json(running_state, status=202)

    def _handle_guard_cloud_connect_status(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        connect_flow = _resolve_guard_cloud_connect_flow(server=self.server, store=store)  # type: ignore[arg-type]
        self._write_json(
            {
                "connect_required": connect_flow is not None,
                "connect_flow": connect_flow,
                "dashboard_url": _package_firewall_connect_url(store).removesuffix("/connect"),
            }
        )

    def _handle_guard_cloud_connect_start(self) -> None:
        store = self.server.store  # type: ignore[attr-defined]
        if not _guard_cloud_connect_required_for_insights(store):
            self._write_json(
                {
                    "error": "guard_cloud_connect_not_required",
                    "connect_required": False,
                    "connect_flow": None,
                    "dashboard_url": _package_firewall_connect_url(store).removesuffix("/connect"),
                    "message": "Guard Cloud connect is not required to publish insights from this machine.",
                },
                status=409,
            )
            return
        repair_mode = _guard_cloud_connect_repair_mode(store)
        connect_url = _package_firewall_connect_url(store)
        action_label = "Repair Guard Cloud access" if repair_mode else "Connect Guard Cloud"
        request_id = f"guard-connect-{uuid.uuid4().hex}"
        starting_state = {
            **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
            "state": "starting",
            "title": "Opening Guard Cloud sign-in",
            "detail": "HOL Guard is opening the secure sign-in flow in your browser.",
            "action_label": action_label,
            "authorize_url": None,
            "browser_opened": None,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        started, current = _begin_guard_cloud_connect_state(self.server, starting_state)  # type: ignore[arg-type]
        if not started:
            self._write_json({"connect_required": True, "connect_flow": current}, status=202)
            return
        try:
            prepare_guard_cloud_connect_authorization(store)
            device = store.get_device_metadata()
            session = start_guard_browser_session(
                connect_url=connect_url,
                machine_id=str(device["installation_id"]),
                machine_label=str(device["device_label"]),
            )
            browser_opened = open_browser_url(session.authorize_url)
        except Exception as error:
            failure = {
                **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
                "state": "failed",
                "detail": str(error),
                "browser_opened": False,
                "poll_after_ms": None,
            }
            _set_guard_cloud_connect_state(self.server, failure)  # type: ignore[arg-type]
            self._write_json(
                {"connect_required": True, "connect_flow": failure, "message": str(error)},
                status=500,
            )
            return

        running_state = {
            **_default_guard_cloud_connect_flow(store=store, repair_mode=repair_mode),
            "state": "running",
            "title": "Finish Guard Cloud sign-in in your browser",
            "detail": (
                "HOL Guard opened the secure sign-in flow in your browser. Finish sign-in there and this modal will "
                "unlock public sharing automatically."
                if browser_opened
                else (
                    "HOL Guard is waiting for browser approval. Open the sign-in page below if your browser did "
                    "not open automatically."
                )
            ),
            "action_label": action_label,
            "authorize_url": session.authorize_url,
            "browser_opened": browser_opened,
            "request_id": request_id,
            "poll_after_ms": _SUPPLY_CHAIN_CONNECT_POLL_AFTER_MS,
        }
        _set_guard_cloud_connect_state(self.server, running_state)  # type: ignore[arg-type]

        def _complete_connect() -> None:
            try:
                payload = _complete_browser_oauth_connect(
                    store=store,
                    session=session,
                    connect_url=connect_url,
                    browser_opened=browser_opened,
                    managed_controls_publish=_managed_controls_publish_for(self.server),
                )
                if _guard_cloud_connect_succeeded(store):
                    _set_guard_cloud_connect_state(self.server, None)  # type: ignore[arg-type]
                    return
                repair_message = str(
                    payload.get("repair_message") or payload.get("sync_error") or "Guard Cloud connect did not finish."
                )
                _set_guard_cloud_connect_state(  # type: ignore[arg-type]
                    self.server,
                    failed_browser_connect_flow_state(running_state, detail=repair_message),
                )
            except Exception as error:
                _set_guard_cloud_connect_state(  # type: ignore[arg-type]
                    self.server,
                    failed_browser_connect_flow_state(running_state, detail=str(error)),
                )
            finally:
                session.close()

        threading.Thread(
            target=_complete_connect,
            daemon=True,
            name="guard-cloud-connect",
        ).start()
        self._write_json({"connect_required": True, "connect_flow": running_state}, status=202)

    def _handle_dashboard_reconnect_prepare(self) -> None:
        daemon_server = self._daemon_server()
        try:
            with daemon_server.dashboard_reconnect_lock:
                authorization = prepare_dashboard_reconnect_authorization(daemon_server.store.guard_home)
        except (OSError, RuntimeError):
            self._write_json(
                {
                    "error": "dashboard_reconnect_unavailable",
                    "reason_code": "dashboard_reconnect_identity_unavailable",
                },
                status=503,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        self._write_json(authorization, extra_headers={"Cache-Control": "no-store"})

    def _handle_dashboard_reconnect_challenge(self, payload: dict[str, object]) -> None:
        if payload.get("protocol_version") != DASHBOARD_RECONNECT_PROTOCOL_VERSION:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_protocol_mismatch")
            return
        candidate_origin = self._strict_loopback_origin(payload.get("candidate_origin"))
        daemon_origin = self._dashboard_reconnect_daemon_origin()
        if candidate_origin is None or daemon_origin is None or candidate_origin != daemon_origin:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_origin_mismatch")
            return
        state = self._current_authenticated_daemon_state()
        state_id = self._optional_string(state.get("state_id")) if state is not None else None
        if state_id is None:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_state_unavailable")
            return
        daemon_server = self._daemon_server()
        with daemon_server.dashboard_reconnect_lock:
            challenge, reason_code = issue_dashboard_reconnect_challenge(
                daemon_server.store.guard_home,
                reconnect_id=payload.get("reconnect_id"),
                client_nonce=payload.get("client_nonce"),
                candidate_origin=candidate_origin,
                state_id=state_id,
            )
        if challenge is None:
            self._write_dashboard_reconnect_candidate_failure(reason_code)
            return
        self._write_json(challenge, extra_headers={"Cache-Control": "no-store"})

    def _handle_dashboard_reconnect_verify(self, payload: dict[str, object]) -> None:
        if payload.get("protocol_version") != DASHBOARD_RECONNECT_PROTOCOL_VERSION:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_protocol_mismatch")
            return
        raw_challenge = payload.get("challenge")
        if not isinstance(raw_challenge, dict) or not _is_string_object_dict(raw_challenge):
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_malformed_proof")
            return
        candidate_origin = self._strict_loopback_origin(raw_challenge.get("candidate_origin"))
        daemon_origin = self._dashboard_reconnect_daemon_origin()
        state = self._current_authenticated_daemon_state()
        state_id = self._optional_string(state.get("state_id")) if state is not None else None
        if candidate_origin is None or daemon_origin is None or candidate_origin != daemon_origin or state_id is None:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_proof_context_mismatch")
            return
        daemon_server = self._daemon_server()
        challenge_identity = dashboard_reconnect_challenge_identity(raw_challenge)
        if challenge_identity is None:
            self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_malformed_proof")
            return
        now_ms = int(time.time() * 1000)
        with daemon_server.dashboard_reconnect_lock:
            expired_challenges = [
                identity
                for identity, expires_at_ms in daemon_server.dashboard_reconnect_consumed_challenges.items()
                if expires_at_ms < now_ms
            ]
            for identity in expired_challenges:
                daemon_server.dashboard_reconnect_consumed_challenges.pop(identity, None)
            if challenge_identity in daemon_server.dashboard_reconnect_consumed_challenges:
                self._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_proof_replayed")
                return
            verified, reason_code = consume_dashboard_reconnect_challenge(
                daemon_server.store.guard_home,
                challenge=raw_challenge,
                proof=payload.get("proof"),
                expected_candidate_origin=daemon_origin,
                expected_state_id=state_id,
            )
            if verified:
                expires_at_ms = raw_challenge.get("expires_at_ms")
                daemon_server.dashboard_reconnect_consumed_challenges[challenge_identity] = (
                    expires_at_ms if isinstance(expires_at_ms, int) else now_ms
                )
                while len(daemon_server.dashboard_reconnect_consumed_challenges) > 256:
                    oldest = next(iter(daemon_server.dashboard_reconnect_consumed_challenges))
                    daemon_server.dashboard_reconnect_consumed_challenges.pop(oldest, None)
        if not verified:
            self._write_dashboard_reconnect_candidate_failure(reason_code)
            return
        self._write_json(
            {"verified": True, "reason_code": reason_code},
            extra_headers={"Cache-Control": "no-store"},
        )

    def _write_dashboard_reconnect_candidate_failure(self, reason_code: str) -> None:
        self._write_json(
            {"error": "daemon_candidate_unavailable", "reason_code": reason_code},
            status=404,
            extra_headers={"Cache-Control": "no-store"},
        )

    def _current_authenticated_daemon_state(self) -> dict[str, object] | None:
        daemon_server = self._daemon_server()
        state = load_authenticated_daemon_state(daemon_server.store.guard_home)
        if state is None:
            return None
        expected_guard_home = str(daemon_server.store.guard_home.resolve())
        if (
            state.get("guard_home") != expected_guard_home
            or state.get("host") != daemon_server.daemon_host()
            or state.get("port") != daemon_server.daemon_port()
            or state.get("pid") != os.getpid()
            or state.get("state_id") != daemon_server.runtime_session_id
        ):
            return None
        return state

    def _dashboard_reconnect_daemon_origin(self) -> str | None:
        daemon_server = self._daemon_server()
        host = daemon_server.daemon_host()
        if host == "127.0.0.1":
            return f"http://127.0.0.1:{daemon_server.daemon_port()}"
        if host == "::1":
            return f"http://[::1]:{daemon_server.daemon_port()}"
        return None

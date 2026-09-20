"""Runtime health, event streams, and origin checks."""

from __future__ import annotations

from . import server as _server


def _touch_runtime_heartbeat(self: _server._GuardDaemonHandler, path: str) -> None:
    if path != "/healthz" and not path.startswith("/v1/"):
        return
    self.server.last_activity_monotonic = _server.time.monotonic()  # type: ignore[attr-defined]
    self._daemon_server().runtime_heartbeat.touch(_server._now())


def _increment_active_stream_clients(self: _server._GuardDaemonHandler) -> None:
    with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
        self.server.active_stream_clients += 1  # type: ignore[attr-defined]


def _try_increment_active_stream_clients(self: _server._GuardDaemonHandler, maximum: int) -> bool:
    with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
        if self.server.active_stream_clients >= maximum:  # type: ignore[attr-defined]
            return False
        self.server.active_stream_clients += 1  # type: ignore[attr-defined]
        return True


def _decrement_active_stream_clients(self: _server._GuardDaemonHandler) -> None:
    with self.server.active_stream_clients_lock:  # type: ignore[attr-defined]
        self.server.active_stream_clients = max(0, self.server.active_stream_clients - 1)  # type: ignore[attr-defined]


def _optional_int(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _stream_events(self: _server._GuardDaemonHandler, cursor: int) -> None:
    self.send_response(200)
    self.send_header("Content-Type", "text/event-stream")
    self.send_header("Cache-Control", "no-cache")
    self.send_header("Connection", "keep-alive")
    self.end_headers()
    next_cursor = cursor
    self._increment_active_stream_clients()
    try:
        while True:
            self._touch_runtime_heartbeat("/v1/events/stream")
            items = self.server.store.list_events_after(next_cursor, limit=100)  # type: ignore[attr-defined]
            for item in items:
                event_id = item.get("event_id")
                if not isinstance(event_id, int):
                    continue
                next_cursor = event_id
                body = _server.json.dumps(item)
                try:
                    self.wfile.write(f"data: {body}\n\n".encode())
                    self.wfile.flush()
                except BrokenPipeError:
                    return
            _server.time.sleep(0.5)
    finally:
        self._decrement_active_stream_clients()


def _origin_is_allowed_for_request(self: _server._GuardDaemonHandler, path: str, path_parts: list[str]) -> bool:
    origin = self.headers.get("Origin")
    if origin is None:
        return True
    normalized_origin = self._normalize_origin(origin)
    if normalized_origin is None:
        return False
    parsed = _server.urlparse(normalized_origin)
    local_origin = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if local_origin:
        return True
    return normalized_origin in _server._HOSTED_GUARD_DASHBOARD_ORIGINS and self._is_hosted_dashboard_api_path(
        path, path_parts
    )


def _is_hosted_dashboard_api_path(path: str, path_parts: list[str]) -> bool:
    if path in {
        "/v1/capabilities",
        "/v1/connect/complete",
        "/v1/inventory",
        "/v1/connect/state",
        "/v1/daemon/repair",
        "/v1/evidence",
        "/v1/evidence/export",
        "/v1/command-activity",
        "/v1/command-activity/analytics",
        "/v1/command-activity/diagnostics",
        "/v1/command-activity/events",
        "/v1/command-activity/feedback",
        "/v1/command-extensions",
        "/v1/extension-controls/catalog",
        "/v1/extension-controls/effective",
        "/v1/extension-controls/history",
        "/v1/extension-controls/preview",
        "/v1/extension-controls/test",
        "/v1/extension-controls/apply",
        "/v1/extension-controls/refresh",
        "/v1/extension-controls/recover-authority",
        "/v1/extension-controls/acknowledge-degraded",
        "/v1/local-clis",
        *_server._LOCAL_CLI_PATHS,
        "/v1/harnesses",
        "/v1/notifications/setup",
        "/v1/policy",
        "/v1/policy/cloud-exceptions",
        "/v1/policy/cloud-exception-requests",
        "/v1/policy/clear",
        "/v1/receipts",
        "/v1/receipts/analytics",
        "/v1/insights/share",
        "/v1/cloud/connect",
        "/v1/supply-chain/package-shims/connect",
        "/v1/supply-chain/package-shims/activate",
        "/v1/receipts/latest",
        "/v1/runtime",
        "/v1/settings",
        "/v1/settings/export",
        "/v1/settings/import",
        "/v1/settings/reset",
        "/v1/read-state",
        "/v1/update",
        "/v1/update/channel",
        "/v1/update/reconnect/challenge",
        "/v1/update/reconnect/prepare",
        "/v1/update/reconnect/verify",
        "/v1/update/status",
    }:
        return True
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "receipts"]:
        return True
    if len(path_parts) == 4 and path_parts[:3] == ["v1", "audit", "remediations"]:
        return True
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "approvals"] and path_parts[3] == "decision":
        return True
    if (
        len(path_parts) == 5
        and path_parts[:2] == ["v1", "apps"]
        and path_parts[3] == "cloud"
        and path_parts[4] == "start"
    ):
        return True
    if (
        len(path_parts) == 4
        and path_parts[:2] == ["v1", "harnesses"]
        and path_parts[3]
        in {
            "install",
            "verify",
            "repair",
            "uninstall",
        }
    ):
        return True
    return len(path_parts) == 4 and path_parts[:2] == ["v1", "artifacts"] and path_parts[3] == "diff"


def _is_hosted_dashboard_origin(self: _server._GuardDaemonHandler) -> bool:
    origin = self._normalize_origin(self.headers.get("Origin"))
    return origin in _server._HOSTED_GUARD_DASHBOARD_ORIGINS


def _public_healthz_payload(self: _server._GuardDaemonHandler) -> dict[str, object]:
    return {
        "ok": True,
        "compatibility_version": _server.GUARD_DAEMON_COMPATIBILITY_VERSION,
    }


def _containment_health_payload(
    self: _server._GuardDaemonHandler, *, force_refresh: bool = False
) -> dict[str, object] | None:
    from ..runtime.containment_health import probe_containment_health

    server = self._daemon_server()
    with server.containment_health_cache_lock:
        age = _server.time.monotonic() - server.containment_health_cache_monotonic
        if not force_refresh and server.containment_health_cache is not None and age <= 10.0:
            return dict(server.containment_health_cache)
        try:
            payload = probe_containment_health(
                daemon_fingerprint=_server.current_guard_daemon_runtime_fingerprint(),
            ).to_dict()
        except (OSError, RuntimeError, TypeError, ValueError):
            server.containment_health_cache = None
            server.containment_health_cache_monotonic = _server.time.monotonic()
            return None
        server.containment_health_cache = payload
        server.containment_health_cache_monotonic = _server.time.monotonic()
        return dict(payload)


def _detailed_healthz_payload(self: _server._GuardDaemonHandler) -> dict[str, object]:
    uptime = round(_server.time.monotonic() - self.server.start_monotonic, 1)  # type: ignore[attr-defined]
    daemon_server = self._daemon_server()
    store = daemon_server.store
    pending_approvals = store.count_approval_requests()
    activity_health = store.get_command_activity_persistence_health()
    scheduler_stats = daemon_server.runtime_hook_scheduler.stats()
    process_scheduler_stats = daemon_server.runtime_hook_process_scheduler.stats()
    evidence_writer_stats = daemon_server.runtime_hook_evidence_writer.stats()
    sqlite_profile = store.sqlite_profile()
    sqlite_migration_gate = store.sqlite_migration_gate_report()
    with daemon_server.hook_capacity_lock:
        hook_capacity = {
            "active": scheduler_stats["active"],
            "limit": scheduler_stats["active_limit"],
            "queued": scheduler_stats["queued"],
            "queued_limit": scheduler_stats["queued_limit"],
            "retained_bytes": scheduler_stats["retained_bytes"],
            "retained_bytes_limit": scheduler_stats["retained_bytes_limit"],
            "per_harness_active": scheduler_stats["per_harness_active"],
            "per_harness_queued": scheduler_stats["per_harness_queued"],
            "per_harness_rejected": dict(daemon_server.hook_harness_rejected),
            "rejected": daemon_server.rejected_hook_requests,
            "expired": scheduler_stats["expired"],
            "cancelled": scheduler_stats["cancelled"],
            "retries": scheduler_stats["retries"],
            "completed": scheduler_stats["completed"],
            "oldest_queued_ms": scheduler_stats["oldest_queued_ms"],
            "queue_wait_by_lane_p95_ms": scheduler_stats["queue_wait_by_lane_p95_ms"],
            "service_time_by_lane_p95_ms": scheduler_stats["service_time_by_lane_p95_ms"],
            "queue_wait_by_lane_p99_ms": scheduler_stats["queue_wait_by_lane_p99_ms"],
            "service_time_by_lane_p99_ms": scheduler_stats["service_time_by_lane_p99_ms"],
            "rejection_reasons": scheduler_stats["rejected"],
        }
    with daemon_server.request_capacity_lock:
        request_capacity = {
            "active": daemon_server.active_requests,
            "connection_limit": daemon_server.connection_capacity_limit,
            "control_limit": daemon_server.control_request_capacity_limit,
            "critical_limit": daemon_server.critical_request_capacity_limit,
            "limit": daemon_server.request_capacity_limit,
            "rejected": daemon_server.rejected_requests,
        }
    if evidence_writer_stats["failures"] and evidence_writer_stats["queued"]:
        load_state = "store-contended"
        load_detail = "Evidence persistence is retrying outside the security decision path."
    elif scheduler_stats["expired"] or process_scheduler_stats["expired"] or daemon_server.rejected_hook_requests:
        load_state = "saturated"
        load_detail = "Secure review capacity was exhausted; recovery is automatic as load falls."
    elif scheduler_stats["queued"] or process_scheduler_stats["queued"]:
        load_state = "backlogged"
        load_detail = "Queued reviews are draining automatically."
    else:
        load_state = "healthy"
        load_detail = "Review capacity is available."
    return {
        "ok": True,
        "receipts": len(store.list_receipts(limit=500)),
        "approvals": pending_approvals,
        "pending_approvals": pending_approvals,
        "hook_evidence_writer": evidence_writer_stats,
        "sqlite_profile": sqlite_profile,
        "sqlite_migration_gate": sqlite_migration_gate,
        "uptime_seconds": uptime,
        "pid": _server.os.getpid(),
        "tables": store.list_table_names(),
        "compatibility_version": _server.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": _server.__version__,
        "runtime_fingerprint": _server.current_guard_daemon_runtime_fingerprint(),
        "guard_home": str(store.guard_home.resolve()),
        "command_activity_evidence": {
            "state": "degraded" if activity_health.persistence_error_count else "healthy",
            "dropped_event_count": activity_health.dropped_event_count,
            "persistence_error_count": activity_health.persistence_error_count,
            "last_error_code": activity_health.last_error_code,
            "last_error_at": (
                activity_health.last_error_at.isoformat() if activity_health.last_error_at is not None else None
            ),
            "schema_version": activity_health.schema_version,
        },
        "network_protection": _server.project_network_supervisor_health(
            daemon_server.network_supervisor.health(now_epoch_ms=int(_server.time.time() * 1000))
        ),
        "hook_capacity": hook_capacity,
        "hook_load": {
            "state": load_state,
            "detail": load_detail,
        },
        "hook_process_capacity": process_scheduler_stats,
        "hook_workers": daemon_server.hook_process_runner.stats(),
        "request_capacity": request_capacity,
    }


def _operator_health_payload(self: _server._GuardDaemonHandler) -> dict[str, object]:
    daemon_server = self._daemon_server()
    scheduler = daemon_server.runtime_hook_scheduler.stats()
    workers = daemon_server.hook_process_runner.stats()
    evidence_writer = daemon_server.runtime_hook_evidence_writer.stats()
    activity_health = daemon_server.store.get_command_activity_persistence_health()
    worker_fault = workers["configured"] > 0 and workers["workers"] == 0
    evidence_fault = not evidence_writer["running"]
    store_busy = (
        activity_health.persistence_error_count > 0
        and activity_health.last_error_code is not None
        and activity_health.last_error_code.startswith("sqlite.")
    )
    saturated = scheduler["queued_limit"] > 0 and scheduler["queued"] >= scheduler["queued_limit"]

    if worker_fault or evidence_fault:
        state = "saturated"
        cause = "A local processing component stopped and needs repair."
    elif store_busy:
        state = "store-contended"
        cause = "The local evidence store is busy; queued writes are retrying automatically."
    elif saturated:
        state = "saturated"
        cause = "Local review capacity is full; new work waits or receives a typed retry."
    elif scheduler["queued"] > 0:
        state = "backlogged"
        cause = "A short local backlog is waiting behind active reviews."
    else:
        state = "healthy"
        cause = "Local reviews are processing within available capacity."

    repairable = worker_fault or evidence_fault
    return {
        "state": state,
        "cause": cause,
        "automatic_recovery": (
            "Repair restores the stopped local component."
            if repairable
            else "Guard drains queued work and adjusts ready workers automatically."
        ),
        "repairable": repairable,
        "queue_depth": scheduler["queued"],
        "queue_limit": scheduler["queued_limit"],
        "oldest_wait_ms": scheduler["oldest_queued_ms"],
        "workers_busy": workers["busy"],
        "workers_ready": workers["ready"],
        "workers_configured": workers["configured"],
    }


def _normalize_origin(origin: str | None) -> str | None:
    if not isinstance(origin, str) or not origin.strip():
        return None
    parsed = _server.urlparse(origin.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return None
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 80 if parsed.scheme == "http" else 443
    try:
        port = parsed.port
    except ValueError:
        return None
    port_suffix = f":{port}" if port not in {None, default_port} else ""
    return f"{parsed.scheme}://{host}{port_suffix}"


def _cors_headers(
    origin: str,
    *,
    allow_methods: str = "POST, OPTIONS",
    allow_headers: str = "Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token",
) -> dict[str, str]:
    return {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": allow_methods,
        "Access-Control-Allow-Headers": allow_headers,
        "Access-Control-Allow-Private-Network": "true",
        "Vary": "Origin",
    }


def _cors_headers_for_request(
    self: _server._GuardDaemonHandler,
    *,
    allow_methods: str = "POST, OPTIONS",
    allow_headers: str = "Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token",
) -> dict[str, str] | None:
    parsed = _server.urlparse(self.path)
    path_parts = [part for part in parsed.path.split("/") if part]
    origin = self._normalize_origin(self.headers.get("Origin"))
    if origin is None or not self._origin_is_allowed_for_request(parsed.path, path_parts):
        return None
    return self._cors_headers(origin, allow_methods=allow_methods, allow_headers=allow_headers)

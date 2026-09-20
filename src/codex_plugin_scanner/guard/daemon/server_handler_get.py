"""GET route dispatch."""

from __future__ import annotations

from . import server as _server


def do_GET(self: _server._GuardDaemonHandler) -> None:  # noqa: N802 - HTTP dispatch contract
    store = self.server.store  # type: ignore[attr-defined]
    parsed = _server.urlparse(self.path)
    self._touch_runtime_heartbeat(parsed.path)
    path_parts = [part for part in parsed.path.split("/") if part]
    if not self._origin_is_allowed_for_request(parsed.path, path_parts):
        self._write_json({"error": "forbidden_origin"}, status=403)
        return
    if parsed.path == "/healthz":
        self._write_json(self._public_healthz_payload())
        return
    if parsed.path == "/v1/healthz/details":
        if not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        self._write_json(self._detailed_healthz_payload())
        return
    if parsed.path == "/v1/events/stream":
        if self._query_has_guard_token(parsed.query):
            self._record_query_token_rejection()
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        self._stream_events(_server._int_query_value(parsed.query, "cursor"))
        return
    if parsed.path == "/v1/command-activity/events":
        if self._query_has_guard_token(parsed.query):
            self._record_query_token_rejection()
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        if not self._header_token_is_valid():
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
            return
        try:
            cursor = _server.parse_command_activity_event_cursor(
                parsed.query,
                last_event_id=self.headers.get("Last-Event-ID"),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        _server.stream_command_activity_events(self, cursor)
        return
    if parsed.path.startswith("/v1/") and not self._header_token_is_valid():
        self._write_unauthorized(extra_headers=self._cors_headers_for_request())
        return
    if parsed.path == "/v1/extension-controls/catalog":
        try:
            catalog = self._daemon_server().extension_control_api.catalog()
        except _server.ExtensionControlApiError as error:
            self._write_json(error.to_payload(), status=error.status)
            return
        self._write_json(catalog, extra_headers={"Cache-Control": "no-store"})
        return
    if parsed.path == "/v1/extension-controls/effective":
        self._write_json(
            self._daemon_server().extension_control_api.effective(),
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    if parsed.path == "/v1/extension-controls/history":
        try:
            history = self._daemon_server().extension_control_api.history()
        except _server.ExtensionControlApiError as error:
            self._write_json(error.to_payload(), status=error.status)
            return
        self._write_json(history, extra_headers={"Cache-Control": "no-store"})
        return
    if parsed.path == "/v1/local-clis":
        _server.handle_local_cli_list(self)
        return
    if parsed.path == "/v1/capabilities":
        self._handle_capabilities()
        return
    if parsed.path == "/v1/network/status":
        self._write_json(
            _server.build_network_status(
                supervisor_health=self._daemon_server().network_supervisor.health(
                    now_epoch_ms=int(_server.time.time() * 1000)
                )
            ),
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    if parsed.path == "/v1/runtime/containment-health":
        self._write_json(
            {"containment_health": self._containment_health_payload(force_refresh=True)},
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    if parsed.path == "/v1/sessions":
        self._write_json({"items": store.list_guard_sessions(limit=200)})
        return
    if parsed.path == "/v1/runtime":
        _server._maybe_queue_first_cloud_sync(
            store=store,
            managed_controls_publish=_server._managed_controls_publish_for(self._daemon_server()),
        )
        config = _server.load_guard_config(store.guard_home, config_reader=self._daemon_server().hook_config_reader)
        include_receipts = self._query_bool(parsed.query, "include_receipts", default=True)
        snapshot = _server.build_runtime_snapshot(
            store=store,
            approval_center_url=_server.format_local_http_origin(
                self._daemon_server().daemon_host(),
                self._daemon_server().daemon_port(),
            ),
            active_request_id=self._query_string(parsed.query, "active_request_id"),
            include_items=self._query_bool(parsed.query, "include_items", default=True),
            receipt_limit=25 if include_receipts else 0,
            containment_health=self._containment_health_payload(),
        )
        self._write_json(
            {
                **snapshot,
                "security_level": config.security_level,
                "operator_health": self._operator_health_payload(),
            }
        )
        return
    if parsed.path == "/v1/harnesses":
        context = self._harness_context({})
        self._write_json({"items": _server.list_harness_setup_items(context, self.server.store)})  # type: ignore[attr-defined]
        return
    if parsed.path == "/v1/supply-chain/package-shims":
        self._handle_supply_chain_package_firewall_status()
        return
    if parsed.path == "/v1/cloud/connect":
        self._handle_guard_cloud_connect_status()
        return
    if parsed.path == "/v1/supply-chain/entitlement":
        self._write_json(self._supply_chain_entitlement())
        return
    if parsed.path == "/v1/supply-chain/bundle":
        self._handle_get_supply_chain_bundle()
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "apps"] and path_parts[3] == "cloud":
        self._handle_cloud_app_handoff(path_parts[2], parsed.query)
        return
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
        return
    if parsed.path == "/v1/settings/export":
        config = _server.load_guard_config(store.guard_home, config_reader=self._daemon_server().hook_config_reader)
        self._write_json(_server._settings_export_payload(config))
        return
    if parsed.path == "/v1/settings":
        from ..config import maybe_auto_revert_watch

        config = maybe_auto_revert_watch(store.guard_home)
        self._write_json(_server._settings_response_payload(store.guard_home, _server.editable_guard_settings(config)))
        return
    if parsed.path == "/v1/cloud-review":
        from .cloud_review_settings import cloud_review_settings_status

        self._write_json(cloud_review_settings_status(store), extra_headers={"Cache-Control": "no-store"})
        return
    if parsed.path == "/v1/update/status":
        self._write_json(
            _server.merge_dashboard_update_progress(
                store.guard_home,
                _server.build_guard_update_status_payload(guard_home=store.guard_home),
            ),
            extra_headers={"Cache-Control": "no-store, max-age=0"},
        )
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "sessions"] and path_parts[3] == "resume":
        self._handle_session_resume(path_parts[2])
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "resume":
        if not self._header_token_is_valid():
            self._write_json(
                {"error": "unauthorized"},
                status=401,
                extra_headers=self._cors_headers_for_request(),
            )
            return
        self._handle_request_resume_read(path_parts[2])
        return
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "operations"]:
        operation = store.get_guard_operation(path_parts[2])
        if operation is None:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(operation)
        return
    if len(path_parts) == 4 and path_parts[:3] == ["v1", "mcp-policy", "requests"]:
        self._handle_mcp_policy_request_get(path_parts[3])
        return
    if parsed.path == "/v1/events":
        self._write_json(
            {"items": store.list_events_after(_server._int_query_value(parsed.query, "cursor"), limit=200)}
        )
        return
    if parsed.path == "/v1/requests":
        self._handle_requests_list(parsed.query)
        return
    if parsed.path == "/v1/command-activity":
        _server.handle_command_activity_list(self, parsed.query)
        return
    if parsed.path == "/v1/command-activity/analytics":
        _server.handle_command_activity_analytics(self, parsed.query)
        return
    if parsed.path == "/v1/command-activity/diagnostics":
        _server.handle_command_activity_diagnostics(self)
        return
    if parsed.path == "/v1/command-extensions":
        _server.handle_command_extensions(self, parsed.query)
        return
    if parsed.path == "/v1/connect/state":
        self._write_legacy_pairing_disabled()
        return
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "requests"]:
        approval = store.get_approval_request(path_parts[2])
        if approval is None:
            self._write_json(
                {
                    "error": "not_found",
                    "recovery": {
                        "code": "request_unknown",
                        "title": "This request is no longer waiting.",
                        "body": "The request was either already resolved or expired. You can close this tab.",
                        "queue_url": self._local_queue_url(),
                    },
                },
                status=404,
            )
            return
        self._write_json(approval)
        return
    if parsed.path == "/v1/receipts":
        query = _server.parse_qs(parsed.query)
        harness_q = query.get("harness", [None])[-1]
        limit_q = query.get("limit", ["200"])[-1]
        try:
            limit_v = min(max(int(limit_q), 1), 500)
        except (ValueError, TypeError):
            limit_v = 200
        self._write_json(
            {
                "items": store.list_receipts(
                    limit=limit_v,
                    harness=harness_q if isinstance(harness_q, str) and harness_q else None,
                )
            }
        )
        return
    if parsed.path == "/v1/receipts/analytics":
        query = _server.parse_qs(parsed.query)
        activity_days_q = query.get("activity_days", ["90"])[-1]
        trend_days_q = query.get("trend_days", ["7"])[-1]
        top_limit_q = query.get("top_limit", ["10"])[-1]
        try:
            activity_days = min(max(int(activity_days_q), 1), 366)
        except (ValueError, TypeError):
            activity_days = 90
        try:
            trend_days = min(max(int(trend_days_q), 1), activity_days)
        except (ValueError, TypeError):
            trend_days = 7
        try:
            top_limit = min(max(int(top_limit_q), 1), 50)
        except (ValueError, TypeError):
            top_limit = 10
        self._write_json(
            store.receipt_analytics(
                activity_days=activity_days,
                trend_days=trend_days,
                top_limit=top_limit,
            )
        )
        return
    if parsed.path == "/v1/receipts/latest":
        query = _server.parse_qs(parsed.query)
        harness = query.get("harness", [None])[-1]
        artifact_id = query.get("artifact_id", [None])[-1]
        if not isinstance(harness, str) or not harness or not isinstance(artifact_id, str) or not artifact_id:
            self._write_json({"error": "missing_receipt_query"}, status=400)
            return
        receipt = store.get_latest_receipt(harness, artifact_id)
        if receipt is None:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(receipt)
        return
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "receipts"]:
        receipt = store.get_receipt(path_parts[2])
        if receipt is None:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(receipt)
        return
    if parsed.path == "/v1/policy":
        query = _server.parse_qs(parsed.query)
        harness = query.get("harness", [None])[-1]
        harness_filter = harness if isinstance(harness, str) else None
        self._write_json(
            {
                "items": _server.managed_policy_rows(store, harness_filter),
                "cloud_exceptions": store.list_cloud_exceptions(harness=harness_filter),
            }
        )
        return
    if parsed.path == "/v1/policy/cloud-exceptions":
        query = _server.parse_qs(parsed.query)
        harness = query.get("harness", [None])[-1]
        harness_filter = harness if isinstance(harness, str) else None
        self._write_json({"items": store.list_cloud_exceptions(harness=harness_filter)})
        return
    if parsed.path == "/v1/policy/cloud-exception-requests":
        self._handle_cloud_exception_request_list()
        return
    if parsed.path == "/v1/evidence":
        query = _server.parse_qs(parsed.query)
        harness_q = query.get("harness", [None])[-1]
        category_q = query.get("category", [None])[-1]
        severity_q = query.get("severity", [None])[-1]
        before_q = query.get("before", [None])[-1]
        limit_q = query.get("limit", ["100"])[-1]
        try:
            limit_v = min(max(int(limit_q), 1), 500)
        except (ValueError, TypeError):
            limit_v = 100
        with store._connect() as conn:
            records = _server.list_evidence(
                conn,
                harness=harness_q if isinstance(harness_q, str) else None,
                category=category_q if isinstance(category_q, str) else None,
                severity=severity_q if isinstance(severity_q, str) else None,
                before_cursor=before_q if isinstance(before_q, str) else None,
                limit=limit_v,
                include_details=False,
            )
            total = _server.count_evidence(
                conn,
                harness=harness_q if isinstance(harness_q, str) else None,
                category=category_q if isinstance(category_q, str) else None,
                severity=severity_q if isinstance(severity_q, str) else None,
            )
        self._write_json(
            {
                "items": [_server.evidence_record_to_dict(record) for record in records],
                "total": total,
            }
        )
        return
    if parsed.path == "/v1/evidence/export":
        query = _server.parse_qs(parsed.query)
        format_q = query.get("format", ["json"])[-1]
        with store._connect() as conn:
            if format_q == "json":
                export_body = _server.export_evidence_json(conn, limit=10_000)
                content_type = "application/json"
            elif format_q == "csv":
                export_body = _server.export_evidence_csv(conn, limit=10_000)
                content_type = "text/csv; charset=utf-8"
            else:
                self._write_json({"error": "invalid_export_format"}, status=400)
                return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(export_body.encode("utf-8"))
        return
    if len(path_parts) == 4 and path_parts[:3] == ["v1", "artifacts", path_parts[2]] and path_parts[3] == "diff":
        query = _server.parse_qs(parsed.query)
        harness = query.get("harness", [None])[-1]
        if not isinstance(harness, str) or not harness:
            self._write_json({"error": "missing_harness"}, status=400)
            return
        diff = store.get_latest_diff(harness, _server.unquote(path_parts[2]))
        if diff is None:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(diff)
        return
    if parsed.path == "/v1/read-state":
        self._write_json({"ids": store.get_read_state()})
        return
    if parsed.path in _server._ROOT_STATIC_FILES:
        self._write_static_asset(parsed.path.removeprefix("/"))
        return
    if parsed.path.startswith("/assets/") or parsed.path.startswith("/brand/"):
        self._write_static_asset(parsed.path.removeprefix("/"))
        return
    if self._is_dashboard_route(parsed.path):
        self._write_dashboard_shell()
        return
    self.send_response(404)
    self.end_headers()

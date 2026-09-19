"""POST route dispatch."""

from __future__ import annotations

from . import server as _server


def do_POST(self: _server._GuardDaemonHandler) -> None:  # noqa: N802 - HTTP dispatch contract
    parsed = _server.urlparse(self.path)
    self._touch_runtime_heartbeat(parsed.path)
    path_parts = [part for part in parsed.path.split("/") if part]
    if parsed.path in {"/v1/connect/requests", "/v1/connect/complete", "/v1/connect/result"}:
        self._write_legacy_pairing_disabled()
        return
    if not self._origin_is_allowed_for_request(parsed.path, path_parts):
        self._write_json({"error": "forbidden_origin"}, status=403)
        return
    if parsed.path in _server._EXTENSION_CONTROL_PATHS | _server._LOCAL_CLI_PATHS and not self._header_token_is_valid():
        self._write_unauthorized(extra_headers=self._cors_headers_for_request())
        return
    if parsed.path in _server._EXTENSION_CONTROL_PATHS | _server._LOCAL_CLI_PATHS:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._write_json({"error": "invalid_content_length"}, status=400)
            return
        if content_length < 0 or content_length > self._MAX_BODY_BYTES:
            self._write_json({"error": "body_too_large"}, status=413)
            return
    payload, body_error = self._load_request_body()
    if body_error is not None:
        status = {
            "request_body_timeout": 408,
            "request_body_too_large": 413,
        }.get(body_error, 400)
        self._write_json({"error": body_error}, status=status)
        return
    if parsed.path == "/v1/healthz/verify":
        nonce = self._optional_string(payload.get("nonce")) if payload else None
        if not nonce:
            self._write_json({"error": "missing_nonce"}, status=400)
            return
        auth_token = self.server.auth_token  # type: ignore[attr-defined]
        daemon_port = self.server.server_address[1]  # type: ignore[attr-defined]
        # Bind the proof to this daemon's listening port so a relay attacker
        # cannot proxy the nonce to the real daemon and reuse its proof from
        # a different port. The hook includes the same port in its local HMAC.
        proof_message = f"{daemon_port}:{nonce}"
        proof = _server.hmac.new(
            auth_token.encode("utf-8"),
            proof_message.encode("utf-8"),
            _server.hashlib.sha256,
        ).hexdigest()
        self._write_json({"proof": proof})
        return
    if parsed.path == "/v1/daemon/identity-challenge":
        self._handle_daemon_identity_challenge(payload)
        return
    if parsed.path == "/v1/update/reconnect/challenge":
        self._handle_dashboard_reconnect_challenge(payload)
        return
    if parsed.path == "/v1/update/reconnect/verify":
        self._handle_dashboard_reconnect_verify(payload)
        return
    proof_authorized = _server.challenge_auth(parsed.path, payload, self._consume_codex_daemon_challenge)
    requires_token = self._requires_header_token(parsed.path, path_parts)
    if not _server.request_auth(requires_token, proof_authorized, payload, self._header_token_is_valid):
        if (
            len(path_parts) == 4
            and path_parts[:2] == ["v1", "requests"]
            and path_parts[3] in {"approve", "block", "resume"}
        ):
            host = self._daemon_server().daemon_host()
            port = self._daemon_server().daemon_port()
            reconnect_url = _server._build_local_url(host, port, "/#/reconnect")
            self._write_json(
                {
                    "error": "unauthorized",
                    "recovery": {
                        "code": "session_stale",
                        "title": "Your session with the local Guard daemon has expired.",
                        "body": "Click the link below to reconnect, then retry your approval.",
                        "reconnect_url": reconnect_url,
                    },
                },
                status=401,
                extra_headers=self._cors_headers_for_request(),
            )
        else:
            self._write_unauthorized(extra_headers=self._cors_headers_for_request())
        return
    if parsed.path in _server.CHALLENGE_HOOK_PATHS and not proof_authorized:
        self._write_json(
            {"error": "daemon_identity_required", "repair": "Run `hol-guard daemon repair`."},
            status=401,
        )
        return
    if parsed.path in _server._EXTENSION_CONTROL_PATHS:
        try:
            if parsed.path.endswith("/test"):
                response = self._daemon_server().extension_control_api.test_command(payload)
            elif parsed.path.endswith("/preview"):
                response = self._daemon_server().extension_control_api.preview(payload)
            elif parsed.path.endswith("/apply"):
                response = self._daemon_server().extension_control_api.apply(payload)
            elif parsed.path.endswith("/acknowledge-degraded"):
                response = self._daemon_server().extension_control_api.acknowledge_degraded(payload)
            elif parsed.path.endswith("/recover-authority"):
                response = self._daemon_server().extension_control_api.recover_authority(payload)
            else:
                response = self._daemon_server().extension_control_api.refresh()
        except _server.ExtensionControlApiError as error:
            self._write_json(error.to_payload(), status=error.status)
            return
        self._write_json(response, extra_headers={"Cache-Control": "no-store"})
        return
    if parsed.path in _server._LOCAL_CLI_PATHS:
        _server.handle_local_cli_post(self, parsed.path, payload)
        return
    if parsed.path == "/v1/initialize":
        self._handle_initialize(payload)
        return
    if parsed.path == "/v1/command-activity/feedback":
        _server.handle_command_activity_feedback(self, payload)
        return
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "hooks"]:
        self._handle_runtime_hook(payload, parsed.query, default_harness=path_parts[2])
        return
    if parsed.path == "/v1/clients/attach":
        self._handle_client_attach(payload)
        return
    if parsed.path == "/v1/clients/heartbeat":
        self._handle_client_heartbeat(payload)
        return
    if parsed.path == "/v1/sessions/start":
        self._handle_session_start(payload)
        return
    if parsed.path == "/v1/operations/start":
        self._handle_operation_start(payload)
        return
    if parsed.path == "/v1/operations/block":
        self._handle_operation_block(payload)
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "items":
        self._handle_operation_item(path_parts[2], payload)
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "operations"] and path_parts[3] == "status":
        self._handle_operation_status(path_parts[2], payload)
        return
    if parsed.path == "/v1/policy/decisions":
        self._handle_policy_upsert(payload)
        return
    if parsed.path == "/v1/policy/resolve":
        self._handle_policy_resolve(payload)
        return
    if parsed.path == "/v1/policy/claim":
        self._handle_policy_claim(payload)
        return
    if parsed.path == "/v1/policy/clear":
        self._handle_policy_clear(payload)
        return
    if parsed.path == "/v1/requests/clear":
        self._handle_requests_clear(payload)
        return
    if parsed.path == "/v1/requests/bulk-allow-once":
        self._handle_bulk_allow_read_once(payload)
        return
    if parsed.path == "/v1/policy/sync":
        self._handle_headless_policy_sync(payload)
        return
    if parsed.path == "/v1/policy/cloud-exception-requests":
        self._handle_cloud_exception_request_create(payload)
        return
    if parsed.path == "/v1/command-queue/worker/refresh":
        self._handle_command_queue_worker_refresh()
        return
    if parsed.path == "/v1/cloud-review":
        self._handle_cloud_review_settings(payload)
        return
    if parsed.path == "/v1/read-state":
        self._handle_read_state_update(payload)
        return
    if parsed.path == "/v1/settings":
        self._handle_settings_update(payload)
        return
    if parsed.path == "/v1/settings/import":
        self._handle_settings_import(payload)
        return
    if parsed.path == "/v1/settings/reset":
        self._handle_settings_reset(payload)
        return
    if parsed.path == "/v1/approval-gate/cooldown/revoke":
        self._handle_approval_gate_cooldown_revoke(payload)
        return
    if parsed.path == "/v1/approval-gate/totp/enroll":
        self._handle_approval_gate_totp_enroll(payload)
        return
    if parsed.path == "/v1/approval-gate/totp/verify":
        self._handle_approval_gate_totp_verify(payload)
        return
    if parsed.path == "/v1/approval-gate/totp/disable":
        self._handle_approval_gate_totp_disable(payload)
        return
    if parsed.path == "/v1/daemon/repair":
        result = _server.repair_approval_center_locator(self.server.store.guard_home)  # type: ignore[attr-defined]
        self._write_json(result)
        return
    if parsed.path == "/v1/protection/repair":
        self._handle_protection_repair(payload)
        return
    if parsed.path == "/v1/supply-chain/repair":
        self._handle_supply_chain_repair(payload)
        return
    if parsed.path == "/v1/insights/share":
        self._handle_insights_share_publish(payload)
        return
    if parsed.path == "/v1/cloud/connect":
        self._handle_guard_cloud_connect_start()
        return
    if parsed.path == "/v1/update/reconnect/prepare":
        self._handle_dashboard_reconnect_prepare()
        return
    if parsed.path == "/v1/update/channel":
        self._handle_update_channel(payload)
        return
    if parsed.path == "/v1/update":
        self._handle_dashboard_update(payload)
        return
    if parsed.path == "/v1/notifications/setup":
        self._handle_notification_setup(payload)
        return
    if (
        len(path_parts) == 4
        and path_parts[:3] == ["v1", "audit", "remediations"]
        and path_parts[3] in _server._AUDIT_REMEDIATION_ACTIONS
    ):
        self._handle_audit_remediation(path_parts[3], payload)
        return
    if (
        len(path_parts) == 4
        and path_parts[:3] == ["v1", "supply-chain", "package-shims"]
        and path_parts[3] in _server._SUPPLY_CHAIN_PACKAGE_ACTIONS
    ):
        self._handle_supply_chain_package_firewall_action(path_parts[3], payload)
        return
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "supply-chain"] and path_parts[2] in {"audit", "sync"}:
        self._handle_supply_chain_package_firewall_action(path_parts[2], payload)
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "harnesses"]:
        self._handle_harness_action(path_parts[2], path_parts[3], payload)
        return
    if len(path_parts) == 5 and path_parts[:2] == ["v1", "apps"] and path_parts[3] == "cloud":
        self._write_legacy_cloud_handoff_disabled()
        return
    if len(path_parts) == 3 and path_parts[:2] == ["v1", "apps"]:
        self._handle_headless_app_action(path_parts[2], payload)
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "resume":
        self._handle_request_resume_retry(path_parts[2])
        return
    if len(path_parts) == 4 and path_parts[:2] == ["v1", "requests"] and path_parts[3] == "live-decision":
        self._handle_codex_live_decision(path_parts[2], payload)
        return
    if len(path_parts) == 5 and path_parts[:3] == ["v1", "mcp-policy", "requests"] and path_parts[4] == "decision":
        self._handle_mcp_policy_decision(path_parts[3], payload)
        return
    request_id, action, matched = self._resolve_request_action(path_parts, payload)
    if not matched:
        self.send_response(404)
        self.end_headers()
        return
    if action is None:
        self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
        return
    if request_id is None:
        self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
        return
    scope = payload.get("scope")
    if not isinstance(scope, str) or not scope.strip():
        self._write_json({"resolved": False, "error": "missing_required_fields"}, status=400)
        return
    scope_contract_version_value = payload.get("scope_contract_version")
    if scope_contract_version_value is not None and (
        not isinstance(scope_contract_version_value, str) or not scope_contract_version_value.strip()
    ):
        self._write_json({"resolved": False, "error": "invalid_scope_contract_version"}, status=400)
        return
    scope_contract_version = (
        scope_contract_version_value.strip() if isinstance(scope_contract_version_value, str) else None
    )
    if scope_contract_version is not None and (
        not scope_contract_version.startswith(_server.APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX)
        or not scope_contract_version.removeprefix(_server.APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX).isdigit()
    ):
        self._write_json({"resolved": False, "error": "invalid_scope_contract_version"}, status=400)
        return
    scope_contract_digest_value = payload.get("scope_contract_digest")
    if scope_contract_digest_value is not None and (
        not isinstance(scope_contract_digest_value, str) or not scope_contract_digest_value.strip()
    ):
        self._write_json({"resolved": False, "error": "invalid_scope_contract_digest"}, status=400)
        return
    scope_contract_digest = (
        scope_contract_digest_value.strip() if isinstance(scope_contract_digest_value, str) else None
    )
    if scope_contract_digest is not None and (
        len(scope_contract_digest) != 64
        or any(character not in "0123456789abcdef" for character in scope_contract_digest)
    ):
        self._write_json({"resolved": False, "error": "invalid_scope_contract_digest"}, status=400)
        return
    try:
        existing_request = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
        if isinstance(existing_request, dict):
            scope_selection = _server.resolve_request_scope_selection(
                existing_request,
                action=action,
                requested_scope=scope.strip(),
                contract_version=scope_contract_version,
                contract_digest=scope_contract_digest,
            )
            if existing_request.get("status") != "pending":
                if (
                    existing_request.get("resolution_action") == action
                    and existing_request.get("resolution_scope") == scope_selection.applied_scope
                ):
                    self._write_json(
                        {
                            "resolved": True,
                            "idempotent": True,
                            "resolved_request": existing_request,
                            "requested_scope": scope_selection.requested_scope,
                            "applied_scope": scope_selection.applied_scope,
                            **_server.request_scope_contract_payload(existing_request),
                        }
                    )
                    return
                raise _server.ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
        persist_policy = self._approval_persist_policy(payload)
        updated = _server.apply_approval_resolution(
            store=self.server.store,  # type: ignore[attr-defined]
            request_id=request_id,
            action=action,
            scope=scope.strip(),
            workspace=self._optional_string(payload.get("workspace")),
            reason=self._optional_string(payload.get("reason")),
            return_queue_result=True,
            resolve_scope_matches=True,
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
            persist_policy=persist_policy,
            scope_contract_version=scope_contract_version,
            scope_contract_digest=scope_contract_digest,
            mcp_grant_target=payload.get("mcp_grant_target"),
            mcp_grant_duration=payload.get("mcp_grant_duration"),
            local_tool_grant_target=payload.get("local_tool_grant_target"),
            local_tool_grant_duration=payload.get("local_tool_grant_duration"),
        )
    except _server.ApprovalRequestNotFoundError:
        self._write_json(
            {
                "resolved": False,
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
    except _server.ApprovalRequestAlreadyResolvedError:
        resolved_request = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
        if isinstance(resolved_request, dict):
            try:
                replay_selection = _server.resolve_request_scope_selection(
                    resolved_request,
                    action=action,
                    requested_scope=scope.strip(),
                    contract_version=scope_contract_version,
                    contract_digest=scope_contract_digest,
                )
            except _server.StaleApprovalScopeContractError as error:
                self._write_stale_approval_scope_error(error)
                return
            except _server.IneligibleApprovalScopeError as error:
                self._write_ineligible_approval_scope_error(error)
                return
            except ValueError as error:
                self._write_json({"resolved": False, "error": str(error)}, status=400)
                return
            if (
                resolved_request.get("resolution_action") == action
                and resolved_request.get("resolution_scope") == replay_selection.applied_scope
            ):
                self._write_json(
                    {
                        "resolved": True,
                        "idempotent": True,
                        "resolved_request": resolved_request,
                        "requested_scope": replay_selection.requested_scope,
                        "applied_scope": replay_selection.applied_scope,
                        **_server.request_scope_contract_payload(resolved_request),
                    }
                )
                return
        self._write_json(
            {
                "resolved": False,
                "error": "already_resolved",
                "recovery": {
                    "code": "request_resolved",
                    "title": "This request has already been resolved.",
                    "body": (
                        "If the action is blocked and you believe it should be allowed, "
                        "you can re-submit from your AI assistant."
                    ),
                    "queue_url": self._local_queue_url(),
                },
            },
            status=409,
        )
        return
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error, resolved=False)
        return
    except _server.StaleApprovalScopeContractError as error:
        self._write_stale_approval_scope_error(error)
        return
    except _server.IneligibleApprovalScopeError as error:
        self._write_ineligible_approval_scope_error(error)
        return
    except ValueError as error:
        self._write_json({"resolved": False, "error": str(error)}, status=400)
        return
    normalized_scope = scope.strip()
    item = updated.get("item")
    harness_str = str(item.get("harness", "")) if isinstance(item, dict) else ""
    self.server.store.add_event(  # type: ignore[attr-defined]
        "approval_resolved",
        {"request_id": request_id, "action": action, "scope": normalized_scope, "harness": harness_str},
        _server._now(),
    )
    harness = str(updated.get("harness", ""))
    resolved_harness = harness_str or harness
    copy = _server._build_resolution_copy(action, resolved_harness)
    updated, copy = _server.apply_local_approval_continuation(
        store=self.server.store,  # type: ignore[attr-defined]
        updated=updated,
        request_id=request_id,
        action=action,
        harness=resolved_harness,
        copy=copy,
        now=_server._now,
        config_reader=self._daemon_server().hook_config_reader,
    )
    updated["copy"] = copy
    updated["retry_hint"] = copy["body"]
    self._write_json(updated)

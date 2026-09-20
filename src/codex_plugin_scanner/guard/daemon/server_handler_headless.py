"""Headless application actions and policy synchronization."""

from __future__ import annotations

from . import server as _server


def _handle_capabilities(self: _server._GuardDaemonHandler) -> None:
    context = self._harness_context({})
    items = _server.list_harness_setup_items(context, self.server.store)  # type: ignore[attr-defined]
    supported = []
    failure_reasons = _server._headless_safe_failure_reasons()
    for item in items:
        harness = item.get("harness")
        if not isinstance(harness, str):
            continue
        supported.append(
            {
                "display_name": item.get("display_name"),
                "harness": harness,
                "status": _server._headless_detection_status_to_app_status(item.get("status")),
                "command_available": bool(item.get("command_available")),
                "headless_actions": list(_server._HEADLESS_OPERATIONS[:-1]),
                "safe_failure_reasons": failure_reasons,
            }
        )
    self._write_json(
        {
            "auth_state": "dashboard_session" if self._dashboard_session_token_is_valid() else "local_token",
            "command_available": any(bool(item.get("command_available")) for item in items),
            "daemon": {
                "compatibility_version": _server.GUARD_DAEMON_COMPATIBILITY_VERSION,
                "package_version": _server.__version__,
                "platform": _server.platform.system().lower() or "unknown",
            },
            "headless_api": {
                "execution_mode": "guard_cloud_command_queue",
                "operations": list(_server._HEADLESS_OPERATIONS),
            },
            "package_firewall_api": {
                "execution_mode": "guard_cloud_command_queue",
                "operations": ["status", "connect", "install", "repair", "test", "audit", "sync", "remove"],
            },
            "safe_failure_reasons": _server._headless_safe_failure_reasons(),
            "supported_harnesses": sorted(item["harness"] for item in supported),
            "items": supported,
        }
    )


def _latest_cloud_sync_snapshot(self: _server._GuardDaemonHandler) -> dict[str, object]:
    latest_payload = self.server.store.get_sync_payload("headless_app_sync_summary")  # type: ignore[attr-defined]
    if not isinstance(latest_payload, dict):
        latest_payload = self.server.store.get_sync_payload("sync_summary")  # type: ignore[attr-defined]
    if isinstance(latest_payload, dict):
        return dict(latest_payload)
    return {}


def _headless_reconnect_payload(
    self: _server._GuardDaemonHandler,
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
        "correlation_id": str(_server.uuid.uuid4()),
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
            "daemon_version": _server.__version__,
            "hostname": _server.platform.node() or None,
            "ip_address": None,
            "private_ip_address": None,
            "public_ip_address": None,
        },
        "location_id": location_id,
        "reconciliation_status": reconciliation_status,
    }


def _headless_app_action_payload(
    self: _server._GuardDaemonHandler,
    *,
    action_path: str,
    payload: dict[str, object],
) -> tuple[int, dict[str, object]]:
    try:
        mapping = _server._HEADLESS_APP_ACTIONS[action_path]
    except KeyError:
        return _server._headless_action_error_payload(
            operation=action_path,
            error_code="unsupported_operation",
        )
    operation, harness_action = mapping
    harness = self._optional_string(payload.get("harness"))
    if harness is None:
        return _server._headless_action_error_payload(
            operation=operation,
            error_code="missing_harness",
        )
    try:
        adapter = _server.get_adapter(harness)
    except ValueError:
        return _server._headless_action_error_payload(
            operation=operation,
            error_code="unknown_harness",
        )
    try:
        surface = self._cursor_headless_surface(payload) if adapter.harness == "cursor" else None
    except ValueError:
        error_payload = _server._headless_error_payload(
            code="invalid_cursor_surface",
            message="Choose Cursor editor or CLI before retrying this local action.",
            retryable=False,
        )
        error = error_payload["error"]
        if isinstance(error, dict):
            error["app_id"] = "cursor"
            error["surface"] = self._optional_string(payload.get("surface")) or ""
        return 400, error_payload
    context = self._harness_context(payload)
    try:
        if harness_action == "verify":
            verification_action = "status" if action_path == "status" else "test"
            result = _server.build_harness_verification(
                adapter.harness,
                context,
                self.server.store,  # type: ignore[attr-defined]
                surface=surface,
                action=verification_action,
            )
        else:
            result = self._run_headless_managed_action(adapter.harness, harness_action, payload, context)
    except _server.ApprovalGateError as error:
        return error.status, error.to_payload()
    except ValueError as error:
        return _server._headless_action_error_payload(
            operation=operation,
            error_code=str(error),
        )
    location_id = self._optional_string(payload.get("location_id")) or self._optional_string(payload.get("locationId"))
    receipt = self._record_headless_receipt(
        harness=adapter.harness,
        operation=operation,
        payload=payload,
        result=result,
        location_id=location_id,
        workspace_id=self._optional_string(payload.get("workspace_id")),
        cloud_sync={"status": "pending"},
    )
    cloud_sync = _server._queue_headless_cloud_sync_with_optional_publish(
        store=self.server.store,
        managed_controls_publish=_server._managed_controls_publish_for(self.server),
    )
    receipt["cloud_sync"] = cloud_sync
    return 200, {
        "cloud_sync": cloud_sync,
        "harness": adapter.harness,
        "operation": operation,
        "result": result,
        "receipt": receipt,
        "state": _server._headless_action_state_payload(
            harness=adapter.harness,
            operation=operation,
            result=result,
            receipt=receipt,
        ),
        "reconnect": self._headless_reconnect_payload(
            cloud_sync=cloud_sync,
            location_id=location_id,
        ),
        "status": "completed",
    }


def _handle_cloud_app_handoff(self: _server._GuardDaemonHandler, harness: str, query_string: str) -> None:
    _ = (harness, query_string)
    self._write_legacy_cloud_handoff_disabled()


def _handle_headless_app_action(
    self: _server._GuardDaemonHandler, action_path: str, payload: dict[str, object]
) -> None:
    status, payload = self._headless_app_action_payload(action_path=action_path, payload=payload)
    self._write_json(payload, status=status)


def _run_headless_managed_action(
    self: _server._GuardDaemonHandler,
    harness: str,
    action: str,
    payload: dict[str, object],
    context: _server.HarnessContext,
) -> dict[str, object]:
    surface = self._cursor_headless_surface(payload) if harness == "cursor" else None
    if action == "uninstall":
        expected_confirmation = _server.uninstall_confirmation_token(harness)
        confirmation = self._optional_string(payload.get("confirmation_phrase")) or self._optional_string(
            payload.get("confirmation_token")
        )
        if confirmation != expected_confirmation:
            raise ValueError("confirmation_required")
        _server.require_harness_disconnect_gate(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            payload,
            harness=harness,
        )
    install_command = "uninstall" if action == "uninstall" else "install"
    return _server.apply_managed_install(
        install_command,
        harness,
        False,
        context,
        self.server.store,  # type: ignore[attr-defined]
        self._optional_string(payload.get("workspace_id")),
        _server._now(),
        surface=surface,
    )


def _handle_headless_policy_sync(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    harness = self._optional_string(payload.get("harness"))
    if harness is None:
        self._write_json({"error": "missing_harness"}, status=400)
        return
    try:
        adapter = _server.get_adapter(harness)
    except ValueError:
        self._write_json({"error": "unknown_harness"}, status=404)
        return
    try:
        approval_gate_grant = _server.require_high_risk(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            purpose="policy_write",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    policy_memory = self._policy_memory_payload(payload.get("policy_memory"))
    policy_bundle = self._policy_memory_payload(payload.get("policy_bundle") or payload.get("policyBundle"))
    validated_policy_bundle: dict[str, object] | None = None
    validated_policy_bundle_delivery: dict[str, object] | None = None
    managed_controls_policy: _server.ParsedManagedControlsPolicy | None = None
    managed_controls_capabilities = frozenset[str]()
    applied_bundle_hash = applied_bundle_version = _server.cast(str | None, None)
    if not policy_memory and not policy_bundle:
        self._write_json({"error": "missing_policy_memory"}, status=400)
        return
    if policy_memory:
        self._write_json({"error": "unsupported_policy_memory_contract"}, status=400)
        return
    if policy_bundle:
        validated_policy_bundle, rejection_reason, trusted_policy_bundle_keys = _server.validate_synced_policy_bundle(
            policy_bundle,
            stored_keyring=self.server.store.get_sync_payload("policy_bundle_keyring"),  # type: ignore[attr-defined]
            sync_payload=payload if isinstance(payload, dict) else None,
            supply_chain_keyring=self.server.store.get_sync_payload("supply_chain_bundle_keyring"),  # type: ignore[attr-defined]
            managed_keyring_provenance=self.server.store.get_sync_payload(  # type: ignore[attr-defined]
                _server.MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
            ),
            expected_workspace_id=self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
        )
        existing_policy_bundle, _existing_bundle_error = _server._validate_cached_policy_bundle(
            self.server.store,  # type: ignore[attr-defined]
            self.server.store.get_sync_payload("policy_bundle"),  # type: ignore[attr-defined]
        )
        if validated_policy_bundle is None:
            resolved_reason = rejection_reason or "invalid_policy_bundle"
            error_payload: dict[str, object] = {"error": resolved_reason}
            remediation = _server.policy_bundle_rejection_message(resolved_reason)
            if remediation is not None:
                error_payload["message"] = remediation
            self._write_json(error_payload, status=400)
            return
        if not _server._daemon_version_supported(validated_policy_bundle):
            self._write_json({"error": "unsupported_daemon_version"}, status=400)
            return
        if not _server.policy_bundle_is_enforceable(validated_policy_bundle):
            self._write_json(
                {
                    "error": "inactive_rollout_state",
                    "message": _server.policy_bundle_rejection_message("inactive_rollout_state"),
                },
                status=400,
            )
            return
        if _server._policy_bundle_is_version_downgrade(
            _server._policy_bundle_downgrade_reference(self.server.store, existing_policy_bundle),  # type: ignore[attr-defined]
            validated_policy_bundle,
        ):
            self._write_json({"error": "bundle_version_downgrade"}, status=400)
            return
        device_id, device_name = _server._guard_device_metadata(self.server.store)  # type: ignore[attr-defined]
        if validated_policy_bundle.get("contractVersion") == _server.POLICY_BUNDLE_V2_CONTRACT:
            (
                managed_controls_policy,
                managed_controls_capabilities,
                validated_policy_bundle_delivery,
                managed_error,
            ) = _server.daemon_managed_controls_candidate(
                store=self.server.store,  # type: ignore[attr-defined]
                payload=payload,
                policy_bundle=validated_policy_bundle,
                device_id=device_id,
            )
            if managed_error is not None:
                self._write_json({"error": managed_error}, status=400)
                return
        applied_at = _server._now()
        signed_remote_decisions = _server._build_policy_bundle_decisions(
            validated_policy_bundle,
            device_id=device_id,
            device_name=device_name,
        )
        policy_bundle_ack = _server.policy_bundle_acknowledgement_payload(
            device_id=device_id,
            device_name=device_name,
            policy_bundle=validated_policy_bundle,
            synced_at=applied_at,
            delivery=validated_policy_bundle_delivery,
        )
        cloud_exception_items = _server._policy_bundle_cloud_exception_items(
            self.server.store,  # type: ignore[attr-defined]
            sync_exceptions=[],
            policy_bundle=validated_policy_bundle,
            policy_bundle_ack=policy_bundle_ack,
            device_id=device_id,
        )
        try:
            activated, activation_rejection_reason = _server.activate_with_reason(
                self.server.store.apply_policy_bundle_authority,  # type: ignore[attr-defined]
                signed_remote_decisions,
                applied_at,
                policy_bundle=validated_policy_bundle,
                policy_bundle_keyring=_server.policy_bundle_keyring_payload(
                    trusted_policy_bundle_keys,
                    workspace_id=self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
                ),
                cloud_exceptions=cloud_exception_items,
                policy_bundle_ack=policy_bundle_ack,
                policy_bundle_checkpoint=_server._policy_bundle_acceptance_checkpoint(validated_policy_bundle),
                update_last_good=True,
                policy_bundle_last_error={},
                managed_controls_policy=managed_controls_policy,
                managed_controls_negotiated_capabilities=managed_controls_capabilities,
                managed_controls_delivery=validated_policy_bundle_delivery,
                managed_controls_publish=_server._managed_controls_publish_for(self.server),
                approval_gate_grant=approval_gate_grant,
                remote_write_authorized=True,
            )
        except (_server.ExtensionControlAuthorityError, ValueError):
            self._write_json({"error": "managed_runtime_publish_failed"}, status=503)
            return
        if activated is None:
            self._write_json({"error": activation_rejection_reason}, status=400)
            return
        receipt_redaction_level = validated_policy_bundle.get("receiptRedactionLevel")
        if (
            isinstance(receipt_redaction_level, str)
            and receipt_redaction_level in _server.VALID_RECEIPT_REDACTION_LEVELS
        ):
            _server._persist_cloud_receipt_redaction_level(
                self.server.store,  # type: ignore[attr-defined]
                level=receipt_redaction_level,
                synced_at=applied_at,
            )
        else:
            _server._reset_cloud_receipt_redaction_authority(  # type: ignore[arg-type]
                self.server.store,  # type: ignore[attr-defined]
                synced_at=applied_at,
            )
        applied_bundle_hash = str(validated_policy_bundle["bundleHash"])
        applied_bundle_version = str(validated_policy_bundle["bundleVersion"])
    self._write_json(
        {
            "bundle_hash": applied_bundle_hash,
            "bundle_version": applied_bundle_version,
            "harness": adapter.harness,
            "operation": "policy_sync",
            "status": "completed",
        }
    )

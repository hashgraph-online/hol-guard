"""Approval receipts, policy reset, and harness actions."""

from __future__ import annotations

from . import server as _server


def _policy_memory_payload(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = _server.json.loads(value)
        except _server.json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _record_headless_receipt(
    self: _server._GuardDaemonHandler,
    *,
    harness: str,
    location_id: str | None = None,
    operation: str,
    payload: dict[str, object],
    result: dict[str, object],
    workspace_id: str | None,
    cloud_sync: dict[str, object] | None = None,
    policy_decision: str | None = None,
    capabilities_summary: str | None = None,
    artifact_name: str | None = None,
    scanner_evidence_extra: dict[str, object] | None = None,
) -> dict[str, object]:
    cursor_receipt_context = self._cursor_receipt_context(
        harness=harness,
        operation=operation,
        payload=payload,
        result=result,
        cloud_sync=cloud_sync,
    )
    material = _server.json.dumps(
        {
            "harness": harness,
            "location_id": location_id,
            "operation": operation,
            "result_keys": sorted(result.keys()),
            "cursor": cursor_receipt_context,
            "workspace_id": workspace_id,
        },
        sort_keys=True,
    )
    artifact_hash = _server.stable_digest_hex(material.encode("utf-8"))
    changed_capabilities = [] if operation in {"status", "scan"} else [operation]
    artifact_id = f"headless:{harness}:{operation}"
    resolved_artifact_name = artifact_name or f"Headless {operation}"
    resolved_capabilities_summary = capabilities_summary or f"Guard local daemon completed headless {operation}."
    source_scope = "local-daemon"
    resolved_policy_decision = policy_decision or "allow"
    scanner_evidence: dict[str, object] = {
        "operation": operation,
        "location_id": location_id,
        "workspace_id": workspace_id,
        "status": "completed",
    }
    if scanner_evidence_extra is not None:
        scanner_evidence.update(scanner_evidence_extra)
    if cursor_receipt_context is not None:
        artifact_id = str(cursor_receipt_context["action_scope"])
        resolved_artifact_name = str(cursor_receipt_context["artifact_name"])
        resolved_capabilities_summary = str(cursor_receipt_context["capabilities_summary"])
        source_scope = str(cursor_receipt_context["source_scope"])
        changed_capabilities = [str(cursor_receipt_context["changed_capability"])]
        scanner_evidence.update(cursor_receipt_context["scanner_evidence"])
    receipt = _server.build_receipt(
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=resolved_policy_decision,
        capabilities_summary=resolved_capabilities_summary,
        changed_capabilities=changed_capabilities,
        provenance_summary="Guard Cloud local daemon API",
        artifact_name=resolved_artifact_name,
        source_scope=source_scope,
        scanner_evidence=(scanner_evidence,),
        approval_source="guard-cloud-headless",
    )
    self.server.store.add_receipt(receipt)  # type: ignore[attr-defined]
    summary: dict[str, object] = {
        "id": receipt.receipt_id,
        "operation": operation,
        "status": "completed",
        "timestamp": receipt.timestamp,
    }
    if cursor_receipt_context is not None:
        summary.update(cursor_receipt_context["summary"])
    return summary


def _cursor_headless_surface(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> str | None:
    surface = self._optional_string(payload.get("surface")) or self._optional_string(payload.get("editor_or_cli"))
    if surface is None:
        return None
    if surface not in {"editor", "cli"}:
        raise ValueError("invalid_cursor_surface")
    return surface


def _cursor_receipt_context(
    self: _server._GuardDaemonHandler,
    *,
    harness: str,
    operation: str,
    payload: dict[str, object],
    result: dict[str, object],
    cloud_sync: dict[str, object] | None,
) -> _server._CursorReceiptContext | None:
    if harness != "cursor":
        return None
    action_payload = result.get("cursor_action")
    action_dict = action_payload if isinstance(action_payload, dict) else {}
    surface = (
        self._optional_string(action_dict.get("surface"))
        or self._optional_string(payload.get("surface"))
        or self._optional_string(payload.get("editor_or_cli"))
        or "editor"
    )
    action = self._optional_string(action_dict.get("action")) or operation
    evidence = action_dict.get("evidence")
    evidence_dict = evidence if isinstance(evidence, dict) else {}
    action_scope = self._optional_string(evidence_dict.get("actionScope")) or f"cursor:{surface}:{action}"
    cloud_sync_status = "pending"
    if isinstance(cloud_sync, dict):
        cloud_sync_status = self._optional_string(cloud_sync.get("status")) or cloud_sync_status
    surface_label = "CLI" if surface == "cli" else "editor"
    scanner_evidence: dict[str, object] = {
        "action_scope": action_scope,
        "cloud_sync_status": cloud_sync_status,
        "cursor_status": self._optional_string(action_dict.get("status")) or "unknown",
        "editor_or_cli": surface,
        "error_reason": self._optional_string(payload.get("error_reason")),
    }
    summary: dict[str, object] = {
        "action_scope": action_scope,
        "cloud_sync": dict(cloud_sync) if isinstance(cloud_sync, dict) else {"status": cloud_sync_status},
        "editor_or_cli": surface,
    }
    return {
        "action_scope": action_scope,
        "artifact_name": f"Cursor {surface_label} {action}",
        "capabilities_summary": f"Guard local daemon completed Cursor {surface_label} {action}.",
        "changed_capability": f"{surface}:{action}",
        "scanner_evidence": scanner_evidence,
        "source_scope": f"cursor:{surface}",
        "summary": summary,
    }


def _handle_policy_clear(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    harness = self._optional_string(payload.get("harness"))
    source = self._optional_string(payload.get("source"))
    scope = self._optional_string(payload.get("scope"))
    artifact_id = self._optional_string(payload.get("artifact_id"))
    artifact_hash = self._optional_string(payload.get("artifact_hash"))
    workspace = self._optional_string(payload.get("workspace"))
    publisher = self._optional_string(payload.get("publisher"))
    try:
        clear_all = self._optional_bool(payload.get("all"), default=False)
        artifact_id_is_null = self._optional_bool(payload.get("artifact_id_is_null"), default=False)
        artifact_hash_is_null = self._optional_bool(payload.get("artifact_hash_is_null"), default=False)
    except ValueError:
        self._write_json({"error": "invalid_clear_payload", "cleared": 0}, status=400)
        return
    if scope is not None and scope not in {"artifact", "workspace", "publisher", "harness", "global"}:
        self._write_json({"error": "invalid_scope", "cleared": 0, "scope": scope}, status=400)
        return
    if clear_all and harness is not None:
        self._write_json(
            {
                "error": "choose_all_or_harness",
                "cleared": 0,
                "harness": harness,
                "source": source,
            },
            status=400,
        )
        return
    if not clear_all and harness is None:
        self._write_json({"error": "missing_harness_or_all", "cleared": 0}, status=400)
        return
    try:
        approval_gate_grant = _server.require_high_risk(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            purpose="policy_clear",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
        cleared = self.server.store.clear_policy_decisions(  # type: ignore[attr-defined]
            None if clear_all else harness,
            source,
            scope=scope,
            artifact_id=artifact_id,
            artifact_hash=artifact_hash,
            artifact_id_is_null=artifact_id_is_null,
            artifact_hash_is_null=artifact_hash_is_null,
            workspace=workspace,
            publisher=publisher,
            approval_gate_grant=approval_gate_grant,
        )
    except _server.ApprovalGateError as error:
        payload = error.to_payload()
        payload["cleared"] = 0
        self._write_json(payload, status=error.status)
        return
    self._write_json(
        {
            "cleared": cleared,
            "harness": None if clear_all else harness,
            "source": source,
            "scope": scope,
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "artifact_id_is_null": artifact_id_is_null,
            "artifact_hash_is_null": artifact_hash_is_null,
            "workspace": workspace,
            "publisher": publisher,
        }
    )


def _handle_requests_clear(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    status = self._optional_string(payload.get("status")) or "pending"
    harness = self._optional_string(payload.get("harness"))
    if status not in {"pending", "resolved"}:
        self._write_json({"error": "invalid_status", "cleared": 0, "status": status}, status=400)
        return
    try:
        _server.require_high_risk(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            purpose="queue_clear",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
        cleared = self.server.store.clear_approval_requests(  # type: ignore[attr-defined]
            harness=harness,
            status=status,
        )
    except _server.ApprovalGateError as error:
        payload = error.to_payload()
        payload["cleared"] = 0
        payload["status"] = status
        self._write_json(payload, status=error.status)
        return
    self._write_json({"cleared": cleared, "status": status, "harness": harness})


def _handle_bulk_allow_read_once(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    request_ids = payload.get("request_ids")
    if not isinstance(request_ids, list) or len(request_ids) == 0:
        self._write_json({"error": "missing_request_ids", "resolved_count": 0, "failed": []}, status=400)
        return
    normalized_ids = [str(item).strip() for item in request_ids if isinstance(item, str) and str(item).strip()]
    if len(normalized_ids) == 0:
        self._write_json({"error": "missing_request_ids", "resolved_count": 0, "failed": []}, status=400)
        return
    try:
        result = _server.bulk_allow_read_only_once(
            store=self.server.store,  # type: ignore[attr-defined]
            request_ids=normalized_ids,
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except ValueError as error:
        if str(error) == "bulk_approve_gate_required":
            self._write_json(
                {"error": str(error), "resolved_count": 0, "failed": []},
                status=403,
            )
            return
        self._write_json(
            {"error": str(error), "resolved_count": 0, "failed": []},
            status=400,
        )
        return
    except _server.ApprovalGateError as error:
        error_payload = error.to_payload()
        error_payload.setdefault("resolved_count", 0)
        error_payload.setdefault("failed", [])
        self._write_json(error_payload, status=error.status)
        return
    self._write_json(result)


def _harness_context(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> _server.HarnessContext:
    del payload
    return _server.HarnessContext(
        home_dir=_server.Path.home().resolve(),
        workspace_dir=None,
        guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
    )


def _handle_harness_action(
    self: _server._GuardDaemonHandler, harness: str, action: str, payload: dict[str, object]
) -> None:
    if action not in {"install", "verify", "repair", "uninstall"}:
        self._write_json({"error": "not_found"}, status=404)
        return
    context = self._harness_context(payload)
    if action == "verify":
        try:
            self._write_json(_server.build_harness_verification(harness, context, self.server.store))  # type: ignore[attr-defined]
        except ValueError as error:
            self._write_json({"error": str(error)}, status=404)
        return
    try:
        dry_run = self._optional_bool(payload.get("dry_run"), default=True)
    except ValueError:
        self._write_json({"error": "invalid_dry_run"}, status=400)
        return
    try:
        adapter = _server.get_adapter(harness)
    except ValueError as error:
        self._write_json({"error": str(error)}, status=404)
        return
    if action == "uninstall":
        expected_confirmation = _server.uninstall_confirmation_token(adapter.harness)
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
        self._write_json(_server.build_harness_setup_plan(action, adapter.harness, context, dry_run=True))
        return
    if action == "uninstall":
        try:
            _server.require_harness_disconnect_gate(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                payload,
                harness=adapter.harness,
            )
        except _server.ApprovalGateError as error:
            self._write_approval_gate_error(error)
            return
    install_command = "uninstall" if action == "uninstall" else "install"
    try:
        result = _server.apply_managed_install(
            install_command,
            adapter.harness,
            False,
            context,
            self.server.store,  # type: ignore[attr-defined]
            str(context.workspace_dir) if context.workspace_dir is not None else None,
            _server._now(),
        )
    except ValueError as error:
        self._write_json({"error": str(error)}, status=400)
        return
    except RuntimeError:
        _server._LOGGER.exception("Guard could not complete %s repair for %s", action, adapter.harness)
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


def _handle_notification_setup(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    del payload
    host = self._daemon_server().daemon_host()
    port = self._daemon_server().daemon_port()
    approval_url = _server._build_local_url(host, port, "/approvals/notification-preview")
    try:
        result = _server.ensure_desktop_notification_setup(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            approval_url=approval_url,
            force=True,
        )
    except Exception as error:
        self._write_json({"error": str(error)}, status=500)
        return
    guidance = _server.macos_notification_guidance(result.notifier_path) if result.platform == "Darwin" else None
    self._write_json(_server.desktop_notification_setup_payload(result, guidance=guidance))

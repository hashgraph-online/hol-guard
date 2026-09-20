"""Supply chain repair and package firewall actions."""

from __future__ import annotations

from . import server as _server


def _handle_audit_remediation(self: _server._GuardDaemonHandler, action: str, payload: dict[str, object]) -> None:
    if action != "package_shim_path":
        self._write_json({"error": "unsupported_remediation", "operation": action}, status=404)
        return
    manager = self._optional_string(payload.get("manager"))
    if manager is None:
        self._write_json({"error": "missing_manager", "operation": action}, status=400)
        return
    managers, manager_error = self._supply_chain_managers({"managers": [manager]})
    if manager_error is not None:
        self._write_json({"error": manager_error, "operation": action}, status=400)
        return
    entitlement = self._supply_chain_entitlement()
    if not bool(entitlement["allowed"]):
        status, error_code, message = _server.package_firewall_block_details(entitlement)
        current_status = _server.package_shim_status(self._supply_chain_context(payload))
        self._write_json(
            {
                "available_actions": _server.package_firewall_available_actions(
                    entitlement,
                    has_installed_managers=bool(current_status.get("installed_managers")),
                ),
                "entitlement": entitlement,
                "error": error_code,
                "message": message,
                "operation": action,
            },
            status=status,
        )
        return
    context = self._supply_chain_context(payload)
    try:
        _server.require_high_risk(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            purpose="supply_chain_firewall",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
        activation_result = _server.activate_package_shims(context, managers=managers)
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    except ValueError as error:
        self._write_json({"error": str(error), "operation": action}, status=400)
        return
    result = {
        "manager": manager,
        **activation_result,
    }
    receipt_overrides = _server.package_firewall_receipt_metadata(
        operation=action,
        result=result,
        managers=(manager,),
        workspace_dir=context.workspace_dir,
    )
    scanner_evidence = receipt_overrides.get("scanner_evidence")
    receipt = self._record_headless_receipt(
        harness="package-firewall",
        operation=action,
        payload=payload,
        result=result,
        workspace_id=self._optional_string(payload.get("workspace_id")) or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
        policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
        capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
        artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
        scanner_evidence_extra=scanner_evidence if _server._is_string_object_dict(scanner_evidence) else None,
    )
    self._write_json(
        {
            "entitlement": entitlement,
            "operation": action,
            "receipt": receipt,
            "result": result,
            "status": "completed",
        }
    )


def _handle_supply_chain_package_firewall_status(self: _server._GuardDaemonHandler) -> None:
    entitlement = self._supply_chain_entitlement()
    status = _server.package_shim_dashboard_status(self._harness_context({}))
    audit_workspace_dir = self._resolve_supply_chain_workspace_dir({})
    self._write_json(
        {
            "actions": _server.package_firewall_action_states(
                entitlement,
                has_installed_managers=bool(status.get("installed_managers")),
            ),
            "audit_workspace_dir": (str(audit_workspace_dir) if audit_workspace_dir is not None else None),
            "cli_fallback": {
                "connect": "hol-guard connect",
                "install": "hol-guard package-shims install --json",
                "status": "hol-guard package-shims status --json",
                "remove": "hol-guard package-shims uninstall --json",
            },
            "connect_flow": self._supply_chain_connect_flow(entitlement),
            "entitlement": entitlement,
            "operation": "status",
            "status": "completed",
            "supported_managers": list(_server.package_shim_supported_managers()),
            "package_shims": status,
        }
    )


def _handle_supply_chain_repair(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    if not self._enforce_package_firewall_rate_limit("repair", payload):
        return

    try:
        _server.require_high_risk(
            self.server.store.guard_home,  # type: ignore[attr-defined]
            purpose="supply_chain_firewall",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return

    entitlement = self._supply_chain_entitlement()
    context = self._supply_chain_context(payload)
    current_status = _server.package_shim_status(context)
    if not _server.package_firewall_operation_allowed(
        entitlement,
        "repair",
        has_installed_managers=bool(current_status.get("installed_managers")),
    ):
        status, error_code, message = _server.package_firewall_block_details(entitlement)
        self._write_json(
            {
                "entitlement": entitlement,
                "error": error_code,
                "message": message,
                "operation": "repair_all",
            },
            status=status,
        )
        return
    result = _server.coordinate_supply_chain_repair(
        repair_package_shims=lambda: _server._repair_detected_package_shims(context),
        activate_runtime=lambda: _server._activate_package_firewall_runtime(context),
        sync_intelligence=lambda: _server.repair_sync_intelligence(
            self.server.store,  # type: ignore[attr-defined]
            workspace_dir=context.workspace_dir,
        ),
    )
    receipt = self._record_headless_receipt(
        harness="package-firewall",
        operation="repair_all",
        payload=payload,
        result=result,
        workspace_id=self._optional_string(payload.get("workspace_id")) or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
    )
    self._write_json(
        {
            "entitlement": entitlement,
            "operation": "repair_all",
            "receipt": receipt,
            "result": result,
            "status": "completed" if result["repaired"] is True else "incomplete",
        }
    )


def _handle_supply_chain_package_firewall_action(
    self: _server._GuardDaemonHandler, action: str, payload: dict[str, object]
) -> None:
    if action == "connect":
        self._handle_supply_chain_package_firewall_connect()
        return
    operation = "remove" if action == "uninstall" else action
    if operation == "open-shell":
        operation = "activate"
    if not self._enforce_package_firewall_rate_limit(operation, payload):
        return
    entitlement = self._supply_chain_entitlement()
    context = self._supply_chain_context(payload)
    current_status = _server.package_shim_status(context)
    if not _server.package_firewall_operation_allowed(
        entitlement,
        operation,
        has_installed_managers=bool(current_status.get("installed_managers")),
    ):
        status, error_code, message = _server.package_firewall_block_details(entitlement)
        self._write_json(
            {
                "available_actions": _server.package_firewall_available_actions(
                    entitlement,
                    has_installed_managers=bool(current_status.get("installed_managers")),
                ),
                "entitlement": entitlement,
                "error": error_code,
                "message": message,
                "operation": operation,
            },
            status=status,
        )
        return
    managers, manager_error = self._supply_chain_managers(payload)
    if manager_error is not None:
        self._write_json({"error": manager_error, "operation": operation}, status=400)
        return
    try:
        if operation in {"install", "repair", "remove", "test", "sync"}:
            _server.require_high_risk(
                self.server.store.guard_home,  # type: ignore[attr-defined]
                purpose="supply_chain_firewall",
                approval_gate_input=_server.approval_gate_input_from_mapping(payload),
            )
        if operation == "activate":
            status, response = _server._activate_package_firewall_runtime(context)
            self._write_json(response, status=status)
            return
        result = self._run_supply_chain_package_action(operation, context, managers)
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    except ValueError as error:
        error_code = str(error)
        error_payload: dict[str, object] = {"error": error_code, "operation": operation}
        if error_code == "workspace_dir_required":
            error_payload["message"] = (
                "Guard needs a project folder with package manifests before it can run "
                "the workspace audit. Open Guard from a connected app workspace or pass "
                "workspace_dir in the audit request."
            )
        self._write_json(error_payload, status=400)
        return
    except Exception as error:
        status, error_payload = _server._supply_chain_package_action_error_response(
            operation=operation,
            error=error,
        )
        self._write_json(error_payload, status=status)
        return
    receipt_overrides = _server.package_firewall_receipt_metadata(
        operation=operation,
        result=result,
        managers=managers,
        workspace_dir=context.workspace_dir,
        store=self.server.store,  # type: ignore[attr-defined]
    )
    scanner_evidence = receipt_overrides.get("scanner_evidence")
    receipt = self._record_headless_receipt(
        harness="package-firewall",
        operation=operation,
        payload=payload,
        result=result,
        workspace_id=self._optional_string(payload.get("workspace_id")) or self.server.store.get_cloud_workspace_id(),  # type: ignore[attr-defined]
        policy_decision=self._optional_string(receipt_overrides.get("policy_decision")),
        capabilities_summary=self._optional_string(receipt_overrides.get("capabilities_summary")),
        artifact_name=self._optional_string(receipt_overrides.get("artifact_name")),
        scanner_evidence_extra=scanner_evidence if _server._is_string_object_dict(scanner_evidence) else None,
    )
    response_status = "completed"
    if operation == "audit":
        audit_status = result.get("audit_status")
        if audit_status == "incomplete":
            response_status = "incomplete"
    response_payload: dict[str, object] = {
        "entitlement": entitlement,
        "operation": operation,
        "receipt": receipt,
        "result": result,
        "status": response_status,
    }
    if operation == "audit":
        cloud_sync = _server._queue_headless_cloud_sync_with_optional_publish(
            store=self.server.store,
            managed_controls_publish=_server._managed_controls_publish_for(self.server),
        )
        receipt["cloud_sync"] = cloud_sync
        response_payload["cloud_sync"] = cloud_sync
    self._write_json(response_payload)


def _run_supply_chain_package_action(
    self: _server._GuardDaemonHandler,
    operation: str,
    context: _server.HarnessContext,
    managers: tuple[str, ...] | None,
) -> dict[str, object]:
    store = self.server.store  # type: ignore[attr-defined]
    if operation == "install":
        return _server.activate_package_shims(context, managers=managers)
    if operation == "repair":
        return _server.activate_package_shims(context, managers=managers, repair=True)
    if operation == "remove":
        return _server.uninstall_package_shims(context, managers=managers)
    if operation == "test":
        return _server.probe_package_shim_intercepts(
            context,
            managers=managers,
            workspace_dir=context.workspace_dir,
        )
    if operation == "audit":
        if context.workspace_dir is None:
            raise ValueError("workspace_dir_required")
        config = _server.load_guard_config(store.guard_home, config_reader=self._daemon_server().hook_config_reader)
        now = _server.datetime.now(_server.timezone.utc).isoformat()
        audit_payload, exit_code = _server.build_workspace_audit_payload(
            command_name="audit",
            config=config,
            now=now,
            sbom_paths=(),
            store=store,
            workspace_dir=context.workspace_dir,
        )
        audit_payload["exit_code"] = exit_code
        if exit_code == 0:
            _server.record_package_shim_audit_result(context, audited_at=now)
        return audit_payload
    if operation == "sync":
        return _server._sync_supply_chain_cloud_state_with_optional_auth_context(
            self.server.store,  # type: ignore[attr-defined]
            None,
            workspace_dir=context.workspace_dir,
        )
    raise ValueError("unsupported_supply_chain_operation")


def _resolve_supply_chain_workspace_dir(
    self: _server._GuardDaemonHandler, payload: dict[str, object]
) -> _server.Path | None:
    allowed_roots = (
        _server.Path.home().resolve(),
        _server.Path.cwd().resolve(),
        _server.Path(_server.tempfile.gettempdir()).resolve(),
    )
    managed_workspace_dirs = _server.managed_install_audit_workspace_dirs(self.server.store)  # type: ignore[attr-defined]
    return _server.resolve_supply_chain_audit_workspace_dir(
        workspace_dir_value=payload.get("workspace_dir"),
        workspace_value=payload.get("workspace"),
        allowed_roots=allowed_roots,
        managed_workspace_dirs=managed_workspace_dirs,
    )


def _supply_chain_context(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> _server.HarnessContext:
    workspace_dir = self._resolve_supply_chain_workspace_dir(payload)
    return _server.HarnessContext(
        home_dir=_server.Path.home().resolve(),
        workspace_dir=workspace_dir,
        guard_home=self.server.store.guard_home,  # type: ignore[attr-defined]
    )


def _supply_chain_managers(payload: dict[str, object]) -> tuple[tuple[str, ...] | None, str | None]:
    managers_value = payload.get("managers")
    if managers_value is None:
        return None, None
    if not isinstance(managers_value, list) or not all(isinstance(manager, str) for manager in managers_value):
        return None, "invalid_managers"
    supported = set(_server.package_shim_supported_managers())
    normalized = [manager.strip().lower() for manager in managers_value if manager.strip()]
    if len(normalized) != len(set(normalized)):
        return None, "duplicate_manager"
    managers = tuple(normalized)
    if not managers:
        return None, "invalid_managers"
    if not set(managers).issubset(supported):
        return None, "unsupported_manager"
    return managers, None


def _supply_chain_entitlement(self: _server._GuardDaemonHandler) -> dict[str, object]:
    server = self.server  # type: ignore[attr-defined]
    with server.guard_cloud_browser_session_lock:
        cloud_connect = _server._copy_guard_cloud_connect_state(server)
        package_connect = _server._copy_package_firewall_connect_state(server)
        if _server._guard_cloud_connect_state_is_in_flight(
            cloud_connect
        ) or _server._guard_cloud_connect_state_is_in_flight(package_connect):
            return _server.resolve_package_firewall_entitlement(server.store)
        return _server.resolve_package_firewall_entitlement_with_refresh(server.store)


def _handle_get_supply_chain_bundle(self: _server._GuardDaemonHandler) -> None:
    store = self.server.store  # type: ignore[attr-defined]
    workspace_id = store.get_cloud_workspace_id()
    wrapper = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id is not None else None
    bundle = wrapper.get("bundle") if isinstance(wrapper, dict) else None
    self._write_json({"bundle": bundle})


def _supply_chain_connect_flow(
    self: _server._GuardDaemonHandler, entitlement: dict[str, object]
) -> dict[str, object] | None:
    return _server._resolve_package_firewall_connect_flow(server=self.server, entitlement=entitlement)  # type: ignore[arg-type]

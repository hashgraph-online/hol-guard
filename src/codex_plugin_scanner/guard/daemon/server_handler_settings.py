"""Protection repair and Guard settings."""

from __future__ import annotations

from . import server as _server


def _handle_protection_repair(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    check_id = self._optional_string(payload.get("check_id"))
    store = self.server.store  # type: ignore[attr-defined]
    if check_id in {"all", "policy_engine", "rule_packs", "tamper_checks"}:
        try:
            status = store.setup_policy_integrity(now=_server._now(), include_items=False)
            if status.get("mode") != "protected":
                status = store.repair_policy_integrity(
                    clear_invalid=False,
                    now=_server._now(),
                    include_items=False,
                )
        except (OSError, RuntimeError, TypeError, ValueError):
            self._write_json(
                {
                    "error": "protection_repair_failed",
                    "message": "Guard could not restore integrity protection automatically.",
                },
                status=409,
            )
            return
        repaired = status.get("mode") == "protected"
        degraded_reasons = status.get("degraded_reasons")
        reason_count = len(degraded_reasons) if isinstance(degraded_reasons, list) else 0
        repaired_check_ids = ["policy_engine", "rule_packs", "tamper_checks"]
        pending_check_ids: list[str] = []
        failed_check_ids: list[str] = []
        if check_id == "all":
            hook_repair_unknown = False
            try:
                _, hook_failures = _server.repair_failing_managed_harness_hooks(store)
            except (OSError, RuntimeError, TypeError, ValueError, _server.sqlite3.Error):
                hook_failures = []
                hook_repair_unknown = True
            has_active_hooks = any(
                isinstance(install.get("harness"), str) and install.get("active") is True
                for install in store.list_managed_installs()
            )
            if hook_failures or hook_repair_unknown or not has_active_hooks:
                failed_check_ids.append("harness_hooks")
            else:
                repaired_check_ids.append("harness_hooks")
            if repaired:
                containment_repaired, containment_failed = _server.confirmed_containment_repair_signals(
                    lambda: self._containment_health_payload(force_refresh=True)
                )
                repaired_check_ids.extend(containment_repaired)
                failed_check_ids.extend(containment_failed)
                try:
                    config = _server.load_guard_config(
                        store.guard_home, config_reader=self._daemon_server().hook_config_reader
                    )
                    _server._repair_command_activity_persistence_health(store)
                    store.maintain_command_activity(
                        now=_server.datetime.now(_server.timezone.utc),
                        detail_retain_days=config.evidence_retain_days,
                    )
                    evidence_health = store.get_command_activity_persistence_health()
                    if evidence_health.active_error_count > 0:
                        failed_check_ids.append("decision_stream")
                    else:
                        repaired_check_ids.append("decision_stream")
                except (OSError, RuntimeError, TypeError, ValueError, _server.sqlite3.Error):
                    failed_check_ids.append("decision_stream")
            if repaired and (failed_check_ids or pending_check_ids):
                self._write_json(
                    _server.incomplete_protection_repair_payload(
                        repaired_check_ids=repaired_check_ids,
                        failed_check_ids=failed_check_ids,
                        failed_harnesses=hook_failures,
                        pending_check_ids=pending_check_ids,
                        has_active_hooks=has_active_hooks,
                        hook_failures=hook_failures,
                        hook_repair_unknown=hook_repair_unknown,
                    ),
                    status=409,
                )
                return
        self._write_json(
            {
                **({"error": "local_integrity_repair_incomplete"} if not repaired else {}),
                "repaired": repaired,
                "repair_scope": "local_integrity",
                "check_ids": repaired_check_ids,
                "pending_check_ids": pending_check_ids,
                "message": (
                    "Integrity protection restored."
                    if repaired
                    else (
                        "Guard could not establish a local integrity proof. "
                        "Unverified local rules remain disabled. Local repair did not change Guard Cloud policy "
                        "availability. Retry local repair from Protect; "
                        f"Guard will keep the remaining {reason_count or 1} issue isolated."
                    )
                ),
            },
            status=200 if repaired else 409,
        )
        return
    if check_id == "decision_stream":
        try:
            config = _server.load_guard_config(store.guard_home, config_reader=self._daemon_server().hook_config_reader)
            _server._repair_command_activity_persistence_health(store)
            store.maintain_command_activity(
                now=_server.datetime.now(_server.timezone.utc),
                detail_retain_days=config.evidence_retain_days,
            )
            health = store.get_command_activity_persistence_health()
        except (OSError, RuntimeError, TypeError, ValueError, _server.sqlite3.Error):
            self._write_json(
                {
                    "error": "protection_repair_failed",
                    "message": "Guard could not verify the command evidence store.",
                },
                status=409,
            )
            return
        repaired = health.active_error_count == 0
        self._write_json(
            {
                "repaired": repaired,
                "repair_scope": "local_integrity",
                "check_ids": ["decision_stream"],
                "message": (
                    "Command evidence is healthy."
                    if repaired
                    else "Guard could not restore command evidence persistence."
                ),
            },
            status=200 if repaired else 409,
        )
        return
    self._write_json({"error": "unsupported_protection_check"}, status=400)


def _handle_settings_update(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    self._apply_settings_payload(payload, missing_error="invalid_settings")


def _apply_settings_payload(
    self: _server._GuardDaemonHandler, payload: dict[str, object], *, missing_error: str
) -> None:
    settings = payload.get("settings")
    if not isinstance(settings, dict):
        self._write_json({"error": missing_error}, status=400)
        return
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    previous_redaction_level = _server.load_guard_config(
        guard_home, config_reader=self._daemon_server().hook_config_reader
    ).receipt_redaction_level
    gate_payload = settings.get("approval_gate")
    gate_input = (
        _server.approval_gate_input_from_mapping({"approval_gate": gate_payload})
        if isinstance(gate_payload, dict)
        else None
    )
    if payload.get("approval_password") or payload.get("approval_totp_code"):
        proof_input = _server.approval_gate_input_from_mapping(payload)
        if proof_input is not None:
            gate_input = proof_input
    presentation_only_keys = {
        "presentation_mode",
        "presentation_mode_explicit",
        "presentation_schema_version",
        "presentation_revision",
    }
    presentation_only = gate_payload is None and bool(settings) and set(settings).issubset(presentation_only_keys)
    try:
        approval_gate_grant = (
            None
            if presentation_only
            else _server.require_high_risk(
                guard_home,
                purpose="settings_write",
                approval_gate_input=gate_input,
            )
        )
        if isinstance(gate_payload, dict):
            _server.validate_approval_gate_settings(
                guard_home,
                gate_payload,
                approval_gate_grant=approval_gate_grant,
            )
        config_settings = {key: value for key, value in settings.items() if key != "approval_gate"}
        if missing_error == "invalid_settings_import":
            config_settings.pop("presentation_revision", None)
        entitlement = _server.resolve_package_firewall_entitlement(self.server.store)  # type: ignore[attr-defined]
        config = _server.update_guard_settings(
            guard_home,
            config_settings,
            approval_gate_grant=approval_gate_grant,
            cloud_sync_entitled=bool(entitlement.get("allowed")),
            skip_approval_gate=presentation_only,
        )
        if isinstance(gate_payload, dict):
            _server.update_approval_gate_settings(
                guard_home,
                gate_payload,
                approval_gate_grant=approval_gate_grant,
            )
            config = _server.load_guard_config(guard_home, config_reader=self._daemon_server().hook_config_reader)
        if config.receipt_redaction_level != previous_redaction_level:
            _server._requeue_cloud_review_privacy_projection(  # type: ignore[arg-type]
                self.server.store,
                level=config.receipt_redaction_level,
                changed_at=_server._now(),
            )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    except ValueError as error:
        self._write_json({"error": "invalid_settings", "message": str(error)}, status=400)
        return
    self._write_json(_server._settings_response_payload(guard_home, _server.editable_guard_settings(config)))


def _handle_update_channel(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    try:
        approval_gate_grant = _server.require_high_risk(
            guard_home,
            purpose="settings_write",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
        _server.update_guard_update_channel(
            guard_home,
            payload.get("update_channel"),
            approval_gate_grant=approval_gate_grant,
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    except ValueError as error:
        self._write_json({"error": "invalid_update_channel", "message": str(error)}, status=400)
        return
    self._write_json(
        _server.build_guard_update_status_payload(guard_home=guard_home),
        extra_headers={"Cache-Control": "no-store, max-age=0"},
    )


def _handle_settings_import(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    self._apply_settings_payload(payload, missing_error="invalid_settings_import")


def _handle_settings_reset(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    confirm = payload.get("confirm")
    if confirm != "reset-local-settings":
        self._write_json({"error": "confirmation_required", "confirm": "reset-local-settings"}, status=400)
        return
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    previous_redaction_level = _server.load_guard_config(
        guard_home, config_reader=self._daemon_server().hook_config_reader
    ).receipt_redaction_level
    try:
        approval_gate_grant = _server.require_high_risk(
            guard_home,
            purpose="settings_write",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
        config = _server.reset_guard_settings(guard_home, approval_gate_grant=approval_gate_grant)
        if config.receipt_redaction_level != previous_redaction_level:
            _server._requeue_cloud_review_privacy_projection(  # type: ignore[arg-type]
                self.server.store,
                level=config.receipt_redaction_level,
                changed_at=_server._now(),
            )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    self._write_json(_server._settings_response_payload(guard_home, _server.editable_guard_settings(config)))


def _handle_approval_gate_cooldown_revoke(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    try:
        _server.require_high_risk(
            guard_home,
            purpose="settings_write",
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    gate = _server.revoke_approval_gate_cooldown(guard_home).to_dict()
    config = _server.load_guard_config(guard_home, config_reader=self._daemon_server().hook_config_reader)
    settings = _server.editable_guard_settings(config)
    settings["approval_gate"] = gate
    self._write_json(_server._settings_response_payload(guard_home, settings))


def _handle_approval_gate_totp_enroll(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    device_label = self._optional_string(payload.get("device_label")) or "local-device"
    try:
        enrollment = _server.begin_totp_enrollment(
            guard_home,
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
            device_label=device_label,
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    config = _server.load_guard_config(guard_home, config_reader=self._daemon_server().hook_config_reader)
    settings = _server.editable_guard_settings(config)
    settings["approval_gate"] = _server.approval_gate_public_config(guard_home).to_dict()
    response = _server._settings_response_payload(guard_home, settings)
    response["enrollment"] = enrollment
    self._write_json(response)


def _handle_approval_gate_totp_verify(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    try:
        gate = _server.confirm_totp_enrollment(
            guard_home,
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    config = _server.load_guard_config(guard_home, config_reader=self._daemon_server().hook_config_reader)
    settings = _server.editable_guard_settings(config)
    settings["approval_gate"] = gate.to_dict()
    self._write_json(_server._settings_response_payload(guard_home, settings))


def _handle_approval_gate_totp_disable(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    try:
        gate = _server.disable_totp(
            guard_home,
            approval_gate_input=_server.approval_gate_input_from_mapping(payload),
        )
    except _server.ApprovalGateError as error:
        self._write_approval_gate_error(error)
        return
    config = _server.load_guard_config(guard_home, config_reader=self._daemon_server().hook_config_reader)
    settings = _server.editable_guard_settings(config)
    settings["approval_gate"] = gate.to_dict()
    self._write_json(_server._settings_response_payload(guard_home, settings))

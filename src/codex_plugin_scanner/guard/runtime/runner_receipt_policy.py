"""Receipt policy.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _activate_receipt_sync_policy(
    *,
    store: runner.GuardStore,
    device_id: str,
    device_name: str,
    now: str,
    policy_bundle_field_provided: bool,
    policy_bundle_field_malformed: bool,
    policy_bundle_payload: dict[str, object] | None,
    policy_bundle_sync_payload: dict[str, object] | None,
    policy_bundle_delivery_field_provided: bool,
    policy_bundle_delivery_payload: object,
    alert_preferences_payload: dict[str, object] | None,
    remote_decisions: set[runner.PolicyDecision],
    managed_controls_publish: runner.Callable[[runner.ExtensionControlAuthorityView, runner.Callable[[], None]], object]
    | None,
) -> tuple[str | None, list[dict[str, object]], int, bool]:
    cloud_workspace_id = store.get_cloud_workspace_id()
    canonical_enforcement = runner._canonical_policy_enforcement_enabled(
        device_id=device_id,
        workspace_id=cloud_workspace_id,
    )
    candidate_policy_decisions: list[runner.PolicyDecision] = []
    validated_policy_bundle: dict[str, object] | None = None
    candidate_managed_controls: runner.ParsedManagedControlsPolicy | None = None
    candidate_managed_capabilities = frozenset[str]()
    validated_policy_bundle_delivery: dict[str, object] | None = None
    effective_managed_controls: runner.ParsedManagedControlsPolicy | None = None
    effective_managed_capabilities = frozenset[str]()
    effective_policy_bundle: dict[str, object] | None = None
    retain_existing_policy_authority = False
    activation_last_error: dict[str, object] = {}
    trusted_policy_bundle_keys: tuple[runner.PolicyBundleVerificationKey, ...] = ()
    update_last_good = False
    existing_policy_bundle_payload = store.get_sync_payload("policy_bundle")
    existing_policy_bundle, existing_policy_bundle_error = runner._validate_cached_policy_bundle(
        store,
        existing_policy_bundle_payload,
    )
    runtime_session_summary = store.get_sync_payload("runtime_session_summary")
    delivery_device_id = runner.runtime_summary_device_id(runtime_session_summary, device_id)
    if policy_bundle_field_provided:
        policy_bundle_rejection_reason: str | None
        if policy_bundle_field_malformed or policy_bundle_payload is None:
            policy_bundle_rejection_reason = "invalid_policy_bundle"
        else:
            validated_policy_bundle, policy_bundle_rejection_reason, trusted_policy_bundle_keys = (
                runner.validate_synced_policy_bundle(
                    policy_bundle_payload,
                    stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
                    sync_payload=policy_bundle_sync_payload,
                    supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
                    managed_keyring_provenance=store.get_sync_payload(
                        runner.MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
                    ),
                    expected_workspace_id=store.get_cloud_workspace_id(),
                )
            )
        if validated_policy_bundle is not None and not runner._daemon_version_supported(validated_policy_bundle):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "unsupported_daemon_version"
        if validated_policy_bundle is not None and not runner.policy_bundle_is_enforceable(validated_policy_bundle):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "inactive_rollout_state"
        if validated_policy_bundle is not None and runner._policy_bundle_is_version_downgrade(
            runner._policy_bundle_downgrade_reference(store, existing_policy_bundle),
            validated_policy_bundle,
        ):
            validated_policy_bundle = None
            policy_bundle_rejection_reason = "bundle_version_downgrade"
        candidate_managed_capabilities = runner._managed_controls_negotiated_capabilities(
            store, policy_bundle_sync_payload
        )
        (
            validated_policy_bundle,
            candidate_managed_controls,
            validated_policy_bundle_delivery,
            managed_controls_error,
            validated_bundle_is_v2,
        ) = runner.validated_managed_controls_candidate(
            validated_policy_bundle,
            negotiated_capabilities=candidate_managed_capabilities,
            delivery_field_provided=policy_bundle_delivery_field_provided,
            delivery_payload=policy_bundle_delivery_payload,
            workspace_id=cloud_workspace_id,
            device_id=delivery_device_id,
            runtime_summary=runtime_session_summary,
        )
        if managed_controls_error is not None:
            policy_bundle_rejection_reason = managed_controls_error
        if validated_policy_bundle is not None:
            try:
                if validated_bundle_is_v2:
                    canonical_decisions = runner._build_canonical_policy_bundle_decisions(
                        validated_policy_bundle,
                        device_id=device_id,
                        device_name=device_name,
                    )
                    legacy_payload = store.get_sync_payload("policy_bundle_legacy_last_good")
                    if not isinstance(legacy_payload, dict):
                        legacy_payload = (
                            existing_policy_bundle
                            if isinstance(existing_policy_bundle, dict)
                            and existing_policy_bundle.get("contractVersion") != runner.POLICY_BUNDLE_V2_CONTRACT
                            else None
                        )
                    legacy_decisions = (
                        runner._build_policy_bundle_decisions(
                            legacy_payload,
                            device_id=device_id,
                            device_name=device_name,
                        )
                        if isinstance(legacy_payload, dict)
                        else []
                    )
                    mismatch_reasons = runner._policy_shadow_mismatch_reason_codes(
                        legacy_decisions,
                        canonical_decisions,
                    )
                    blocking_mismatch_reasons = tuple(
                        reason for reason in mismatch_reasons if reason != "legacy_unavailable"
                    )
                    candidate_policy_decisions = (
                        canonical_decisions
                        if canonical_enforcement and not blocking_mismatch_reasons
                        else legacy_decisions
                    )
                    if mismatch_reasons:
                        store.add_event(
                            "policy_bundle/shadow_mismatch",
                            {
                                "canonicalRows": len(canonical_decisions),
                                "legacyRows": len(legacy_decisions),
                                "reasonCodes": list(mismatch_reasons),
                                "status": "mismatch",
                            },
                            now,
                        )
                    if canonical_enforcement and blocking_mismatch_reasons:
                        validated_policy_bundle = None
                        policy_bundle_rejection_reason = "canonical_shadow_mismatch"
                else:
                    candidate_policy_decisions = runner._build_policy_bundle_decisions(
                        validated_policy_bundle,
                        device_id=device_id,
                        device_name=device_name,
                    )
            except runner.PolicyCompilationError as error:
                validated_policy_bundle = None
                policy_bundle_rejection_reason = f"canonical_compile_{error.code}"
        if validated_policy_bundle is not None:
            effective_policy_bundle = validated_policy_bundle
            update_last_good = True
        else:
            # A response that claims signed-bundle authority cannot route the
            # same policy through unsigned sibling fields after verification
            # fails. Keep only a still-valid signed current/LKG bundle.
            remote_decisions.clear()
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            last_good_bundle, _last_good_error = runner._validate_cached_policy_bundle(
                store,
                last_good_bundle_payload,
            )
            # A valid current bundle may be newer than last-good when a prior
            # sync stopped after persisting current but before advancing the
            # checkpoint. Prefer current so a rejected refresh cannot roll
            # policy authority back to an older signed bundle.
            effective_policy_bundle = existing_policy_bundle or last_good_bundle
            activation_last_error = runner._policy_bundle_rejection_payload(policy_bundle_rejection_reason)
            store.add_event(
                "policy_bundle/rejected",
                activation_last_error,
                now,
            )
    else:
        effective_policy_bundle = existing_policy_bundle
        if effective_policy_bundle is None:
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            effective_policy_bundle, last_good_error = runner._validate_cached_policy_bundle(
                store,
                last_good_bundle_payload,
            )
            if (
                effective_policy_bundle is None
                and isinstance(existing_policy_bundle_payload, dict)
                and existing_policy_bundle_payload
            ):
                rejection_reason = existing_policy_bundle_error or last_good_error or "invalid_policy_bundle"
                activation_last_error = runner._policy_bundle_rejection_payload(rejection_reason)
                store.add_event("policy_bundle/rejected", activation_last_error, now)
        if not activation_last_error:
            stored_last_error = store.get_sync_payload("policy_bundle_last_error")
            if isinstance(stored_last_error, dict):
                activation_last_error = stored_last_error
    if alert_preferences_payload is not None:
        store.set_sync_payload("alert_preferences", alert_preferences_payload, now)
    else:
        store.set_sync_payload("alert_preferences", {}, now)
    cloud_exception_items: list[dict[str, object]] = []
    remote_policies_stored = 0
    remote_policy_sync_blocked = False
    if effective_policy_bundle is not None:
        activation_keyring = store.get_sync_payload("policy_bundle_keyring")
        if effective_policy_bundle is validated_policy_bundle and trusted_policy_bundle_keys:
            activation_keyring = runner.policy_bundle_keyring_payload(
                trusted_policy_bundle_keys,
                workspace_id=store.get_cloud_workspace_id(),
            )
        activation_bundle, activation_reason, activation_keys = runner.validate_synced_policy_bundle(
            effective_policy_bundle,
            stored_keyring=activation_keyring,
            supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
            managed_keyring_provenance=store.get_sync_payload(
                runner.MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
            ),
            expected_workspace_id=store.get_cloud_workspace_id(),
        )
        if activation_bundle is not None and not runner.policy_bundle_is_enforceable(activation_bundle):
            activation_bundle = None
            activation_reason = "inactive_rollout_state"
        acceptance_checkpoint = store.get_sync_payload("policy_bundle_acceptance_checkpoint")
        if (
            activation_bundle is not None
            and isinstance(acceptance_checkpoint, dict)
            and runner._policy_bundle_is_version_downgrade(
                acceptance_checkpoint,
                activation_bundle,
            )
        ):
            activation_bundle = None
            activation_reason = "bundle_version_downgrade"
        if activation_bundle is None:
            activation_last_error = runner._policy_bundle_rejection_payload(activation_reason)
            store.add_event("policy_bundle/rejected", activation_last_error, now)
            effective_policy_bundle = None
        else:
            # Use exactly the payload and anchor set from the final live trust
            # check for materialization and atomic activation. A key rotation
            # or revocation between initial selection and this check therefore
            # cannot leave the previously selected current/LKG bundle active.
            effective_policy_bundle = activation_bundle
            trusted_policy_bundle_keys = activation_keys
            if activation_bundle.get("contractVersion") == runner.POLICY_BUNDLE_V2_CONTRACT:
                effective_managed_controls, effective_managed_capabilities, managed_error = (
                    runner.effective_managed_controls_for_activation(
                        store,
                        activation_bundle,
                        validated_policy_bundle=validated_policy_bundle,
                        candidate=candidate_managed_controls,
                        candidate_capabilities=candidate_managed_capabilities,
                    )
                )
                if managed_error is not None:
                    activation_last_error = runner._policy_bundle_rejection_payload(managed_error)
                    store.add_event("policy_bundle/rejected", activation_last_error, now)
                    effective_policy_bundle = None
                    retain_existing_policy_authority = True
    if effective_policy_bundle is None:
        if not retain_existing_policy_authority:
            store.clear_policy_bundle_authority(
                now,
                policy_bundle_last_error=activation_last_error,
                managed_controls_publish=managed_controls_publish,
            )
            runner._reset_cloud_receipt_redaction_authority(store, synced_at=now)
    else:
        selected_policy_decisions = (
            candidate_policy_decisions
            if validated_policy_bundle is not None
            and effective_policy_bundle.get("bundleHash") == validated_policy_bundle.get("bundleHash")
            else runner._build_policy_bundle_decisions(
                effective_policy_bundle,
                device_id=device_id,
                device_name=device_name,
                canonical_enforcement=canonical_enforcement,
            )
        )
        remote_decisions.update(selected_policy_decisions)
        policy_bundle_ack = runner.effective_policy_bundle_acknowledgement(
            device_id=device_id,
            device_name=device_name,
            effective_policy_bundle=effective_policy_bundle,
            validated_policy_bundle=validated_policy_bundle,
            validated_delivery=validated_policy_bundle_delivery,
            stored_acknowledgement=store.get_sync_payload("policy_bundle_ack"),
            synced_at=now,
        )
        cloud_exception_items = runner._policy_bundle_cloud_exception_items(
            store,
            device_id=device_id,
            sync_exceptions=[],
            policy_bundle=effective_policy_bundle,
            policy_bundle_ack=policy_bundle_ack,
        )
        try:
            custom_extension_continuity = runner.apply_custom_extension_continuity_from_sync(
                store,
                effective_policy_bundle,
                device_id=delivery_device_id,
                negotiated_capabilities=effective_managed_capabilities,
                now=now,
            )
            activated, activation_rejection_reason = runner.activate_with_reason(
                store.apply_policy_bundle_authority,
                list(remote_decisions),
                now,
                policy_bundle=effective_policy_bundle,
                policy_bundle_keyring=runner.policy_bundle_keyring_payload(
                    trusted_policy_bundle_keys,
                    workspace_id=store.get_cloud_workspace_id(),
                ),
                cloud_exceptions=cloud_exception_items,
                policy_bundle_ack=policy_bundle_ack,
                policy_bundle_checkpoint=runner._policy_bundle_acceptance_checkpoint(effective_policy_bundle),
                update_last_good=update_last_good,
                policy_bundle_last_error=activation_last_error,
                managed_controls_policy=effective_managed_controls,
                managed_controls_negotiated_capabilities=effective_managed_capabilities,
                managed_controls_delivery=validated_policy_bundle_delivery,
                managed_controls_publish=managed_controls_publish,
                custom_extension_continuity=custom_extension_continuity,
                remote_write_authorized=True,
            )
            if activated is None:
                cloud_exception_items = []
                activation_last_error = runner._policy_bundle_rejection_payload(activation_rejection_reason)
                runner.persist_activation_rejection(store, activation_last_error, now)
            else:
                remote_policies_stored = len(remote_decisions)
                if effective_policy_bundle.get("contractVersion") == runner.POLICY_BUNDLE_V2_CONTRACT:
                    canonical_last_good = store.get_sync_payload("policy_bundle_canonical_last_good")
                    if isinstance(canonical_last_good, dict) and canonical_last_good.get(
                        "bundleHash"
                    ) != effective_policy_bundle.get("bundleHash"):
                        store.set_sync_payload(
                            "policy_bundle_canonical_previous_good",
                            canonical_last_good,
                            now,
                        )
                    store.set_sync_payload(
                        "policy_bundle_canonical_last_good",
                        effective_policy_bundle,
                        now,
                    )
                else:
                    store.set_sync_payload(
                        "policy_bundle_legacy_last_good",
                        effective_policy_bundle,
                        now,
                    )
                if validated_policy_bundle is None and policy_bundle_field_provided:
                    store.add_event(
                        "policy_bundle/rollback",
                        {
                            "reason": activation_last_error.get("reason", "invalid_policy_bundle"),
                            "restored": "policy_bundle_last_good",
                        },
                        now,
                    )
                cloud_redaction_level = runner.non_empty_string(effective_policy_bundle.get("receiptRedactionLevel"))
                if cloud_redaction_level in runner.VALID_RECEIPT_REDACTION_LEVELS:
                    runner._persist_cloud_receipt_redaction_level(
                        store,
                        level=cloud_redaction_level,
                        synced_at=now,
                    )
                else:
                    runner._reset_cloud_receipt_redaction_authority(store, synced_at=now)
        except runner.ApprovalGateError as error:
            cloud_exception_items = []
            remote_policy_sync_blocked = True
            store.add_event(
                "approval_gate/remote_policy_sync_blocked",
                {
                    "error": error.code,
                    "remote_policies_count": len(remote_decisions),
                },
                now,
            )
    return cloud_workspace_id, cloud_exception_items, remote_policies_stored, remote_policy_sync_blocked

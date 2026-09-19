"""Policy.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _policy_bundle_is_version_downgrade(
    existing_bundle: dict[str, object] | None,
    next_bundle: dict[str, object],
    *,
    expected_last_good_bundle: dict[str, object] | None = None,
) -> bool:
    if next_bundle.get("contractVersion") == runner.POLICY_BUNDLE_V2_CONTRACT:
        current_version = existing_bundle.get("bundleVersion") if isinstance(existing_bundle, dict) else None
        current_hash = existing_bundle.get("bundleHash") if isinstance(existing_bundle, dict) else None
        expected_version = (
            expected_last_good_bundle.get("bundleVersion") if isinstance(expected_last_good_bundle, dict) else None
        )
        expected_hash = (
            expected_last_good_bundle.get("bundleHash") if isinstance(expected_last_good_bundle, dict) else None
        )
        return (
            runner.validate_policy_bundle_v2_transition(
                next_bundle,
                current_bundle_version=(
                    current_version
                    if isinstance(current_version, int) and not isinstance(current_version, bool)
                    else None
                ),
                current_bundle_hash=(current_hash if isinstance(current_hash, str) else None),
                expected_last_good_bundle_version=(
                    expected_version
                    if isinstance(expected_version, int) and not isinstance(expected_version, bool)
                    else None
                ),
                expected_last_good_bundle_hash=(expected_hash if isinstance(expected_hash, str) else None),
            )
            is not None
        )
    return runner.policy_bundle_is_version_downgrade(existing_bundle, next_bundle)


def _policy_bundle_utc_datetime(value: str) -> runner.datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = runner.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=runner.timezone.utc)
    return parsed.astimezone(runner.timezone.utc)


def _policy_bundle_numeric_version(value: str) -> tuple[int, ...] | None:
    tokens = tuple(int(token) for token in runner.re.findall(r"\d+", value))
    return tokens or None


def _policy_bundle_acceptance_checkpoint(policy_bundle: runner.Mapping[str, object]) -> dict[str, object]:
    return runner.policy_bundle_acceptance_checkpoint(dict(policy_bundle))


def _policy_bundle_downgrade_reference(
    store: runner.GuardStore,
    existing_bundle: dict[str, object] | None,
) -> dict[str, object] | None:
    checkpoint = store.get_sync_payload("policy_bundle_acceptance_checkpoint")
    workspace_id = store.get_cloud_workspace_id()
    candidates = [
        item
        for item in (
            checkpoint,
            existing_bundle,
            store.get_sync_payload("policy_bundle_last_good"),
        )
        if isinstance(item, dict) and runner.non_empty_string(item.get("issuedAt")) is not None
        if (workspace_id is None or runner.non_empty_string(item.get("workspaceId")) in {None, workspace_id})
    ]
    if not candidates:
        return None

    def _sort_key(item: dict[str, object]) -> tuple[runner.datetime, tuple[int, ...], str, bool]:
        issued_at = runner.non_empty_string(item.get("issuedAt"))
        assert issued_at is not None
        try:
            timestamp = runner._policy_bundle_utc_datetime(issued_at)
        except ValueError:
            timestamp = runner.datetime.max.replace(tzinfo=runner.timezone.utc)
        version = runner.non_empty_string(item.get("bundleVersion")) or ""
        return (
            timestamp,
            runner._policy_bundle_numeric_version(version) or (),
            version,
            runner.non_empty_string(item.get("payloadHash")) is not None,
        )

    return max(candidates, key=_sort_key)


def _validate_cached_policy_bundle(
    store: runner.GuardStore,
    policy_bundle: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Revalidate cached policy authority before any rule is made effective."""

    return runner.cached_policy_bundle_validation(store, policy_bundle)


def _policy_bundle_rejection_payload(reason: str | None) -> dict[str, object]:
    resolved_reason = reason or "invalid_policy_bundle"
    payload: dict[str, object] = {"reason": resolved_reason}
    remediation = runner.policy_bundle_rejection_message(resolved_reason)
    if remediation is not None:
        payload["message"] = remediation
    return payload


def _build_canonical_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[runner.PolicyDecision]:
    payload = policy_bundle.get("payload")
    if not isinstance(payload, dict):
        raise runner.PolicyCompilationError("missing_policy_bundle_payload", "policy-bundle")
    local_document = runner.json.loads(runner.json.dumps(payload))
    spec = local_document.get("spec")
    if not isinstance(spec, dict):
        raise runner.PolicyCompilationError("invalid_policy_spec", "policy-bundle")
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise runner.PolicyCompilationError("invalid_policy_rules", "policy-bundle")
    local_rules: list[object] = []
    for raw_rule in rules:
        if not isinstance(raw_rule, dict):
            continue
        # Extension-targeted rules are compiled by the Managed Controls
        # authority path. Materializing them again as generic policy rows can
        # reject valid Extension outcomes (for example ``review``) or apply a
        # second, semantically different enforcement decision.
        if "x-hol-extension-targets" in raw_rule:
            continue
        match = raw_rule.get("match")
        if not isinstance(match, dict):
            local_rules.append(raw_rule)
            continue
        devices = match.get("devices")
        if isinstance(devices, list) and devices:
            device_selectors = {str(value) for value in devices}
            if device_id not in device_selectors and device_name not in device_selectors:
                continue
            match.pop("devices", None)
        local_rules.append(raw_rule)
    spec["rules"] = local_rules
    document = runner.GuardPolicyDocument.from_mapping(local_document)
    decisions: list[runner.PolicyDecision] = []
    for row in runner.compile_policy_document(document):
        decision = row.decision
        decisions.append(
            runner.PolicyDecision(
                harness=decision.harness,
                scope=decision.scope,
                action=decision.action,
                artifact_id=decision.artifact_id,
                artifact_hash=decision.artifact_hash,
                workspace=decision.workspace,
                publisher=decision.publisher,
                reason=decision.reason,
                owner=row.rule_id,
                source="policy-bundle-canonical",
                expires_at=decision.expires_at,
            )
        )
    return decisions


def _build_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
    canonical_enforcement: bool = False,
) -> list[runner.PolicyDecision]:
    if policy_bundle.get("contractVersion") == runner.POLICY_BUNDLE_V2_CONTRACT:
        if not canonical_enforcement:
            return []
        return runner._build_canonical_policy_bundle_decisions(
            policy_bundle,
            device_id=device_id,
            device_name=device_name,
        )
    return runner._materialize_policy_bundle_decisions(
        policy_bundle,
        device_id=device_id,
        device_name=device_name,
    )


def _policy_shadow_mismatch_reason_codes(
    legacy: list[runner.PolicyDecision],
    canonical: list[runner.PolicyDecision],
) -> tuple[str, ...]:
    if not legacy:
        return ("legacy_unavailable",)

    def keyed(
        decisions: list[runner.PolicyDecision],
    ) -> dict[tuple[str, str, str | None, str | None, str | None, str | None], runner.PolicyDecision]:
        return {
            (
                decision.harness,
                decision.scope,
                decision.artifact_id,
                decision.artifact_hash,
                decision.workspace,
                decision.publisher,
            ): decision
            for decision in decisions
        }

    reasons: list[str] = []
    legacy_by_key = keyed(legacy)
    canonical_by_key = keyed(canonical)
    if len(legacy) != len(canonical):
        reasons.append("row_count")
    if legacy_by_key.keys() != canonical_by_key.keys():
        reasons.append("selector_set")
    shared_keys = legacy_by_key.keys() & canonical_by_key.keys()
    if any(legacy_by_key[key].action != canonical_by_key[key].action for key in shared_keys):
        reasons.append("action")
    if any(legacy_by_key[key].expires_at != canonical_by_key[key].expires_at for key in shared_keys):
        reasons.append("expiration")
    return tuple(reasons[:4])


def _parse_policy_simulation_timestamp(value: object) -> runner.datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        return runner.datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _receipt_policy_bundle_matcher_family(receipt: dict[str, object]) -> str | None:
    artifact_id = runner.non_empty_string(receipt.get("artifact_id"))
    if artifact_id is None:
        return None
    for family in runner.POLICY_BUNDLE_RULE_MATCHER_FAMILIES:
        if f":{family}:" in artifact_id:
            return family
    return None


def simulate_policy_bundle_receipts(
    store: runner.GuardStore,
    policy_bundle: dict[str, object],
    *,
    limit: int = 50,
    now: str | None = None,
) -> dict[str, object]:
    receipts = store.list_receipts(limit=limit)
    device_id, device_name = runner._guard_device_metadata(store)
    decisions = runner._build_policy_bundle_decisions(policy_bundle, device_id=device_id, device_name=device_name)
    generated_at = now or runner._now()
    generated_at_dt = runner._parse_policy_simulation_timestamp(generated_at)
    latest_receipt_at: str | None = None
    oldest_receipt_at: str | None = None
    latest_dt: runner.datetime | None = None
    oldest_dt: runner.datetime | None = None
    matches: list[dict[str, object]] = []
    summary = {"allow": 0, "block": 0, "review": 0, "ignore": 0, "matched": 0, "unchanged": 0}
    for receipt in receipts:
        receipt_dt = runner._parse_policy_simulation_timestamp(receipt.get("timestamp"))
        if receipt_dt is not None and (latest_dt is None or receipt_dt > latest_dt):
            latest_dt = receipt_dt
            latest_receipt_at = str(receipt.get("timestamp"))
        if receipt_dt is not None and (oldest_dt is None or receipt_dt < oldest_dt):
            oldest_dt = receipt_dt
            oldest_receipt_at = str(receipt.get("timestamp"))
        family = runner._receipt_policy_bundle_matcher_family(receipt)
        if family is None:
            continue
        harness = runner.non_empty_string(receipt.get("harness")) or "*"
        matched = next(
            (item for item in decisions if item.artifact_id == f"family:{family}" and item.harness in {harness, "*"}),
            None,
        )
        simulated_action = matched.action if matched is not None else str(receipt.get("policy_decision") or "review")
        if simulated_action not in {"allow", "block", "review", "ignore"}:
            simulated_action = "review"
        summary[simulated_action] = summary.get(simulated_action, 0) + 1
        if matched is not None:
            summary["matched"] += 1
        else:
            summary["unchanged"] += 1
        matches.append(
            {
                "receipt_id": receipt.get("receipt_id"),
                "artifact_id": receipt.get("artifact_id"),
                "harness": harness,
                "matcher_family": family,
                "observed_action": receipt.get("policy_decision"),
                "simulated_action": simulated_action,
                "matched_rule_id": matched.owner if matched is not None else None,
                "policy_version": runner.non_empty_string(policy_bundle.get("bundleHash")),
                "timestamp": receipt.get("timestamp"),
            }
        )
    stale = False
    if generated_at_dt is not None and latest_dt is not None:
        stale = (generated_at_dt - latest_dt).total_seconds() > 24 * 60 * 60
    return {
        "generated_at": generated_at,
        "policy_bundle_version": runner.non_empty_string(policy_bundle.get("bundleVersion")),
        "policy_version": runner.non_empty_string(policy_bundle.get("bundleHash")),
        "receipt_count": len(receipts),
        "summary": summary,
        "matches": matches,
        "event_freshness": {
            "latest_receipt_at": latest_receipt_at,
            "oldest_receipt_at": oldest_receipt_at,
            "sampled_receipts": len(receipts),
            "stale": stale,
        },
    }


def _persist_cloud_exceptions(
    store: runner.GuardStore,
    *,
    device_id: str | None = None,
    sync_exceptions: list[dict[str, object]] | None = None,
    policy_bundle: dict[str, object] | None = None,
    now: str,
) -> list[dict[str, object]]:
    serialized = runner._policy_bundle_cloud_exception_items(
        store,
        device_id=device_id,
        sync_exceptions=sync_exceptions,
        policy_bundle=policy_bundle,
    )
    store.set_cloud_exceptions(serialized, now)
    return serialized


def _policy_bundle_cloud_exception_items(
    store: runner.GuardStore,
    *,
    device_id: str | None = None,
    sync_exceptions: list[dict[str, object]] | None = None,
    policy_bundle: dict[str, object] | None = None,
    policy_bundle_ack: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Build bundle-derived exceptions without mutating activation state."""

    resolved_device_id = device_id
    if resolved_device_id is None:
        resolved_device_id, _device_name = runner._guard_device_metadata(store)
    bundle_ack = policy_bundle_ack
    if bundle_ack is None:
        bundle_ack_payload = store.get_sync_payload("policy_bundle_ack")
        bundle_ack = bundle_ack_payload if isinstance(bundle_ack_payload, dict) else None
    items = []
    # ``sync_exceptions`` is retained as an explicit compatibility boundary so
    # callers can demonstrate that legacy unsigned siblings were considered
    # and rejected. It must never contribute enforcement authority.
    del sync_exceptions
    if isinstance(policy_bundle, dict):
        items.extend(
            runner.build_cloud_exceptions_from_policy_bundle(
                policy_bundle,
                device_id=resolved_device_id,
                policy_bundle_ack=bundle_ack,
            )
        )
    serialized = [runner.cloud_exception_to_dict(item) for item in runner.dedupe_cloud_exceptions(items)]
    return serialized

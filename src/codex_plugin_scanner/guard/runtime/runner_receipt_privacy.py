"""Receipt privacy.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _receipt_redaction_level_rank(level: str | None) -> int:
    if level is None:
        return runner._RECEIPT_REDACTION_LEVEL_RANK["full"]
    return runner._RECEIPT_REDACTION_LEVEL_RANK.get(level, runner._RECEIPT_REDACTION_LEVEL_RANK["full"])


def _stored_cloud_receipt_redaction_level(store: runner.GuardStore) -> str | None:
    payload = store.get_sync_payload("cloud_receipt_redaction_level")
    if not isinstance(payload, dict):
        return None
    level = payload.get("level")
    return level if isinstance(level, str) and level in runner.VALID_RECEIPT_REDACTION_LEVELS else None


def _persist_cloud_receipt_redaction_level(store: runner.GuardStore, *, level: str, synced_at: str) -> None:
    previous_level = runner._stored_cloud_receipt_redaction_level(store) or runner.local_receipt_redaction_level(
        store.guard_home
    )
    if runner._receipt_redaction_level_rank(level) > runner._receipt_redaction_level_rank(previous_level):
        store.set_sync_payload(
            "receipt_sync_cursor",
            {
                "last_rowid": 0,
                "synced_at": synced_at,
                "reason": "cloud_receipt_redaction_level_relaxed",
                "receipt_redaction_level": level,
            },
            synced_at,
        )
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": level, "updated_at": synced_at},
        synced_at,
    )
    if level != previous_level:
        runner._requeue_cloud_review_privacy_projection(store, level=level, changed_at=synced_at)
    if runner._receipt_redaction_level_rank(level) > runner._receipt_redaction_level_rank("full"):
        store.set_sync_payload(
            runner._RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
            {"level": level, "updated_at": synced_at},
            synced_at,
        )


def _reset_cloud_receipt_redaction_authority(store: runner.GuardStore, *, synced_at: str) -> None:
    """Reset relaxation bookkeeping when no signed override is effective."""

    previous_level = runner._stored_cloud_receipt_redaction_level(store)
    local_level = runner.local_receipt_redaction_level(store.guard_home)
    store.set_sync_payload(
        "cloud_receipt_redaction_level",
        {"level": local_level, "updated_at": synced_at},
        synced_at,
    )
    if previous_level is not None and previous_level != local_level:
        runner._requeue_cloud_review_privacy_projection(store, level=local_level, changed_at=synced_at)
    store.delete_sync_payload(runner._RELAXED_RECEIPT_REDACTION_RESYNC_MARKER)
    store.delete_sync_payload(runner._RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER)


def _ensure_cloud_review_privacy_projection(
    store: runner.GuardStore,
    *,
    level: str,
    synced_at: str,
) -> None:
    marker = store.get_sync_payload(runner._CLOUD_REVIEW_PRIVACY_PROJECTION_MARKER)
    if isinstance(marker, dict) and marker.get("level") == level:
        return
    runner._requeue_cloud_review_privacy_projection(store, level=level, changed_at=synced_at)


def _requeue_cloud_review_privacy_projection(
    store: runner.GuardStore,
    *,
    level: str,
    changed_at: str,
) -> int:
    return store.requeue_pending_review_events_with_marker(
        changed_at=changed_at,
        marker_key=runner._CLOUD_REVIEW_PRIVACY_PROJECTION_MARKER,
        marker_payload={"level": level, "updated_at": changed_at},
    )


def _ensure_relaxed_receipt_redaction_resync(
    store: runner.GuardStore,
    *,
    level: str,
    synced_at: str,
) -> None:
    if runner._receipt_redaction_level_rank(level) <= runner._receipt_redaction_level_rank("full"):
        return
    marker = store.get_sync_payload(runner._RELAXED_RECEIPT_REDACTION_RESYNC_MARKER)
    if isinstance(marker, dict) and marker.get("level") == level:
        return
    store.set_sync_payload(
        "receipt_sync_cursor",
        {
            "last_rowid": 0,
            "synced_at": synced_at,
            "reason": "cloud_receipt_redaction_level_relaxed_existing",
            "receipt_redaction_level": level,
        },
        synced_at,
    )
    store.set_sync_payload(
        runner._RELAXED_RECEIPT_REDACTION_RESYNC_MARKER,
        {"level": level, "updated_at": synced_at},
        synced_at,
    )


def _resolve_cloud_receipt_redaction_level(store: runner.GuardStore) -> str:
    """Resolve the receipt redaction level for cloud sync.

    A cloud relaxation is authoritative only while its signed policy bundle
    remains valid. The separately persisted level is cursor bookkeeping, not
    an authority source, because it can outlive or be detached from a bundle.
    """
    policy_bundle = runner.validated_synced_policy_bundle(store)
    if policy_bundle is not None:
        level = policy_bundle.get("receiptRedactionLevel")
        if isinstance(level, str) and level in runner.VALID_RECEIPT_REDACTION_LEVELS:
            return level
    return runner.local_receipt_redaction_level(store.guard_home)


def _cloud_sync_command_display_part(value: str) -> str:
    return " ".join(runner._cloud_sync_sanitize_text(value, fallback="").split())


def _cloud_sync_transport_encode_text(value: str) -> str:
    return runner.base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _cloud_sync_receipt_action_command(envelope: dict[str, object], *, redaction_level: str) -> str | None:
    tool_name = runner._optional_string(envelope.get("tool_name"))
    sanitized_tool_name = runner._cloud_sync_command_display_part(tool_name) if tool_name is not None else ""
    command = runner._optional_string(envelope.get("command"))
    if command is not None and command not in {"guard_commands_module"}:
        if redaction_level == "full":
            return sanitized_tool_name or None
        return runner._cloud_sync_command_display_part(command)
    target_paths = envelope.get("target_paths")
    if sanitized_tool_name and isinstance(target_paths, list):
        raw_targets = [target for target in target_paths[:3] if isinstance(target, str) and target.strip()]
        if raw_targets and redaction_level == "full":
            target_placeholder = "[targets withheld]" if len(raw_targets) > 1 else "[target withheld]"
            return " ".join([sanitized_tool_name, target_placeholder])
        targets = [runner._cloud_sync_command_display_part(target) for target in raw_targets]
        targets = [target for target in targets if target]
        if targets:
            return " ".join([sanitized_tool_name, *targets])
        return sanitized_tool_name
    return None


def _cloud_sync_receipt_payload(
    receipt: dict[str, object],
    *,
    device_id: str,
    device_name: str,
    redaction_level: str = "full",
) -> dict[str, object]:
    receipt_fingerprint = runner._cloud_sync_receipt_fingerprint(receipt)
    artifact_id = (
        runner._optional_string(receipt.get("artifact_id")) or f"guard:local-receipt:{receipt_fingerprint[:24]}"
    )
    artifact_name = runner._optional_string(receipt.get("artifact_name")) or artifact_id
    policy_decision = runner._optional_string(receipt.get("policy_decision")) or "review"
    capabilities_summary = runner._optional_string(receipt.get("capabilities_summary"))
    explicit_capabilities = receipt.get("capabilities")
    if isinstance(explicit_capabilities, list):
        capabilities = [
            runner._cloud_sync_sanitize_text(item, fallback="redacted-capability")
            for item in explicit_capabilities
            if isinstance(item, str)
        ]
    else:
        capabilities = []
    summary_input = (
        runner._optional_string(receipt.get("provenance_summary"))
        or capabilities_summary
        or f"Guard recorded a {policy_decision} decision."
    )
    summary = runner._cloud_sync_sanitize_text(summary_input, fallback=f"Guard recorded a {policy_decision} decision.")
    explicit_changed_since_last_approval = receipt.get("changedSinceLastApproval")
    if not isinstance(explicit_changed_since_last_approval, bool):
        explicit_changed_since_last_approval = receipt.get("changed_since_last_approval")
    changed_since_last_approval = explicit_changed_since_last_approval is True
    # Review-tier decisions always remain changed, even if an explicit false is present.
    if policy_decision in {"review", "require-reapproval", "sandbox-required"}:
        changed_since_last_approval = True
    payload: dict[str, object] = {
        "receiptId": runner._optional_string(receipt.get("receipt_id")) or f"guard-receipt-{receipt_fingerprint}",
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": runner._cloud_sync_artifact_type(artifact_id),
        "artifactSlug": runner._cloud_sync_artifact_slug(artifact_name, artifact_id),
        "artifactHash": runner._optional_string(receipt.get("artifact_hash"))
        or runner.hashlib.sha256(artifact_id.encode("utf-8")).hexdigest(),
        "capabilities": capabilities,
        "capturedAt": runner._optional_string(receipt.get("timestamp")) or runner._now(),
        "changedSinceLastApproval": changed_since_last_approval,
        "deviceId": device_id,
        "deviceName": device_name,
        "harness": runner._optional_string(receipt.get("harness")) or "unknown",
        "policyDecision": policy_decision,
        "recommendation": runner._cloud_sync_recommendation(policy_decision),
        "summary": summary,
    }
    raw_command_text = runner._optional_string(receipt.get("raw_command_text"))
    if raw_command_text is not None:
        payload["raw_command_text"] = runner._cloud_sync_command_display_part(raw_command_text)
    publisher = runner._optional_string(receipt.get("publisher"))
    if publisher is not None:
        payload["publisher"] = publisher
    redacted_envelope = receipt.get("envelope_redacted_json")
    if isinstance(redacted_envelope, dict) and redacted_envelope:
        full_envelope = receipt.get("action_envelope_json")
        if isinstance(full_envelope, dict):
            enriched = dict(redacted_envelope)
            command = runner._cloud_sync_receipt_action_command(full_envelope, redaction_level=redaction_level)
            if command is not None:
                enriched.pop("command", None)
                enriched["commandEncoded"] = runner._cloud_sync_transport_encode_text(command)
                enriched["commandTransport"] = "base64url-v1"
            if redaction_level == "none":
                target_paths = full_envelope.get("target_paths")
                if isinstance(target_paths, list):
                    enriched["target_paths"] = target_paths
                network_hosts = full_envelope.get("network_hosts")
                if isinstance(network_hosts, list):
                    enriched["network_hosts"] = network_hosts
                package_name = full_envelope.get("package_name")
                if isinstance(package_name, str) and package_name:
                    enriched["package_name"] = package_name
            payload["envelopeRedacted"] = enriched
        else:
            payload["envelopeRedacted"] = redacted_envelope
    return payload


def _cloud_sync_receipt_fingerprint(receipt: dict[str, object]) -> str:
    encoded_receipt = runner.json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str)
    return runner.hashlib.sha256(encoded_receipt.encode("utf-8")).hexdigest()


def _cloud_sync_artifact_type(artifact_id: str) -> str:
    if artifact_id.startswith("skill:") or ":skill:" in artifact_id:
        return "skill"
    return "plugin"


def _cloud_sync_artifact_slug(artifact_name: str, artifact_id: str) -> str:
    base_value = artifact_name.strip() or artifact_id.strip() or "artifact"
    slug = runner.re.sub(r"[^a-z0-9]+", "-", base_value.lower()).strip("-")
    if slug:
        return slug
    fallback = runner.re.sub(r"[^a-z0-9]+", "-", artifact_id.lower()).strip("-")
    return fallback or "artifact"


def _cloud_sync_recommendation(policy_decision: str) -> str:
    if policy_decision == "block":
        return "block"
    if policy_decision in {"review", "require-reapproval", "sandbox-required"}:
        return "review"
    return "monitor"


def _cloud_sync_sanitize_text(value: str, *, fallback: str) -> str:
    redacted = runner.redact_sensitive_text(value).strip()
    if not redacted:
        return fallback
    if runner._looks_like_source_excerpt(redacted):
        return fallback
    if len(redacted) > 320:
        return f"{redacted[:317]}..."
    return redacted


def _looks_like_source_excerpt(value: str) -> bool:
    lowered = value.lower()
    suspicious_tokens = (
        "function ",
        "def ",
        "class ",
        "import ",
        "from ",
        " => ",
        "console.log(",
        "<script",
        "#!/bin/",
    )
    has_structured_code_shape = "\n" in value and ("{" in value or "}" in value or ";" in value)
    return has_structured_code_shape or any(token in lowered for token in suspicious_tokens)

"""Explicitly consented, integrity-bound exact policy source disclosure."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from .exact_command import exact_shell_command_from_hook, valid_exact_command_text
from .local_authority_integrity import sign_local_authority_payload, verify_local_authority_payload
from .review_oauth_binding import GuardReviewContractError, guard_review_oauth_metadata
from .runtime.local_runtime_fallbacks import local_receipt_redaction_level
from .synced_policy import validated_synced_policy_bundle

if TYPE_CHECKING:
    import sqlite3

    from .models import GuardApprovalRequest
    from .store import GuardStore

CONTRACT = "guard.policy-memory-source.v1"
_INPUT_CONTRACT = "guard.policy-memory-source-input.v1"
_SOURCE_KEY = "_policyMemorySource"
_INPUT_KEY = "_policyMemorySourceInput"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", re.ASCII)
_SOURCE_FIELDS = frozenset(
    {
        "contractVersion",
        "artifactId",
        "commandText",
        "harnessId",
        "localRequestId",
        "workspaceId",
        "installationId",
        "complete",
        "redaction",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class CapturedPolicyMemorySource:
    """Private original-input capture; never accepted from hook JSON."""

    command: str | None
    authority: tuple[tuple[str, object], ...] | None


def capture_hook_policy_memory_source(
    store: GuardStore, *, payload: Mapping[str, object]
) -> CapturedPolicyMemorySource:
    """Retain original shell bytes only under current explicit disclosure consent."""
    authority = _disclosure_authority(store)
    return CapturedPolicyMemorySource(
        exact_shell_command_from_hook(payload) if authority is not None else None,
        tuple(sorted(authority.items())) if authority is not None else None,
    )


def _disclosure_authority(store: GuardStore, *, now: str | None = None) -> dict[str, object] | None:
    from .runtime.command_capability import (
        CommandCapabilityError,
        _verified_capability,
        command_environment_allows_queue,
    )

    try:
        capability = _verified_capability(store, now=now)
        if (
            capability.get("sharePolicySource") is not True
            or capability.get("operations") != ["guard.review.syncPolicyMemory"]
            or not command_environment_allows_queue()
            or local_receipt_redaction_level(store.guard_home) != "none"
        ):
            return None
        oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
        policy = validated_synced_policy_bundle(store)
        if (
            oauth.installation_id != oauth.machine_id
            or not _identifier(oauth.grant_id)
            or (policy is not None and policy.get("receiptRedactionLevel", "none") != "none")
        ):
            return None
        return {
            "capabilityNonce": capability["nonce"],
            "grantId": oauth.grant_id,
            "deviceId": oauth.device_id,
            "workspaceId": oauth.workspace_id,
            "installationId": oauth.installation_id,
        }
    except (CommandCapabilityError, GuardReviewContractError, OSError, ValueError):
        return None


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36 or [value[i] for i in (8, 13, 18, 23)] != ["-"] * 4:
        return False
    try:
        UUID(value)
        return True
    except ValueError:
        return False


def safe_policy_memory_source(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or set(value) != _SOURCE_FIELDS:
        return None
    if (
        value.get("contractVersion") != CONTRACT
        or value.get("complete") is not True
        or value.get("redaction") != "none"
    ):
        return None
    command = valid_exact_command_text(value.get("commandText"))
    if command is None or len(command.encode("utf-16-le")) // 2 > 8192:
        return None
    if not all(_identifier(value.get(key)) for key in ("harnessId", "localRequestId", "workspaceId", "installationId")):
        return None
    if not _uuid(value.get("workspaceId")):
        return None
    artifact = value.get("artifactId")
    if (
        not isinstance(artifact, str)
        or not 1 <= len(artifact) <= 512
        or any(ord(c) < 32 or ord(c) == 127 for c in artifact)
    ):
        return None
    try:
        if len(artifact.encode("utf-16-le")) // 2 > 512:
            return None
    except UnicodeEncodeError:
        return None
    return dict(value)


def _seal(store: GuardStore, payload: dict[str, object], *, purpose: str, now: str) -> dict[str, object] | None:
    key, key_id = store._policy_integrity_secret_material(create=False)
    if key is None or key_id is None:
        return None
    return {
        **payload,
        "integrity": sign_local_authority_payload(payload, key=key, key_id=key_id, purpose=purpose, signed_at=now),
    }


def _verified(store: GuardStore, value: object, *, purpose: str, now: str | None = None) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or set(value) != {"source", "authority", "integrity"}:
        return None
    integrity = value.get("integrity")
    if not isinstance(integrity, Mapping) or value.get("authority") != _disclosure_authority(store, now=now):
        return None
    if value.get("authority") is None:
        return None
    payload = {"source": value["source"], "authority": value["authority"]}
    key, key_id = store._policy_integrity_secret_material(create=False)
    result = verify_local_authority_payload(payload, integrity, key=key, key_id=key_id, purpose=purpose)
    return payload if result.status == "valid" else None


def capture_policy_memory_source_input(
    store: GuardStore,
    *,
    payload: Mapping[str, object],
    artifact_id: str,
    harness: str,
    redaction_level: str,
    now: str | None = None,
    captured: CapturedPolicyMemorySource | None = None,
) -> dict[str, object] | None:
    """Capture only the actual shell field before display normalization."""
    authority = _disclosure_authority(store, now=now)
    if captured is None:
        command = exact_shell_command_from_hook(payload)
    else:
        command = (
            captured.command
            if authority is not None and captured.authority == tuple(sorted(authority.items()))
            else None
        )
    if redaction_level != "none" or authority is None or command is None:
        return None
    source = {
        "contractVersion": CONTRACT,
        "artifactId": artifact_id,
        "commandText": command,
        "harnessId": harness,
        "localRequestId": "pending",
        "workspaceId": authority["workspaceId"],
        "installationId": authority["installationId"],
        "complete": True,
        "redaction": "none",
    }
    if safe_policy_memory_source(source) is None:
        return None
    return _seal(store, {"source": source, "authority": authority}, purpose=_INPUT_CONTRACT, now=now or _now())


def request_policy_memory_envelope(
    store: GuardStore,
    *,
    item: Mapping[str, object],
    envelope: Mapping[str, object] | None,
    request_id: str,
    artifact_id: str,
    harness: str,
    now: str,
) -> dict[str, object] | None:
    clean = {key: value for key, value in (envelope or {}).items() if key not in {_SOURCE_KEY, "policyMemorySource"}}
    verified = _verified(store, item.get(_INPUT_KEY), purpose=_INPUT_CONTRACT, now=now)
    source = safe_policy_memory_source(verified.get("source")) if verified is not None else None
    if (
        verified is not None
        and source is not None
        and source["artifactId"] == artifact_id
        and source["harnessId"] == harness
    ):
        source["localRequestId"] = request_id
        sealed = _seal(store, {"source": source, "authority": verified["authority"]}, purpose=CONTRACT, now=now)
        if sealed is not None:
            clean[_SOURCE_KEY] = sealed
    return clean or None


def verified_request_policy_memory_source(
    store: GuardStore, request: Mapping[str, object], *, now: str | None = None
) -> dict[str, object] | None:
    envelope = request.get("action_envelope_json")
    if not isinstance(envelope, Mapping):
        return None
    payload = _verified(store, envelope.get(_SOURCE_KEY), purpose=CONTRACT, now=now)
    source = safe_policy_memory_source(payload.get("source")) if payload is not None else None
    if source is None or any(
        source[source_key] != request.get(request_key)
        for source_key, request_key in (
            ("localRequestId", "request_id"),
            ("artifactId", "artifact_id"),
            ("harnessId", "harness"),
        )
    ):
        return None
    return source


def bind_persisted_policy_memory_source(
    store: GuardStore, connection: sqlite3.Connection, request: GuardApprovalRequest, request_id: str, now: str
) -> None:
    """Rebind a valid captured source to a deduplicated ID within its insert transaction."""
    row = connection.execute(
        "select action_envelope_json from approval_requests where request_id = ? and oauth_source = ?",
        (request_id, store._guard_source),
    ).fetchone()
    envelope = json.loads(row["action_envelope_json"]) if row is not None and row["action_envelope_json"] else {}
    if not isinstance(envelope, dict):
        return
    verified = verified_request_policy_memory_source(store, request.to_dict(), now=now)
    if _SOURCE_KEY not in envelope:
        return
    wrapper = envelope.pop(_SOURCE_KEY)
    if verified is not None and isinstance(wrapper, Mapping):
        verified["localRequestId"] = request_id
        sealed = _seal(store, {"source": verified, "authority": wrapper["authority"]}, purpose=CONTRACT, now=now)
        if sealed is not None:
            envelope[_SOURCE_KEY] = sealed
    connection.execute(
        "update approval_requests set action_envelope_json = ? where request_id = ? and oauth_source = ?",
        (json.dumps(envelope, sort_keys=True), request_id, store._guard_source),
    )


def policy_memory_receipt_envelope(store: GuardStore, request: Mapping[str, object]) -> dict[str, object] | None:
    """Keep the private local integrity wrapper; ordinary redaction omits it."""
    if verified_request_policy_memory_source(store, request) is None:
        return None
    envelope = request["action_envelope_json"]
    assert isinstance(envelope, Mapping)
    return {_SOURCE_KEY: envelope[_SOURCE_KEY]}


def source_receipt_matches_request(store: GuardStore, request: Mapping[str, object], receipt: object) -> bool:
    expected = verified_request_policy_memory_source(store, request)
    if expected is None:
        return True
    return (
        isinstance(receipt, Mapping)
        and disclosed_receipt_policy_source(store, receipt, redaction_level="none") == expected
    )


def disclosed_receipt_policy_source(
    store: GuardStore, receipt: Mapping[str, object], *, redaction_level: str
) -> dict[str, object] | None:
    if redaction_level != "none":
        return None
    with store._connect() as connection:
        row = connection.execute(
            "select envelope_full_json from runtime_receipt_envelopes where receipt_id = ?",
            (receipt.get("receipt_id"),),
        ).fetchone()
    # Receipt readers may project a newer approval envelope. Disclosure must be
    # committed with this receipt before its upload cursor can pass it.
    envelope = json.loads(row["envelope_full_json"]) if row is not None and row["envelope_full_json"] else None
    return verified_request_policy_memory_source(
        store,
        {**receipt, "request_id": receipt.get("approval_request_id"), "action_envelope_json": envelope},
    )


def attach_disclosed_policy_source(
    payload: dict[str, object], receipt: Mapping[str, object], store: GuardStore | None, *, redaction_level: str
) -> dict[str, object]:
    """Only the currently consented and locally authenticated source may leave."""
    envelope = payload.get("envelopeRedacted")
    clean = dict(envelope) if isinstance(envelope, Mapping) else {}
    clean.pop("policyMemorySource", None)
    source = disclosed_receipt_policy_source(store, receipt, redaction_level=redaction_level) if store else None
    if source is not None:
        clean["policyMemorySource"] = source
    if clean:
        payload["envelopeRedacted"] = clean
    else:
        payload.pop("envelopeRedacted", None)
    return payload


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

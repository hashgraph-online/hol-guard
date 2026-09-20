"""Reconstruct memory authority from its signed inputs and active OAuth binding."""

from __future__ import annotations

from collections.abc import Mapping

from .action_lattice import is_guard_action
from .exact_command_policy import exact_command_policy_digest
from .local_authority_integrity import sign_local_authority_payload, verify_local_authority_payload
from .models import PolicyDecision
from .native_policy_authority_state_keys import REVIEW_MEMORY_REGISTRY_KEY, REVIEW_MEMORY_VERSION_KEY
from .review_contracts import validate_decision_memory_bundle_target, validated_decision_memory_bundle
from .review_memory_application import registered_oauth_for_bundle
from .review_memory_targets import local_memory_match_fields, validate_exact_memory_target
from .review_oauth_binding import GuardReviewContractError, GuardReviewOAuthMetadata, guard_review_oauth_metadata
from .runtime.time_support import parse_utc_timestamp

REGISTRY_KEY = REVIEW_MEMORY_REGISTRY_KEY
VERSION_KEY = REVIEW_MEMORY_VERSION_KEY
ACK_KEY = "guard_review_memory_last_ack"
REGISTRY_CONTRACT = "guard.local-review-memory-authority.v1"


def memory_oauth_authority(store) -> tuple[GuardReviewOAuthMetadata, dict[str, object]]:
    oauth = guard_review_oauth_metadata(store, require_device_dpop_binding=True)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    if not isinstance(credentials, dict) or not oauth.grant_id:
        raise GuardReviewContractError("decision_memory_oauth_binding_missing")
    issuer = text(credentials.get("issuer"))
    client_id = text(credentials.get("client_id"))
    if issuer is None or client_id is None:
        raise GuardReviewContractError("decision_memory_oauth_binding_missing")
    return oauth, {
        "oauthSource": store._guard_source,
        "issuer": issuer,
        "clientId": client_id,
        "grantId": oauth.grant_id,
        "deviceId": oauth.device_id,
        "dpopThumbprint": oauth.dpop_thumbprint,
        "machineId": oauth.machine_id,
        "installationId": oauth.installation_id,
        "runtimeId": oauth.runtime_id,
        "workspaceId": oauth.workspace_id,
    }


def decision_from_memory_rule(
    *,
    bundle: dict[str, object],
    rule: dict[str, object],
    oauth: GuardReviewOAuthMetadata,
) -> PolicyDecision:
    harness = text(rule.get("harnessId"))
    artifact_id = text(rule.get("artifactId"))
    action = text(rule.get("action"))
    scope = text(rule.get("scope"))
    if harness is None or artifact_id is None or action is None or scope is None or not is_guard_action(action):
        raise GuardReviewContractError("invalid_decision_memory_rule")
    if action == "allow" and scope not in {"artifact", "workspace", "project", "machine"}:
        raise GuardReviewContractError("decision_memory_allow_scope_unsupported")
    target = rule.get("target")
    if not isinstance(target, dict):
        raise GuardReviewContractError("decision_memory_target_invalid")
    project_identity = text(rule.get("projectIdentity"))
    validate_exact_memory_target(target, oauth=oauth, project_identity=project_identity)
    workspace, publisher = local_memory_match_fields(
        target,
        oauth=oauth,
        project_identity=project_identity,
        action=action,
        scope=scope,
    )
    bundle_expiry = parse_utc_timestamp(bundle.get("expiresAt"))
    rule_expiry = parse_utc_timestamp(rule.get("expiresAt"))
    if bundle_expiry is None or (rule.get("expiresAt") is not None and rule_expiry is None):
        raise GuardReviewContractError("decision_memory_rule_expiry_invalid")
    expiry = min(bundle_expiry, rule_expiry) if rule_expiry is not None else bundle_expiry
    exact_digest = None
    if "exactCommand" in rule:
        try:
            exact_digest = exact_command_policy_digest(rule["exactCommand"], rule.get("artifactId"), scope=scope)
        except ValueError as error:
            raise GuardReviewContractError("invalid_decision_memory_exact_command") from error
    return PolicyDecision(
        harness=harness,
        scope="workspace" if workspace is not None else "artifact",
        action=action,
        artifact_id=artifact_id,
        artifact_hash=text(rule.get("artifactHash")),
        exact_command_sha256=exact_digest,
        workspace=workspace,
        publisher=publisher,
        reason=text(rule.get("reason")) or "Guard Cloud signed decision memory sync",
        owner=None,
        source="cloud-signed-memory",
        expires_at=expiry.isoformat(),
    )


def bound_registry(value: object, binding: Mapping[str, object], *, store) -> dict[str, object] | None:
    if not isinstance(value, dict) or value.get("contractVersion") != REGISTRY_CONTRACT:
        return None
    if value.get("oauthBinding") != dict(binding):
        return None
    integrity = value.get("integrity")
    if not isinstance(integrity, dict):
        return None
    key, key_id = store._policy_integrity_secret_material(create=False)
    payload = {key: item for key, item in value.items() if key != "integrity"}
    if (
        verify_local_authority_payload(payload, integrity, key=key, key_id=key_id, purpose=REGISTRY_CONTRACT).status
        != "valid"
    ):
        return None
    return value


def registry_entries(
    registry: object,
    *,
    store,
    oauth: GuardReviewOAuthMetadata,
    binding: Mapping[str, object],
    now: str,
) -> dict[str, tuple[dict[str, object], PolicyDecision]]:
    """Only selected rules reconstructable from current signed evidence may match."""
    bound = bound_registry(registry, binding, store=store)
    if bound is None:
        return {}
    bundles = bound.get("bundles")
    selections = bound.get("rules")
    if not isinstance(bundles, dict) or not isinstance(selections, dict):
        return {}
    parsed_now = parse_utc_timestamp(now)
    validated: dict[str, dict[str, object]] = {}
    for digest, payload in bundles.items():
        if not isinstance(digest, str) or not isinstance(payload, dict):
            continue
        try:
            bundle = validated_decision_memory_bundle(payload, store=store)
            if bundle.get("bundleHash") != digest:
                continue
            expiry = parse_utc_timestamp(bundle.get("expiresAt"))
            if expiry is None or parsed_now is None or expiry <= parsed_now:
                continue
            validate_decision_memory_bundle_target(
                bundle=bundle, oauth=registered_oauth_for_bundle(oauth, bound, digest)
            )
            validated[digest] = bundle
        except (GuardReviewContractError, TypeError, ValueError):
            continue
    entries: dict[str, tuple[dict[str, object], PolicyDecision]] = {}
    for rule_id, digest in selections.items():
        bundle = validated.get(digest) if isinstance(digest, str) else None
        if not isinstance(rule_id, str) or bundle is None:
            continue
        rules = bundle.get("memoryRules")
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, dict) or rule.get("ruleId") != rule_id:
                continue
            try:
                decision = decision_from_memory_rule(
                    bundle=bundle, rule=rule, oauth=registered_oauth_for_bundle(oauth, bound, str(digest))
                )
                expiry = parse_utc_timestamp(decision.expires_at)
                if expiry is not None and parsed_now is not None and expiry > parsed_now:
                    entries[rule_id] = (bundle, decision)
            except (GuardReviewContractError, TypeError, ValueError):
                pass
            break
    return entries


def encode_registry(
    entries: Mapping[str, tuple[dict[str, object], PolicyDecision]],
    binding: Mapping[str, object],
    *,
    store,
    now: str,
    acknowledgement: Mapping[str, object],
    registered_installations: Mapping[str, object] | None = None,
) -> dict[str, object]:
    payload = {
        "contractVersion": REGISTRY_CONTRACT,
        "oauthBinding": dict(binding),
        "policyVersion": acknowledgement.get("policyVersion"),
        "bundleHash": acknowledgement.get("bundleHash"),
        "acknowledgement": dict(acknowledgement),
        "bundles": {str(bundle["bundleHash"]): bundle for bundle, _ in entries.values()},
        "registeredInstallations": {
            digest: value
            for digest, value in (registered_installations or {}).items()
            if digest in {str(bundle["bundleHash"]) for bundle, _ in entries.values()}
        },
        "rules": {rule_id: str(bundle["bundleHash"]) for rule_id, (bundle, _) in entries.items()},
    }
    key, key_id = store._policy_integrity_secret_material(create=True)
    if key is None or key_id is None:
        raise GuardReviewContractError("decision_memory_integrity_unavailable")
    return {
        **payload,
        "integrity": sign_local_authority_payload(
            payload,
            key=key,
            key_id=key_id,
            purpose=REGISTRY_CONTRACT,
            signed_at=now,
        ),
    }


def text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None

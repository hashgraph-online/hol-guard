"""Keyring decoding and conservative migration of existing policy anchors."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .policy_bundle_trusted_keys import PolicyBundleVerificationKey


def load_policy_bundle_verification_keys(
    raw: object,
    *,
    require_keyring_contract: bool = False,
) -> tuple[PolicyBundleVerificationKey, ...]:
    """Load policy verification keys, optionally requiring the managed wrapper.

    Bare key lists and ``{"keys": [...]}`` remain supported for legacy local
    stores when ``require_keyring_contract`` is false. Any wrapper metadata
    that is present is still authoritative and must be valid.
    """

    from . import policy_bundle_trusted_keys as _trusted_keys

    raw_keys = raw
    wrapper_purpose: str | None = None
    wrapper_workspace_id: str | None = None
    if require_keyring_contract and not isinstance(raw, dict):
        raise ValueError("invalid_policy_bundle_verification_keyring:wrapper")
    if isinstance(raw, dict):
        wrapper_fields_present = any(field in raw for field in ("contractVersion", "purpose", "workspaceId"))
        validate_wrapper = require_keyring_contract or wrapper_fields_present
        if validate_wrapper and raw.get("contractVersion") != _trusted_keys.POLICY_BUNDLE_KEYRING_CONTRACT_VERSION:
            raise ValueError("invalid_policy_bundle_verification_keyring:contractVersion")
        if validate_wrapper:
            if raw.get("purpose") != _trusted_keys.POLICY_BUNDLE_KEY_PURPOSE:
                raise ValueError("invalid_policy_bundle_verification_keyring:purpose")
            wrapper_purpose = _trusted_keys.POLICY_BUNDLE_KEY_PURPOSE
            workspace_id = raw.get("workspaceId")
            if not isinstance(workspace_id, str) or not workspace_id.strip() or workspace_id != workspace_id.strip():
                raise ValueError("invalid_policy_bundle_verification_keyring:workspaceId")
            wrapper_workspace_id = workspace_id
        raw_keys = raw.get("keys")
        if validate_wrapper and not isinstance(raw_keys, list):
            raise ValueError("invalid_policy_bundle_verification_keyring:keys")
        if validate_wrapper and set(raw) != _trusted_keys._POLICY_BUNDLE_KEYRING_FIELDS:
            raise ValueError("invalid_policy_bundle_verification_keyring:fields")
    if not isinstance(raw_keys, list):
        return ()
    parsed: list[_trusted_keys.PolicyBundleVerificationKey] = []
    seen_key_ids: set[str] = set()
    for item in raw_keys:
        if not isinstance(item, dict):
            raise ValueError("invalid_policy_bundle_verification_keys")
        if require_keyring_contract and not set(item).issubset(_trusted_keys._POLICY_BUNDLE_KEY_FIELDS):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_fields")
        if require_keyring_contract and not {
            "fingerprintSha256",
            "keyId",
            "publicKeyPem",
            "state",
            "purpose",
            "workspaceId",
        }.issubset(item):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_fields")
        parsed_key = _trusted_keys.PolicyBundleVerificationKey.from_dict(item)
        if wrapper_purpose is not None and (
            item.get("purpose") != wrapper_purpose or parsed_key.purpose != wrapper_purpose
        ):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_purpose_mismatch")
        if wrapper_workspace_id is not None and (
            item.get("workspaceId") != wrapper_workspace_id or parsed_key.workspace_id != wrapper_workspace_id
        ):
            raise ValueError("invalid_policy_bundle_verification_keyring:key_workspace_mismatch")
        if parsed_key.key_id in seen_key_ids:
            raise ValueError("invalid_policy_bundle_verification_keys:duplicate_key_id")
        seen_key_ids.add(parsed_key.key_id)
        parsed.append(parsed_key)
    return tuple(parsed)


def migrate_legacy_policy_bundle_anchors(
    *,
    stored_keyring: object,
    sync_keys: tuple[PolicyBundleVerificationKey, ...],
    expected_workspace_id: str | None,
) -> tuple[PolicyBundleVerificationKey, ...]:
    """Scope an exact legacy anchor using authenticated sync metadata.

    Legacy releases persisted the already-trusted key and workspace in a
    snake-case wrapper, but omitted purpose and per-key workspace fields. The
    migration never accepts a new fingerprint: it only enriches an existing
    local anchor when Cloud advertises the same key for the same workspace.
    """

    from . import policy_bundle_trusted_keys as _trusted_keys

    if not isinstance(stored_keyring, dict) or set(stored_keyring) != {"keys", "workspace_id"}:
        return ()
    legacy_workspace_id = stored_keyring.get("workspace_id")
    if (
        not isinstance(expected_workspace_id, str)
        or not expected_workspace_id
        or legacy_workspace_id != expected_workspace_id
    ):
        return ()
    raw_keys = stored_keyring.get("keys")
    if not isinstance(raw_keys, list):
        return ()
    legacy_keys = _trusted_keys.safe_load_policy_bundle_verification_keys(stored_keyring)
    if not legacy_keys or any(key.purpose != "unscoped" or key.workspace_id is not None for key in legacy_keys):
        return ()
    migrated: list[_trusted_keys.PolicyBundleVerificationKey] = []
    for legacy_key in legacy_keys:
        advertised_key = next(
            (
                key
                for key in sync_keys
                if key.key_id == legacy_key.key_id
                and key.fingerprint_sha256 == legacy_key.fingerprint_sha256
                and key.purpose == _trusted_keys.POLICY_BUNDLE_KEY_PURPOSE
                and key.workspace_id == expected_workspace_id
            ),
            None,
        )
        if advertised_key is not None:
            states = {legacy_key.state, advertised_key.state}
            restrictive_state = "active"
            if "revoked" in states:
                restrictive_state = "revoked"
            elif "grace" in states:
                restrictive_state = "grace"
            valid_from_candidates = [
                value for value in (legacy_key.valid_from, advertised_key.valid_from) if value is not None
            ]
            valid_until_candidates = [
                value for value in (legacy_key.valid_until, advertised_key.valid_until) if value is not None
            ]
            migrated.append(
                _trusted_keys.PolicyBundleVerificationKey(
                    key_id=legacy_key.key_id,
                    public_key_pem=legacy_key.public_key_pem,
                    fingerprint_sha256=legacy_key.fingerprint_sha256,
                    state=restrictive_state,
                    purpose=_trusted_keys.POLICY_BUNDLE_KEY_PURPOSE,
                    workspace_id=expected_workspace_id,
                    valid_from=max(
                        valid_from_candidates,
                        key=lambda value: _trusted_keys._parse_iso_timestamp(value, field_name="validFrom"),
                        default=None,
                    ),
                    valid_until=min(
                        valid_until_candidates,
                        key=lambda value: _trusted_keys._parse_iso_timestamp(value, field_name="validUntil"),
                        default=None,
                    ),
                )
            )
    return tuple(migrated)

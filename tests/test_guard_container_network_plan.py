from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from codex_plugin_scanner.guard.runtime.container_network_plan import (
    ContainerNetworkPlanError,
    ContainerNetworkReceiptOutcome,
    ExclusiveProxyEgressControls,
    build_verified_container_network_plan,
    issue_container_network_receipt,
)
from codex_plugin_scanner.guard.runtime.containment_contract import (
    ContainmentNetworkMode,
    ContainmentPolicy,
)
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    GuardExecutionAssuranceBoundary,
)
from codex_plugin_scanner.guard.runtime.oci_plan_generator import (
    OCIExecutionPlan,
    OCIPlanNamespace,
    OCIPlanNetwork,
)


def _oci_plan(
    *,
    isolated: bool = True,
    loopback_only: bool = True,
    ports: tuple[str, ...] = (),
    network_mode: str = "none",
) -> OCIExecutionPlan:
    return OCIExecutionPlan(
        plan_digest="a" * 64,
        bundle_version="1.2.0",
        minimum_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
        available_boundary=GuardExecutionAssuranceBoundary.OS_ISOLATED,
        boundary_lowered=False,
        network=OCIPlanNetwork(mode=network_mode, port_mappings=ports, loopback_only=loopback_only),
        namespaces=OCIPlanNamespace(
            pid_isolated=True,
            net_isolated=isolated,
            ipc_isolated=True,
            uts_isolated=True,
            user_isolated=True,
        ),
    )


def _proxy_controls(
    *,
    oci_plan_digest: str = "a" * 64,
    namespace_identity_digest: str = "d" * 64,
    signing_key: Ed25519PrivateKey,
    observation_nonce: str = "e" * 64,
    observed_at_epoch_ms: int = 100,
    expires_at_epoch_ms: int = 5_100,
) -> ExclusiveProxyEgressControls:
    unsigned = ExclusiveProxyEgressControls(
        oci_plan_digest=oci_plan_digest,
        proxy_endpoint_digest="b" * 64,
        namespace_identity_digest=namespace_identity_digest,
        route_attestation_digest="c" * 64,
        direct_egress_denied=True,
        proxy_only=True,
        observation_nonce=observation_nonce,
        observed_at_epoch_ms=observed_at_epoch_ms,
        expires_at_epoch_ms=expires_at_epoch_ms,
        verifier_signature="0" * 128,
    )
    return replace(unsigned, verifier_signature=signing_key.sign(unsigned.digest.encode()).hex())


def _key_digest(signing_key: Ed25519PrivateKey) -> str:
    return sha256(signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def test_offline_plan_binds_verified_namespace_to_policy(tmp_path: Path) -> None:
    policy = ContainmentPolicy(str(tmp_path), ())

    first = build_verified_container_network_plan(oci_plan=_oci_plan(), containment_policy=policy)
    second = build_verified_container_network_plan(oci_plan=_oci_plan(), containment_policy=policy)

    assert first == second
    assert first.loopback_only is True
    assert first.oci_plan_digest == "a" * 64
    assert len(first.plan_digest) == 64


@pytest.mark.parametrize(
    ("oci_plan", "message"),
    [
        (_oci_plan(isolated=False), "isolated network namespace"),
        (_oci_plan(loopback_only=False), "loopback-only"),
        (_oci_plan(ports=("8080:80",)), "must not publish ports"),
    ],
)
def test_offline_plan_fails_closed(oci_plan: OCIExecutionPlan, message: str, tmp_path: Path) -> None:
    with pytest.raises(ContainerNetworkPlanError, match=message):
        build_verified_container_network_plan(
            oci_plan=oci_plan,
            containment_policy=ContainmentPolicy(str(tmp_path), ()),
        )


def test_proxy_only_plan_requires_digest_bound_exclusive_controls(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    policy = ContainmentPolicy(
        str(tmp_path),
        (),
        network_mode=ContainmentNetworkMode.GUARDED_PROXY,
        proxy_endpoint_digest="b" * 64,
        proxy_verifier_key_digest=_key_digest(signing_key),
    )
    oci_plan = _oci_plan(network_mode="bridge", loopback_only=False)

    with pytest.raises(ContainerNetworkPlanError, match="exclusive proxy egress controls"):
        build_verified_container_network_plan(oci_plan=oci_plan, containment_policy=policy)
    controls = _proxy_controls(signing_key=signing_key)
    plan = build_verified_container_network_plan(
        oci_plan=oci_plan,
        containment_policy=policy,
        proxy_egress_controls=controls,
        control_verifier_public_key=signing_key.public_key(),
    )

    assert plan.mode is ContainmentNetworkMode.GUARDED_PROXY
    assert plan.proxy_endpoint_digest == "b" * 64
    assert plan.proxy_egress_controls_digest == controls.control_state_digest
    assert plan.loopback_only is False


def test_proxy_only_plan_rejects_mismatched_control_binding(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    policy = ContainmentPolicy(
        str(tmp_path),
        (),
        network_mode=ContainmentNetworkMode.GUARDED_PROXY,
        proxy_endpoint_digest="b" * 64,
        proxy_verifier_key_digest=_key_digest(signing_key),
    )
    oci_plan = _oci_plan(network_mode="bridge", loopback_only=False)
    controls = _proxy_controls(oci_plan_digest="d" * 64, signing_key=signing_key)
    with pytest.raises(ContainerNetworkPlanError, match="do not match the OCI plan"):
        build_verified_container_network_plan(
            oci_plan=oci_plan,
            containment_policy=policy,
            proxy_egress_controls=controls,
            control_verifier_public_key=signing_key.public_key(),
        )


def test_proxy_only_plan_rejects_untrusted_control_verifier(tmp_path: Path) -> None:
    trusted_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    policy = ContainmentPolicy(
        str(tmp_path),
        (),
        network_mode=ContainmentNetworkMode.GUARDED_PROXY,
        proxy_endpoint_digest="b" * 64,
        proxy_verifier_key_digest=_key_digest(trusted_key),
    )

    with pytest.raises(ContainerNetworkPlanError, match="trusted containment policy"):
        build_verified_container_network_plan(
            oci_plan=_oci_plan(network_mode="bridge", loopback_only=False),
            containment_policy=policy,
            proxy_egress_controls=_proxy_controls(signing_key=attacker_key),
            control_verifier_public_key=attacker_key.public_key(),
        )


def test_proxy_only_plan_rejects_forged_control_attestation(tmp_path: Path) -> None:
    verifier_key = Ed25519PrivateKey.generate()
    policy = ContainmentPolicy(
        str(tmp_path),
        (),
        network_mode=ContainmentNetworkMode.GUARDED_PROXY,
        proxy_endpoint_digest="b" * 64,
        proxy_verifier_key_digest=_key_digest(verifier_key),
    )
    controls = _proxy_controls(signing_key=Ed25519PrivateKey.generate())

    with pytest.raises(ContainerNetworkPlanError, match="attestation is invalid"):
        build_verified_container_network_plan(
            oci_plan=_oci_plan(network_mode="bridge", loopback_only=False),
            containment_policy=policy,
            proxy_egress_controls=controls,
            control_verifier_public_key=verifier_key.public_key(),
        )


def test_proxy_only_plan_rejects_unrouted_network(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    policy = ContainmentPolicy(
        str(tmp_path),
        (),
        network_mode=ContainmentNetworkMode.GUARDED_PROXY,
        proxy_endpoint_digest="b" * 64,
        proxy_verifier_key_digest=_key_digest(signing_key),
    )

    with pytest.raises(ContainerNetworkPlanError, match="isolated bridge"):
        build_verified_container_network_plan(oci_plan=_oci_plan(), containment_policy=policy)


def test_proxy_receipt_requires_fresh_nonce_bound_observation(tmp_path: Path) -> None:
    signing_key = Ed25519PrivateKey.generate()
    policy = ContainmentPolicy(
        str(tmp_path),
        (),
        network_mode=ContainmentNetworkMode.GUARDED_PROXY,
        proxy_endpoint_digest="b" * 64,
        proxy_verifier_key_digest=_key_digest(signing_key),
    )
    controls = _proxy_controls(signing_key=signing_key)
    plan = build_verified_container_network_plan(
        oci_plan=_oci_plan(network_mode="bridge", loopback_only=False),
        containment_policy=policy,
        proxy_egress_controls=controls,
        control_verifier_public_key=signing_key.public_key(),
    )

    def observe(nonce: str) -> ExclusiveProxyEgressControls:
        return _proxy_controls(
            signing_key=signing_key,
            observation_nonce=nonce,
            observed_at_epoch_ms=1_000,
            expires_at_epoch_ms=6_000,
        )

    receipt = issue_container_network_receipt(
        plan=plan,
        namespace_identity_digest="d" * 64,
        observed_at_epoch_ms=1_001,
        outcome=ContainerNetworkReceiptOutcome.ENFORCED,
        control_observer=observe,
        control_verifier_public_key=signing_key.public_key(),
    )
    assert receipt.outcome is ContainerNetworkReceiptOutcome.ENFORCED

    with pytest.raises(ContainerNetworkPlanError, match="live proxy controls"):
        issue_container_network_receipt(
            plan=plan,
            namespace_identity_digest="d" * 64,
            observed_at_epoch_ms=1_001,
            outcome=ContainerNetworkReceiptOutcome.ENFORCED,
            control_observer=lambda _nonce: controls,
            control_verifier_public_key=signing_key.public_key(),
        )


def test_container_receipt_binds_plan_namespace_and_outcome(tmp_path: Path) -> None:
    plan = build_verified_container_network_plan(
        oci_plan=_oci_plan(),
        containment_policy=ContainmentPolicy(str(tmp_path), ()),
    )

    receipt = issue_container_network_receipt(
        plan=plan,
        namespace_identity_digest="c" * 64,
        observed_at_epoch_ms=123,
        outcome=ContainerNetworkReceiptOutcome.ENFORCED,
    )

    assert receipt.plan_digest == plan.plan_digest
    assert receipt.namespace_identity_digest == "c" * 64
    assert len(receipt.receipt_digest) == 64


def test_container_receipt_rejects_raw_namespace_identity(tmp_path: Path) -> None:
    plan = build_verified_container_network_plan(
        oci_plan=_oci_plan(),
        containment_policy=ContainmentPolicy(str(tmp_path), ()),
    )

    with pytest.raises(ContainerNetworkPlanError, match="namespace identity"):
        issue_container_network_receipt(
            plan=plan,
            namespace_identity_digest="/proc/123/ns/net:[4026531992]",
            observed_at_epoch_ms=123,
            outcome=ContainerNetworkReceiptOutcome.ENFORCED,
        )

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentNetworkMode, ContainmentPolicy
from codex_plugin_scanner.guard.runtime.linux_namespace_network_plan import (
    LinuxProxyNamespaceRoute,
    build_linux_namespace_network_plan,
    create_linux_proxy_namespace_route,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import ProcessTreeIdentity

BROKER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
TRUSTED_BROKER_PUBLIC_KEY = (
    BROKER_PRIVATE_KEY.public_key()
    .public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    .hex()
)


def _tree() -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.alpha", "session.alpha", 123, 456, "a" * 64)


def _route() -> LinuxProxyNamespaceRoute:
    return create_linux_proxy_namespace_route("169.254.240.2", "169.254.240.1", 3128, 99, "c" * 64, BROKER_PRIVATE_KEY)


def _policy(tmp_path: Path, mode: ContainmentNetworkMode) -> ContainmentPolicy:
    endpoint = _route().digest if mode is ContainmentNetworkMode.GUARDED_PROXY else None
    verifier_digest = (
        sha256(bytes.fromhex(TRUSTED_BROKER_PUBLIC_KEY)).hexdigest()
        if mode is ContainmentNetworkMode.GUARDED_PROXY
        else None
    )
    return ContainmentPolicy(str(tmp_path), (), mode, endpoint, verifier_digest)


def test_offline_namespace_has_no_external_or_host_route(tmp_path: Path) -> None:
    plan = build_linux_namespace_network_plan(
        _policy(tmp_path, ContainmentNetworkMode.OFFLINE), _tree(), workload_owner_uid=1000
    )

    assert plan.loopback_up
    assert not plan.default_route_present
    assert not plan.host_namespace_reachable
    assert plan.proxy_route is None
    assert (
        plan.digest
        == build_linux_namespace_network_plan(
            _policy(tmp_path, ContainmentNetworkMode.OFFLINE), _tree(), workload_owner_uid=1000
        ).digest
    )


def test_proxy_namespace_exposes_only_attested_broker_route(tmp_path: Path) -> None:
    plan = build_linux_namespace_network_plan(
        _policy(tmp_path, ContainmentNetworkMode.GUARDED_PROXY),
        _tree(),
        workload_owner_uid=1000,
        proxy_route=_route(),
        trusted_broker_public_key=TRUSTED_BROKER_PUBLIC_KEY,
    )

    assert not plan.default_route_present
    assert not plan.host_namespace_reachable
    assert plan.proxy_route is not None
    assert plan.proxy_route == _route()
    assert plan.proxy_route.digest == _route().digest


def test_namespace_plan_rejects_root_and_endpoint_mismatch(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unprivileged UID"):
        _ = build_linux_namespace_network_plan(
            _policy(tmp_path, ContainmentNetworkMode.OFFLINE), _tree(), workload_owner_uid=0
        )
    mismatched = replace(_route(), broker_address="169.254.240.9")
    with pytest.raises(ValueError, match="must match"):
        _ = build_linux_namespace_network_plan(
            _policy(tmp_path, ContainmentNetworkMode.GUARDED_PROXY),
            _tree(),
            workload_owner_uid=1000,
            proxy_route=mismatched,
            trusted_broker_public_key=TRUSTED_BROKER_PUBLIC_KEY,
        )

    attacker_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    attacker_route = create_linux_proxy_namespace_route(
        "169.254.240.2", "169.254.240.1", 3128, 99, "c" * 64, attacker_key
    )
    attacker_policy = ContainmentPolicy(
        str(tmp_path),
        (),
        ContainmentNetworkMode.GUARDED_PROXY,
        attacker_route.digest,
        sha256(bytes.fromhex(TRUSTED_BROKER_PUBLIC_KEY)).hexdigest(),
    )
    with pytest.raises(ValueError, match="trusted containment endpoint"):
        _ = build_linux_namespace_network_plan(
            attacker_policy,
            _tree(),
            workload_owner_uid=1000,
            proxy_route=attacker_route,
            trusted_broker_public_key=TRUSTED_BROKER_PUBLIC_KEY,
        )

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentNetworkMode, ContainmentPolicy
from codex_plugin_scanner.guard.runtime.linux_namespace_network_plan import (
    LinuxProxyNamespaceRoute,
    build_linux_namespace_network_plan,
)
from codex_plugin_scanner.guard.runtime.network_policy_contract import ProcessTreeIdentity


def _tree() -> ProcessTreeIdentity:
    return ProcessTreeIdentity("install.alpha", "session.alpha", 123, 456, "a" * 64)


def _policy(tmp_path: Path, mode: ContainmentNetworkMode) -> ContainmentPolicy:
    endpoint = "b" * 64 if mode is ContainmentNetworkMode.GUARDED_PROXY else None
    return ContainmentPolicy(str(tmp_path), (), mode, endpoint)


def _route() -> LinuxProxyNamespaceRoute:
    return LinuxProxyNamespaceRoute("169.254.240.2", "169.254.240.1", 3128, 99, "c" * 64, "b" * 64)


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
    )

    assert not plan.default_route_present
    assert not plan.host_namespace_reachable
    assert plan.proxy_route is not None
    assert plan.proxy_route == _route()
    assert plan.proxy_route.endpoint_digest == "b" * 64


def test_namespace_plan_rejects_root_and_endpoint_mismatch(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unprivileged UID"):
        _ = build_linux_namespace_network_plan(
            _policy(tmp_path, ContainmentNetworkMode.OFFLINE), _tree(), workload_owner_uid=0
        )
    mismatched = LinuxProxyNamespaceRoute("169.254.240.2", "169.254.240.1", 3128, 99, "c" * 64, "d" * 64)
    with pytest.raises(ValueError, match="must match"):
        _ = build_linux_namespace_network_plan(
            _policy(tmp_path, ContainmentNetworkMode.GUARDED_PROXY),
            _tree(),
            workload_owner_uid=1000,
            proxy_route=mismatched,
        )

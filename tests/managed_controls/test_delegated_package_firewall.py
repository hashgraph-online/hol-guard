from __future__ import annotations

import pytest

from tests.managed_controls.delegation import (
    DelegationError,
    EnforcementPlane,
    compile_delegated_control,
    require_package_firewall_path,
)


def test_package_extension_compiles_through_package_firewall() -> None:
    control = compile_delegated_control(
        extension_id="command.package.node",
        permission_id="command.package.node.permission.package-protection",
        delegated_protection="package-firewall",
        blocked=True,
    )
    assert control.enforcement_plane is EnforcementPlane.PACKAGE_FIREWALL
    require_package_firewall_path(control)


def test_command_extension_stays_on_command_plane() -> None:
    control = compile_delegated_control(
        extension_id="command.git",
        permission_id="push",
        delegated_protection=None,
        blocked=False,
    )
    assert control.enforcement_plane is EnforcementPlane.COMMAND


def test_package_extension_cannot_default_to_command_plane() -> None:
    with pytest.raises(DelegationError):
        compile_delegated_control(
            extension_id="command.package.node",
            permission_id="command.package.node.permission.package-protection",
            delegated_protection=None,
            blocked=True,
        )


def test_command_extension_cannot_claim_package_firewall_delegation() -> None:
    with pytest.raises(DelegationError):
        compile_delegated_control(
            extension_id="command.git",
            permission_id="push",
            delegated_protection="package-firewall",
            blocked=True,
        )


def test_unknown_extension_cannot_claim_package_firewall_delegation() -> None:
    with pytest.raises(DelegationError):
        compile_delegated_control(
            extension_id="command.package.unregistered",
            permission_id=None,
            delegated_protection="package-firewall",
            blocked=True,
        )

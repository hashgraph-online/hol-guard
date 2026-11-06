"""One-way migration of legacy network-domain settings into network policy intent."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.network_policy_contract import NetworkAction


@dataclass(frozen=True, slots=True)
class MigratedNetworkDomainAction:
    action: NetworkAction
    sandbox_required: bool = False


def migrate_new_network_domain_action(action: GuardAction) -> MigratedNetworkDomainAction:
    """Translate the legacy review action without creating a second decision authority."""

    if action == "allow":
        return MigratedNetworkDomainAction(NetworkAction.ALLOW)
    if action == "block":
        return MigratedNetworkDomainAction(NetworkAction.DENY)
    if action == "sandbox-required":
        # Existing Guard containment is deliberately network-disabled. Preserve
        # that stronger invariant instead of treating sandbox review as approval.
        return MigratedNetworkDomainAction(NetworkAction.DENY, sandbox_required=True)
    return MigratedNetworkDomainAction(NetworkAction.APPROVE)

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.network_capability_contract import NetworkPrivacyPolicy


def test_ledger_limits_come_from_validated_privacy_policy() -> None:
    with pytest.raises(ValueError, match="retention_seconds"):
        _ = NetworkPrivacyPolicy(
            raw_destination_enabled=False,
            retention_seconds=59,
            maximum_events=2,
        )

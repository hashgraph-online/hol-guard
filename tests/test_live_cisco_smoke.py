"""Live smoke coverage for the real Cisco skill-scanner integration."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from codex_plugin_scanner.integrations.cisco_skill_scanner import CiscoIntegrationStatus
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("skill_scanner") is None,
    reason="cisco-ai-skill-scanner is not installed in this environment",
)


def test_live_cisco_scan_on_good_plugin() -> None:
    result = scan_plugin(FIXTURES / "good-plugin", ScanOptions(cisco_skill_scan="on", cisco_policy="balanced"))

    integration = next(item for item in result.integrations if item.name == "cisco-skill-scanner")
    skill_security = next(category for category in result.categories if category.name == "Skill Security")

    assert integration.status == CiscoIntegrationStatus.ENABLED
    assert integration.findings_count == 0
    assert sum(check.points for check in skill_security.checks) == sum(
        check.max_points for check in skill_security.checks
    )

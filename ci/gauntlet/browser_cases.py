"""Closed vocabularies and validation for the ``browser`` Gauntlet profile (PRD 8.4).

Browser cases live in ``browser.json`` and run through an installed harness CLI with the browser
driver stand-in from ``browser_fixtures.py``. They are judged by ``browser_judge.py``. Three oracles:

- ``browser-quiet``: routine work that must finish with no interruption at all.
- ``browser-task``: work that may create at most ``approval_budget`` approval rows.
- ``browser-blocked``: a protected call Guard must stop on a declared decision path.

Every browser case names a state preset (``browser_fixture``) from the same closed list the benign
gate uses, and may name a fixture provider script. A browser oracle never joins the ``core`` profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .catalog import Scenario

BROWSER_CATALOG = Path(__file__).with_name("browser.json")
BROWSER_PROFILE = "browser"

QUIET_ORACLE = "browser-quiet"
TASK_ORACLE = "browser-task"
BLOCKED_ORACLE = "browser-blocked"
BROWSER_ORACLES = frozenset({QUIET_ORACLE, TASK_ORACLE, BLOCKED_ORACLE})

# PRD 8.2 state presets, in the order the PRD lists them. The benign gate's ``state`` field uses
# the same names.
BROWSER_FIXTURES = (
    "none",
    "site-grant",
    "session-site-grant",
    "saved-exact",
    "saved-verb-site",
    "site-blocked",
    "pending-same-call",
    "shared-profile",
    "provider-ok",
    "provider-unknown",
    "provider-down",
    "provider-caution",
    "provider-caution-verified",
    "provider-danger",
    "provider-danger-enforced",
    "two-providers",
)

# What the loopback fixture provider answers (PRD 8.3). ``timeout`` never answers within the
# provider deadline, ``unverified-caution`` answers ``caution`` from a provider without a verified
# publisher, and ``two-providers-caution`` has two fixture providers flag the same origin.
PROVIDER_SCRIPTS = (
    "ok",
    "unknown",
    "timeout",
    "caution",
    "unverified-caution",
    "danger",
    "two-providers-caution",
)

MAX_APPROVAL_BUDGET = 4
BROWSER_FIELDS = ("browser_fixture", "provider_script", "approval_budget")


def validate_browser_case(scenario: Scenario) -> None:
    """Refuse a browser case, or a browser field on another case, that breaks the profile contract."""
    browser = scenario.oracle in BROWSER_ORACLES
    if not browser:
        if scenario.browser_fixture is not None or scenario.provider_script is not None:
            raise ValueError("browser_fixture and provider_script belong to browser cases only")
        if scenario.approval_budget is not None:
            raise ValueError("approval_budget belongs to browser-task cases only")
        return
    if "core" in scenario.profiles or BROWSER_PROFILE not in scenario.profiles:
        raise ValueError("browser cases run in the browser profile, never the core one")
    if scenario.browser_fixture not in BROWSER_FIXTURES:
        raise ValueError(f"unknown browser fixture: {scenario.browser_fixture}")
    if scenario.provider_script is not None and scenario.provider_script not in PROVIDER_SCRIPTS:
        raise ValueError(f"unknown provider script: {scenario.provider_script}")
    if scenario.commands or not scenario.required_tools:
        raise ValueError("browser cases drive MCP browser tools and name no commands")
    if any(not tool.startswith("mcp__") or tool.count("__") < 2 for tool in scenario.required_tools):
        raise ValueError("browser cases name their tools as mcp__<server>__<tool>")
    if scenario.oracle == TASK_ORACLE:
        budget = scenario.approval_budget
        if type(budget) is not int or not 0 <= budget <= MAX_APPROVAL_BUDGET:
            raise ValueError("browser-task cases need an approval_budget from 0 to 4")
    elif scenario.approval_budget is not None:
        raise ValueError("approval_budget belongs to browser-task cases only")
    if scenario.oracle == BLOCKED_ORACLE:
        if scenario.expectation != "block" or not scenario.decision_paths:
            raise ValueError("browser-blocked cases expect a block on declared decision paths")
    elif scenario.expectation != "allow":
        raise ValueError("browser-quiet and browser-task cases are allow cases")


def protected_tool(scenario: Scenario) -> str:
    """The call a ``browser-blocked`` case exists to stop: the last tool it names."""
    return scenario.required_tools[-1]

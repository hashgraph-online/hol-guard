"""Pin the Codex hook shape issues both runtimes must report identically.

``codex_hook_inventory.py`` and ``rust/crates/guard-runtime/src/codex_hooks.rs``
walk the same Codex source on two different routes: the CLI install path reads
the Python inventory, while detection reads the native one. Nothing made them
agree on which shapes they refuse or on the wording they refuse them with, so a
repair message could drift on one route while the other kept the old text.

The fixture records the warning each malformed shape produces, in order, for
both sides, together with the coordinate and the two execution flags of every
record the walk keeps. It records no identity: a record carries the identity
the resident derives for it, so the identities themselves cannot be replayed
without a paired native runtime, while the shape walk that produces these
coordinates is ordinary Python on one side and ordinary Rust on the other.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.codex_hook_inventory import (
    CodexHookInventory,
    CodexHookInventoryIssue,
    enumerate_codex_hooks,
)

FIXTURE = Path(__file__).parent / "fixtures" / "codex-hook-inventory.v1.json"
# The resident owns hook identity, so a source it cannot answer for reports an
# identity issue of its own. The native walk never raises one, and the shape
# issues this fixture pins are unaffected by it.
IDENTITY_PREFIX = "native_codex_hook_"


def _warning(issue: CodexHookInventoryIssue) -> str:
    return f"{issue.reason_code}: {issue.coordinate} in {issue.source_path}. {issue.message}"


def _cases() -> list[dict[str, object]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert document["schema"] == "codex-hook-inventory-parity.v1"
    return document["cases"]


def _inventory(case: dict[str, object]) -> CodexHookInventory:
    source = case["source"]
    return enumerate_codex_hooks(
        case["payload"],
        source_path=Path(source["path"]),
        source_scope=source["scope"],
        source_format=source["format"],
        source_hooks_enabled=source["hooks_enabled"],
        authenticated_bindings=case["authenticated"],
        legacy_bindings=case["legacy"],
    )


def _warnings(inventory: CodexHookInventory) -> list[str]:
    return [_warning(issue) for issue in inventory.issues if not issue.reason_code.startswith(IDENTITY_PREFIX)]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_shape_issues_still_describe_the_source(case: dict[str, object]) -> None:
    assert _warnings(_inventory(case)) == case["warnings"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_recorded_handlers_keep_their_coordinates_and_execution_flags(case: dict[str, object]) -> None:
    """A valid shape has to keep producing its records, not merely stay quiet.

    The resident owns hook identity, so a run without one hands back no records
    at all and reports that as its own issue. There is nothing to compare then;
    the native side of this fixture still replays the same records with no
    resident in sight.
    """

    inventory = _inventory(case)
    if any(issue.reason_code.startswith(IDENTITY_PREFIX) for issue in inventory.issues):
        pytest.skip("hook identity needs a paired native runtime")
    recorded = [
        {"coordinate": record.coordinate, "active": record.active, "executable": record.executable}
        for record in inventory.records
    ]
    assert recorded == case["records"]


def test_the_fixture_covers_every_shape_issue_guard_reports() -> None:
    reported = {warning.split(":", 1)[0] for case in _cases() for warning in case["warnings"]}
    assert reported == {
        "codex_hook_inventory_malformed_group",
        "codex_hook_inventory_malformed_handler",
        "codex_hook_inventory_unknown_handler_type",
        "codex_hook_inventory_unsupported_event_shape",
    }

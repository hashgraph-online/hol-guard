"""Kim action-class risk registration tests.

Runtime behavior for the kim extension is covered by the portable compiler
fixture (tests/fixtures/command-source-kim.v1.json), which the native source
compiler executes without target execution. This module pins the static
action-class to risk-class mapping only.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import (
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_kim_extensions import (
    KIM_ACTION_RISK_CLASSES,
)


def test_kim_action_classes_map_to_runtime_risk_classes() -> None:
    """Every kim action class resolves to the same destructive-shell risk set."""

    for action_class, risk_classes in KIM_ACTION_RISK_CLASSES.items():
        assert risk_classes_for_command_action(action_class) == risk_classes

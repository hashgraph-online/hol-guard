from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.package_execution_policy import is_execution_permitted


@pytest.mark.parametrize("action", ["allow", "warn"])
def test_explicitly_permitting_package_actions_allow_execution(action: str) -> None:
    assert is_execution_permitted(action) is True


@pytest.mark.parametrize(
    "action",
    ["monitor", "ask", "block", "review", "", None, object()],
)
def test_every_other_package_action_fails_closed(action: object) -> None:
    assert is_execution_permitted(action) is False

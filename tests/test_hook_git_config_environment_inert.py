"""The Python hook sender marks editor-exported core.quotePath entries like the native one."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    git_config_environment_inert,
    stamp_hook_input_text,
)

# Mirrors the cases in guard-contracts' execution_environment_tests.rs.
GIT_CONFIG_CASES = [
    ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.quotePath", "GIT_CONFIG_VALUE_0": "false"}, True),
    (
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.quotepath",
            "GIT_CONFIG_VALUE_0": "off",
            "GIT_CONFIG_KEY_1": "CORE.QUOTEPATH",
            "GIT_CONFIG_VALUE_1": "true",
        },
        True,
    ),
    (
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.quotePath",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.pager",
            "GIT_CONFIG_VALUE_1": "sh -c id",
        },
        True,
    ),
    ({}, False),
    ({"GIT_CONFIG_COUNT": "1"}, False),
    ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.quotePath"}, False),
    ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.pager", "GIT_CONFIG_VALUE_0": "less"}, False),
    ({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "./x"}, False),
    (
        {
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.quotePath",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "include.path",
            "GIT_CONFIG_VALUE_1": "/tmp/x",
        },
        False,
    ),
    ({"GIT_CONFIG_COUNT": "1k", "GIT_CONFIG_KEY_0": "core.quotePath", "GIT_CONFIG_VALUE_0": "false"}, False),
    ({"GIT_CONFIG_COUNT": "9"}, False),
    ({"GIT_CONFIG_COUNT": ""}, False),
    ({"GIT_CONFIG_COUNT": "+1"}, False),
]


@pytest.mark.parametrize(("entries", "expected"), GIT_CONFIG_CASES)
def test_python_sender_marks_only_quote_path_entries(
    monkeypatch: pytest.MonkeyPatch,
    entries: dict[str, str],
    expected: bool,
) -> None:
    for name in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1"):
        monkeypatch.delenv(name, raising=False)
    for name, value in entries.items():
        monkeypatch.setenv(name, value)

    context = json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY]

    assert git_config_environment_inert(entries) is expected
    # The key is present only when true, and no value is ever sent.
    assert ("git_config_environment_inert" in context) is expected
    if expected:
        assert context["git_config_environment_inert"] is True
    assert "quotePath" not in json.dumps(context)

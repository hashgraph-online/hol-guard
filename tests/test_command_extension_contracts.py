"""Regression coverage for declarative command-extension contract assertions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import command_extension_contracts


@pytest.fixture(autouse=True)
def _stub_native_review_for_diagnostic_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    # These tests exercise error aggregation with stubbed inspection and runtime
    # results; native semantics are covered by the extension contract suites.
    monkeypatch.setattr(
        command_extension_contracts,
        "real_native_command_evaluation",
        lambda command, **_: SimpleNamespace(evaluation=SimpleNamespace(command=command)),
    )


def test_reviewed_cases_report_every_failing_command(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        command_extension_contracts,
        "inspect_command",
        lambda command, **_: {
            "status": "no_match",
            "classification": {},
            "rules": [],
            "controlling_rule_id": None,
        },
    )
    monkeypatch.setattr(
        command_extension_contracts,
        "extract_sensitive_tool_action_request",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(AssertionError) as error:
        command_extension_contracts.assert_reviewed_command_cases(
            (
                ("first destructive command", "destructive", "rule.first"),
                ("second destructive command", "destructive", "rule.second"),
            ),
            tmp_path,
        )

    message = str(error.value)
    assert "first destructive command" in message
    assert "second destructive command" in message


def test_safe_cases_report_every_unexpected_review(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        command_extension_contracts,
        "inspect_command",
        lambda command, **_: {"status": "review"},
    )
    monkeypatch.setattr(
        command_extension_contracts,
        "extract_sensitive_tool_action_request",
        lambda *_args, **_kwargs: SimpleNamespace(action_class="unexpected"),
    )

    with pytest.raises(AssertionError) as error:
        command_extension_contracts.assert_safe_command_cases(
            ("first safe command", "second safe command"),
            tmp_path,
        )

    message = str(error.value)
    assert "first safe command" in message
    assert "second safe command" in message

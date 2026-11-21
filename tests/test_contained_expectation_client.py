"""The contained sink takes the receipt a planned run must carry from native authority.

`contained_expectation.rs` owns the reason and profile table; these tests pin
only how the Python client reads its answer, and that it refuses any answer it
cannot use instead of running with a guessed profile.
"""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime.contained_test_request import contained_expectation
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError


def _answer(monkeypatch: pytest.MonkeyPatch, reply: object) -> list[tuple[str, dict[str, object]]]:
    asked: list[tuple[str, dict[str, object]]] = []

    def native(operation: str, fields: dict[str, object], _expected: object) -> object:
        asked.append((operation, fields))
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(transport, "restricted_native", native)
    return asked


def test_the_resident_answer_names_the_reason_and_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _answer(
        monkeypatch,
        {"reason": "native_pytest_readonly_containment_required", "profile": "pytest-readonly-v2"},
    )

    assert contained_expectation("pytest", None, ["pytest", "-q"]) == (
        "native_pytest_readonly_containment_required",
        "pytest-readonly-v2",
    )
    assert asked == [("contained_expectation", {"kind": "pytest", "plan_profile": None, "command": ["pytest", "-q"]})]


@pytest.mark.parametrize(
    "reply",
    [
        None,
        ["native_pytest_readonly_containment_required", "pytest-readonly-v2"],
        {"reason": "native_pytest_readonly_containment_required"},
        {"reason": "native_pytest_readonly_containment_required", "profile": 2},
        {"reason": None, "profile": "pytest-readonly-v2"},
        {
            "reason": "native_pytest_readonly_containment_required",
            "profile": "pytest-readonly-v2",
            "extra": True,
        },
    ],
)
def test_an_answer_it_cannot_use_refuses_the_run(monkeypatch: pytest.MonkeyPatch, reply: object) -> None:
    _answer(monkeypatch, reply)

    with pytest.raises(RestrictedPytestError):
        contained_expectation("pytest", None, ["pytest", "-q"])


def test_a_resident_refusal_refuses_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, RestrictedPytestError("contained_expectation_invalid", "no expectation"))

    with pytest.raises(RestrictedPytestError):
        contained_expectation("node_tool", "pytest-readonly-v2", ["vite", "build"])

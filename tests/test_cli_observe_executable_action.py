"""The resident names the action observe mode records as executable."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_review as review
from codex_plugin_scanner.guard.native_hook_artifact_compose import NativeHookComposeError


def _state(composition: object, package_action: str | None) -> Any:
    return SimpleNamespace(
        response_payload={"policy_composition": composition},
        package_evaluation=SimpleNamespace(policy_action=package_action),
        guard_home=None,
    )


def test_every_composed_source_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, object] = {}

    def _compose(kind: str, fields: dict[str, object], *, guard_home: object) -> dict[str, object]:
        sent.update({"kind": kind, **fields})
        return {"executable_action": "warn"}

    monkeypatch.setattr(review, "native_hook_compose", _compose)

    action = review._observe_mode_executable_action(
        cast(Any, _state({"scanner_action": "warn", "package_action": "block"}, "allow"))
    )

    assert action == "warn"
    assert sent["kind"] == "observe_executable_action"
    # The gathered sources travel unfiltered: deciding which of them observe
    # mode still executes is the resident's call, not this module's.
    assert sent["scanner_action"] == "warn"
    assert sent["package_action"] == "block"
    assert sent["package_evaluation_action"] == "allow"
    assert sent["data_flow_action"] is None


def test_a_missing_composition_still_asks_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        review,
        "native_hook_compose",
        lambda kind, fields, *, guard_home: {"executable_action": "allow"},
    )

    assert review._observe_mode_executable_action(cast(Any, _state(None, None))) == "allow"


def test_an_unanswered_call_fails_closed_instead_of_recording_a_guess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unavailable(kind: str, fields: dict[str, object], *, guard_home: object) -> dict[str, object]:
        raise NativeHookComposeError("native_hook_artifact_compose_unavailable")

    monkeypatch.setattr(review, "native_hook_compose", _unavailable)

    with pytest.raises(NativeHookComposeError):
        review._observe_mode_executable_action(cast(Any, _state({"scanner_action": "allow"}, None)))

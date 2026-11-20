"""The worker host runs the first publication's policy compiles before it may publish."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_effective
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_inputs import NativePolicySnapshotPublisherInputs


class _Publisher(NativePolicySnapshotPublisherInputs):
    def __init__(self, *, started: bool = False, failure: Exception | None = None) -> None:
        self._condition = threading.Condition()
        self._workspace_paths = {Path("workspace")}
        self._started = started
        self.failure = failure
        self.compiled: list[frozenset[Path] | None] = []

    def _compiled_effective_policy(
        self, *, settled_only: bool = False, workspaces: frozenset[Path] | None = None
    ) -> dict[str, object]:
        del settled_only
        if self.failure is not None:
            raise self.failure
        self.compiled.append(workspaces)
        return {"mode": "prompt"}


@pytest.fixture
def effective(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    calls: list[object] = []
    monkeypatch.setattr(native_policy_effective, "effective_native_policy_v3", lambda config: calls.append(config))
    return calls


def test_warming_compiles_the_policy_the_first_publication_will_publish(effective: list[object]) -> None:
    publisher = _Publisher()

    publisher.warm_first_publication()

    # The same workspaces the first publication compiles, and the policy it hands the runtime.
    assert publisher.compiled == [frozenset({Path("workspace")})]
    assert effective == [{"mode": "prompt"}]


def test_a_started_publisher_is_not_warmed(effective: list[object]) -> None:
    publisher = _Publisher(started=True)

    publisher.warm_first_publication()

    assert publisher.compiled == []
    assert effective == []


def test_a_failed_warm_is_left_for_the_publication(effective: list[object]) -> None:
    publisher = _Publisher(failure=RuntimeError("native runtime did not answer"))

    publisher.warm_first_publication()

    assert effective == []

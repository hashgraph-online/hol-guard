from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import MethodType

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_bundle import MANAGED_CONTROLS_ACTIVE_STATE_KEY
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.store import GuardStore

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "tests"))
from test_managed_controls_activation_integration import _activate, _bundle  # noqa: E402


def _run_activation_crash_child(guard_home: Path, stage: str) -> None:
    store = GuardStore(guard_home)
    bundle = _bundle()
    bundle["bundleVersion"] = 8
    bundle["bundleHash"] = "sha256:" + "8" * 64

    if stage == "after_remote_rows":
        original_replace = store._replace_remote_policy_rows_locked  # pyright: ignore[reportPrivateUsage]

        def replace_then_crash(
            _store: GuardStore,
            connection: sqlite3.Connection,
            rows: Sequence[tuple[object, ...]],
        ) -> None:
            original_replace(connection, rows)
            os._exit(91)

        store._replace_remote_policy_rows_locked = MethodType(  # pyright: ignore[reportPrivateUsage]
            replace_then_crash,
            store,
        )
        _activate(store, bundle)
        raise AssertionError("crash injection did not terminate")

    def publish_then_crash(
        _view: ExtensionControlAuthorityView,
        commit: Callable[[], None],
    ) -> None:
        if stage == "after_commit":
            commit()
            os._exit(93)
        if stage == "before_commit":
            os._exit(92)
        raise AssertionError(f"unknown crash stage: {stage}")

    _activate(store, bundle, managed_controls_publish=publish_then_crash)
    raise AssertionError("crash injection did not terminate")


@pytest.mark.parametrize(
    ("stage", "exit_code", "durable_new_state"),
    (
        ("after_remote_rows", 91, False),
        ("before_commit", 92, False),
        ("after_commit", 93, True),
    ),
)
def test_process_crash_restart_never_exposes_partial_managed_activation(
    tmp_path: Path,
    stage: str,
    exit_code: int,
    durable_new_state: bool,
) -> None:
    guard_home = tmp_path / stage
    store = GuardStore(guard_home)
    first = _bundle()
    assert _activate(store, first)
    previous_active = store.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(previous_active, dict)

    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--activation-crash-child",
            str(guard_home),
            stage,
        ],
        cwd=_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == exit_code, completed.stderr

    restarted = GuardStore(guard_home)
    active = restarted.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(active, dict)
    expected_version = 8 if durable_new_state else 7
    assert active["bundleVersion"] == expected_version
    assert active["complete"] is True
    restarted_view = restarted.read_extension_control_authority_for_registry(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )
    assert restarted_view.health is AuthorityHealth.PROTECTED
    assert restarted_view.managed_revision == (2 if durable_new_state else 1)

    second = _bundle()
    second["bundleVersion"] = 8
    second["bundleHash"] = "sha256:" + "8" * 64
    assert _activate(restarted, second)
    replayed = restarted.get_sync_payload(MANAGED_CONTROLS_ACTIVE_STATE_KEY)
    assert isinstance(replayed, dict)
    assert replayed["complete"] is True
    assert replayed["bundleVersion"] == 8
    replayed_view = restarted.read_extension_control_authority_for_registry(
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )
    assert replayed_view.health is AuthorityHealth.PROTECTED
    assert replayed_view.managed_revision == 2


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--activation-crash-child":
    _run_activation_crash_child(Path(sys.argv[2]), sys.argv[3])

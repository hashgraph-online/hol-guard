from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_capability as command_capability_module
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import (
    CommandCapabilityError,
    authorize_command_job,
    mark_command_job_consumed,
)
from codex_plugin_scanner.guard.runtime.command_executors import COMMAND_OPERATION_SCHEMA_VERSIONS
from tests.test_guard_command_capability import _connected_store, _issue, _job


@pytest.fixture(autouse=True)
def _capability_runtime(native_command_capability_runtime: Path) -> None:
    """Every capability verdict asserted here comes from the compiled runtime."""


def test_only_job_and_replay_questions_ship_the_replay_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    _issue(store, "guard.packageShims.status")
    job = _job(store)
    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    mark_command_job_consumed(store, authorized)
    real = command_capability_module.native_command_capability
    shipped: list[tuple[bool, int]] = []

    def recorded(**kwargs: object) -> dict[str, object]:
        shipped.append((kwargs["job"] is not None, len(kwargs["replay_items"])))  # type: ignore[arg-type]
        return real(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(command_capability_module, "native_command_capability", recorded)

    assert command_queue.command_capability_operations(store) == ("guard.packageShims.status",)
    with pytest.raises(CommandCapabilityError, match="command_replayed"):
        authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    assert shipped == [(False, 0), (True, 1)]

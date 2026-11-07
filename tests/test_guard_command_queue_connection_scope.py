"""Which command queue jobs share one store connection."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import EXACT_CLOUD_REVIEW_TRANSPORT


class _ScopeStore:
    def __init__(self) -> None:
        self.open_scopes = 0

    @contextmanager
    def connection_scope(self) -> Iterator[None]:
        self.open_scopes += 1
        try:
            yield
        finally:
            self.open_scopes -= 1


@pytest.mark.parametrize(
    ("job", "shares_connection"),
    [
        ({"id": "review", "_guardCommandTransport": EXACT_CLOUD_REVIEW_TRANSPORT}, True),
        ({"id": "update", "operation": "guard.app.update"}, False),
    ],
)
def test_only_review_jobs_hold_the_shared_connection_while_executing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, job: dict[str, object], shares_connection: bool
) -> None:
    store = _ScopeStore()
    seen: list[int] = []

    def execute(job: dict[str, object], **kwargs: object) -> dict[str, object]:
        del job, kwargs
        seen.append(store.open_scopes)
        return {}

    monkeypatch.setattr(command_queue, "execute_guard_command_job", execute)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path)

    command_queue._execute_job(job, context, store)  # type: ignore[arg-type]

    # An update can wait on outside work; holding the storage gate through it
    # would stall another process's storage recovery.
    assert seen == [1 if shares_connection else 0]


class _StopError(Exception):
    pass


def test_a_handed_over_review_job_sets_up_on_one_connection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _ScopeStore()
    seen: list[tuple[str, int]] = []
    saved: list[dict[str, object]] = []
    job = {"id": "review", "leaseId": "lease", "_guardCommandTransport": EXACT_CLOUD_REVIEW_TRANSPORT}

    def resolve(_store: object, **_kwargs: object) -> dict[str, object]:
        seen.append(("auth", store.open_scopes))
        return {}

    def load(_store: object) -> dict[str, object]:
        seen.append(("load", store.open_scopes))
        return {"state": "idle", "last_poll_was_empty": True}

    def save(_store: object, state: dict[str, object]) -> None:
        seen.append(("save", store.open_scopes))
        saved.append(dict(state))

    def stop(*_args: object, **_kwargs: object) -> None:
        raise _StopError

    monkeypatch.setattr(command_queue, "command_environment_allows_queue", lambda: True)
    monkeypatch.setattr(command_queue, "command_queue_should_poll", lambda _store: True)
    monkeypatch.setattr(command_queue, "_resolve_command_queue_auth_context", resolve)
    monkeypatch.setattr(command_queue, "_load_state", load)
    monkeypatch.setattr(command_queue, "_save_state", save)
    monkeypatch.setattr(command_queue, "start_command_authorization", stop)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path)

    with pytest.raises(_StopError):
        command_queue.poll_command_queue_once(store, context, leased_item=job)  # type: ignore[arg-type]

    # Each of these would otherwise open its own connection and pay its own
    # schema load while every other drain worker contends for the store.
    assert seen == [("auth", 1), ("load", 1), ("save", 1)]
    assert saved[-1]["state"] == "leased"
    assert saved[-1]["active_job"] == job
    assert saved[-1]["last_poll_was_empty"] is False

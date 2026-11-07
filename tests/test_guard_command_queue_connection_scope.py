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

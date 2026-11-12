"""The test daemon's server view reads the hook worker that reviewed the daemon's hooks.

The native daemon hands each hook review to the resident library, which the
harness runs in the test process. The Gauntlet taps that worker's reviews and
reads its route metrics to prove which route answered, so a view that built a
second worker would see no hook at all and every live case would end unproven.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from ci.guard_daemon_harness import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_observe_mode_liveness import _review_request


@pytest.mark.usefixtures("native_hook_force")
def test_the_view_reads_the_worker_that_reviewed_the_daemons_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    guard_home.mkdir(parents=True)
    daemon = GuardDaemonServer(GuardStore(guard_home), host="127.0.0.1", port=0)
    before_start = daemon._server.hook_worker
    daemon.start()
    # Keep Oh My Pi hooks off the resident's direct lane so the daemon reviews them.
    monkeypatch.setenv("HOL_GUARD_PI_DIRECT_HOOK", "0")
    try:
        worker = daemon._server.hook_worker
        assert worker is not before_start
        reviewed: list[dict[str, Any]] = []
        original = worker.review_http_payload

        def tapped(**kwargs: Any) -> Any:
            reviewed.append(kwargs)
            return original(**kwargs)

        monkeypatch.setattr(worker, "review_http_payload", tapped)
        payload = _review_request(daemon, endpoint="omp", guard_home=guard_home, workspace=workspace)
        assert payload.get("decision") in {"allow", "deny"}
        assert len(reviewed) == 1
        assert worker.metrics.snapshot()["routes"].get("native_resident", 0) >= 1
        assert daemon._server.hook_worker is worker
    finally:
        daemon.stop()

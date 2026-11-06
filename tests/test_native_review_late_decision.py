"""A native decision reached under the lease survives a deadline that passed.

The fence refuses to *start* a review that is already out of time. Once the
review has answered, the answer was read from the snapshot the lease holds, so
discarding it only turns ordinary work into an approval row — and would drop a
deny the runtime had already reached.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore

_PAYLOAD = {
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "git status --short"},
}


def _worker(tmp_path: Any, monkeypatch: Any, action: str) -> HookWorker:
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard-home"),
        wait_for_native_policy=False,
        publish_native_policy=False,
    )

    def slow_review(**kwargs: object) -> tuple[dict[str, object], bool]:
        deadline = kwargs.get("deadline")
        if isinstance(deadline, float):
            time.sleep(max(0.0, deadline - time.monotonic()) + 0.05)
        return ({"policy_action": action, "reason_code": f"native_{action}_fixture"}, True)

    monkeypatch.setattr(worker, "_review_native_edge_with_snapshot", slow_review)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker_native._record_unavailable_native",
        lambda _host, _payload, *, reason_code, **_k: {"unavailable": reason_code},
    )
    monkeypatch.setattr(worker, "_apply_structured_unavailable_overlay", lambda response, **_k: response)
    return worker


def _review(worker: HookWorker, tmp_path: Any, budget_seconds: float) -> dict[str, object]:
    return worker._review_native_edge(
        payload=dict(_PAYLOAD),
        harness="codex",
        event_name="PreToolUse",
        default_harness="codex",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        deadline=time.monotonic() + budget_seconds,
        policy_snapshot={"generation": 1, "command_extensions_bound": True},
    )


def test_an_allow_reached_after_the_deadline_is_still_delivered(tmp_path, monkeypatch):
    worker = _worker(tmp_path, monkeypatch, "allow")
    try:
        response = _review(worker, tmp_path, 0.2)
    finally:
        worker.close()
    assert response["policy_action"] == "allow"


def test_a_deny_reached_after_the_deadline_is_not_downgraded(tmp_path, monkeypatch):
    worker = _worker(tmp_path, monkeypatch, "deny")
    try:
        response = _review(worker, tmp_path, 0.2)
    finally:
        worker.close()
    assert response["policy_action"] == "deny"


def _unleased_worker(tmp_path: Any, monkeypatch: Any, tokens: list[object]) -> HookWorker:
    """A worker whose review runs without the lease, over the given bindings."""

    worker = _worker(tmp_path, monkeypatch, "allow")
    monkeypatch.setattr(
        worker,
        "_review_native_edge_with_snapshot",
        lambda **_k: ({"policy_action": "allow", "reason_code": "native_allow_fixture"}, True),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker_native_review.published_binding_token",
        lambda _publisher: tokens.pop(0),
    )
    return worker


def _review_behind_a_held_mutation(worker: HookWorker, tmp_path: Any) -> dict[str, object]:
    from codex_plugin_scanner.guard.native_command_control_authority_io import (
        hold_command_control_authority_lock,
    )

    held = threading.Event()
    release = threading.Event()

    def mutate() -> None:
        with hold_command_control_authority_lock(tmp_path / "guard-home"):
            held.set()
            release.wait(10.0)

    writer = threading.Thread(target=mutate, daemon=True)
    writer.start()
    try:
        assert held.wait(5.0)
        return _review(worker, tmp_path, 4.0)
    finally:
        release.set()
        writer.join(10.0)


def test_an_unleased_allow_on_an_unchanged_binding_is_delivered(tmp_path, monkeypatch):
    worker = _unleased_worker(tmp_path, monkeypatch, [("gen-1", "digest-1"), ("gen-1", "digest-1")])
    try:
        response = _review_behind_a_held_mutation(worker, tmp_path)
    finally:
        worker.close()
    assert response["policy_action"] == "allow"


def test_durable_control_token_changes_without_a_publisher_generation_change() -> None:
    from codex_plugin_scanner.guard.daemon.hook_native_review_fence import published_binding_token

    committed = {"epoch": 1, "mutation_revision": 7, "phase": "committed", "effective_digest": "digest-1"}

    class Publisher:
        business_source = None
        revision = 3

        def _committed_control_authority(self) -> dict[str, object]:
            return dict(committed)

        def _compiled_business_source(self) -> None:
            return self.business_source

        def _current_local_cli_revision(self) -> int:
            return self.revision

        def current_snapshot_binding(self) -> dict[str, object]:
            # The cached binding has not changed despite a committed write.
            return {"generation": 4, "policy_digest": "unchanged"}

    publisher = Publisher()
    before = published_binding_token(publisher)
    assert before is not None
    committed["effective_digest"] = "digest-2"
    assert published_binding_token(publisher) != before
    committed["effective_digest"] = "digest-1"
    assert published_binding_token(publisher) == before
    publisher.revision += 1
    assert published_binding_token(publisher) != before


def test_a_durable_control_read_that_fails_leaves_no_token() -> None:
    from codex_plugin_scanner.guard.daemon.hook_native_review_fence import published_binding_token

    class Publisher:
        def _committed_control_authority(self) -> dict[str, object]:
            raise OSError("authority unreadable")

        def _compiled_business_source(self) -> None:
            return None

        def _current_local_cli_revision(self) -> int:
            return 1

    assert published_binding_token(Publisher()) is None


def test_a_marker_frozen_mid_mutation_leaves_no_token() -> None:
    from codex_plugin_scanner.guard.daemon.hook_native_review_fence import published_binding_token

    marker = {"epoch": 1, "mutation_revision": 8, "phase": "closed", "effective_digest": None}

    class Publisher:
        def _committed_control_authority(self) -> dict[str, object]:
            return dict(marker)

        def _compiled_business_source(self) -> None:
            return None

        def _current_local_cli_revision(self) -> int:
            return 3

    publisher = Publisher()
    # The writer freezes this marker before it commits its control rows, so two
    # reads taken across that window read the same bytes while the rows change.
    assert published_binding_token(publisher) is None
    marker["phase"] = "committed"
    marker["effective_digest"] = "digest-8"
    assert published_binding_token(publisher) is not None


def test_a_home_without_control_authority_still_has_a_token() -> None:
    from codex_plugin_scanner.guard.daemon.hook_native_review_fence import published_binding_token

    class Publisher:
        def _committed_control_authority(self) -> None:
            # A fresh install has no control authority at all.
            return None

        def _compiled_business_source(self) -> None:
            return None

        def _current_local_cli_revision(self) -> int:
            return 3

    publisher = Publisher()
    token = published_binding_token(publisher)
    # An absent marker is a definite state; refusing it would turn ordinary work
    # on a fresh install into an approval row.
    assert token is not None
    assert published_binding_token(publisher) == token


def test_unleased_review_without_durable_authority_cannot_allow(tmp_path, monkeypatch):
    worker = _unleased_worker(tmp_path, monkeypatch, [None, None])
    try:
        response = _review_behind_a_held_mutation(worker, tmp_path)
    finally:
        worker.close()
    assert response == {"unavailable": "native_command_control_fence_unavailable"}


def test_an_unleased_allow_is_dropped_when_the_policy_is_replaced(tmp_path, monkeypatch):
    worker = _unleased_worker(tmp_path, monkeypatch, [("gen-1", "digest-1"), ("gen-2", "digest-2")])
    try:
        response = _review_behind_a_held_mutation(worker, tmp_path)
    finally:
        worker.close()
    assert response == {"unavailable": "native_command_control_fence_unavailable"}

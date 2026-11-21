"""Stand-in replay store for the native workspace review replay loop tests.

Requests, snapshots and requeues are in memory. The replay marker methods run
on scratch native storage that holds the fake's current marker row, so the
loop exercises the native marker rules.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from codex_plugin_scanner.guard.runtime import native_workspace_review_replay as replay
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"


def replay_binding() -> dict[str, str]:
    return {
        "oauth_source": "default",
        "oauth_subject_hash": "a" * 64,
        "workspace_id": "workspace-1",
        "machine_id": "machine-1",
        "machine_installation_id": "installation-1",
    }


class ReplayStore:
    guard_home: Path
    guard_source = "default"

    def __init__(self, tmp_path: Path, request_ids: list[str]) -> None:
        self.guard_home = tmp_path
        self.binding = replay_binding()
        self.request_ids = request_ids
        self.payloads: dict[str, object] = {}
        self.context_calls: list[str] = []
        self.requeue_calls: list[dict[str, object]] = []
        self.list_calls = 0
        self.requeue_result = 1
        self.fail_marker_update = False
        self.native = GuardStore(tmp_path / "native-store")

    def get_review_event_oauth_binding(self) -> dict[str, str]:
        return dict(self.binding)

    def get_sync_payload(self, key: str) -> object | None:
        return self.payloads.get(key)

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        del now
        if self.fail_marker_update and ":request:" in key:
            raise OSError("marker update failed")
        self.payloads[key] = payload

    def _native_marker_call(
        self, request_id: str, call: Callable[[GuardStore], dict[str, object]]
    ) -> dict[str, object]:
        """Run a native marker method on scratch storage holding this fake's marker row."""

        key = replay._marker_key(cast(replay._NativeWorkspaceReplayStore, cast(object, self)), request_id)
        with self.native._connect() as connection:
            connection.execute("delete from sync_state where state_key = ?", (key,))
            connection.commit()
        if key in self.payloads:
            self.native.set_sync_payload(key, self.payloads[key], _NOW)
        answer = call(self.native)
        if "marker" in answer and answer.get("key") is None:
            if self.fail_marker_update:
                raise OSError("marker update failed")
            self.payloads[key] = answer["marker"]
        return answer

    def native_workspace_review_replay_marker(
        self, request_id: str, *, binding: dict[str, str], now: str, force_probe: bool = False
    ) -> dict[str, object]:
        return self._native_marker_call(
            request_id,
            lambda native: native.native_workspace_review_replay_marker(
                request_id, binding=binding, now=now, force_probe=force_probe
            ),
        )

    def transition_native_workspace_review_replay_marker(
        self, request_id: str, step: str, **kwargs: Any
    ) -> dict[str, object]:
        return self._native_marker_call(
            request_id,
            lambda native: native.transition_native_workspace_review_replay_marker(request_id, step, **kwargs),
        )

    def list_pending_review_request_ids(
        self,
        *,
        binding: dict[str, str],
        limit: int,
        after_request_id: str | None = None,
        through_request_id: str | None = None,
        descending: bool = False,
    ) -> list[str]:
        self.list_calls += 1
        if binding != self.binding:
            return []
        candidates = sorted(
            request_id
            for request_id in self.request_ids
            if (after_request_id is None or request_id > after_request_id)
            and (through_request_id is None or request_id <= through_request_id)
        )
        return list(reversed(candidates))[:limit] if descending else candidates[:limit]

    def requeue_pending_review_events_with_marker(
        self,
        *,
        changed_at: str,
        marker_key: str,
        marker_payload: dict[str, object],
        require_binding: bool = False,
        request_ids: set[str] | None = None,
    ) -> int:
        self.requeue_calls.append(
            {
                "changed_at": changed_at,
                "marker_key": marker_key,
                "marker_payload": dict(marker_payload),
                "require_binding": require_binding,
                "request_ids": set(request_ids or ()),
            }
        )
        self.payloads[marker_key] = {**marker_payload, "requeued": self.requeue_result}
        return self.requeue_result

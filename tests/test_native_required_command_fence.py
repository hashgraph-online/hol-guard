"""Required policy authority cannot become availability after a command-fence refusal."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_fence, hook_worker_native
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError


@pytest.mark.parametrize("authority", ["scoped", "required", "unrequired"])
@pytest.mark.parametrize("failure", ["timeout", "authority-error"])
def test_command_fence_refusal_preserves_required_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
    failure: str,
) -> None:
    attempts: list[tuple[Path, bool]] = []
    timeouts: list[float] = []
    native_calls: list[object] = []
    receipts: list[object] = []
    routes: list[str] = []
    snapshot: dict[str, object] = {
        "generation": 7,
        "mode": "enforce",
        "command_extensions_bound": True,
    }
    if authority == "scoped":
        snapshot["source_input_digest"] = "c" * 64

    @contextmanager
    def unavailable_authority(
        guard_home: Path, *, timeout_seconds: float = 30.0, shared: bool = False
    ) -> Iterator[None]:
        attempts.append((guard_home, shared))
        timeouts.append(timeout_seconds)
        if failure == "timeout":
            raise TimeoutError("native_review_fence_deadline")
        raise NativePolicySnapshotError("native_command_control_authority_invalid")
        yield

    def forbidden_native(**kwargs: object) -> None:
        native_calls.append(kwargs)
        pytest.fail("native evaluation must not run without the command authority lease")

    def forbidden_receipt(receipt: object) -> None:
        receipts.append(receipt)
        pytest.fail("a refused authority lease cannot produce a decision receipt")

    monkeypatch.setattr(hook_native_review_fence, "hold_command_control_authority_lock", unavailable_authority)
    host: Any = SimpleNamespace(
        policy_snapshot_publisher=SimpleNamespace(
            requires_scoped_authority=authority == "scoped",
            requires_policy_authority=authority == "required",
        ),
        _native_policy_snapshot=lambda *_args, **_kwargs: dict(snapshot),
        _review_native_edge_with_snapshot=forbidden_native,
        _record_native_decision_receipt=forbidden_receipt,
        activity_writer=None,
        metrics=SimpleNamespace(record_route=routes.append),
    )
    deadline = time.monotonic() + 0.4
    actual = hook_worker_native.HookWorkerNativeMixin._review_native_edge(
        host,
        payload={"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "printf safe"}},
        harness="claude-code",
        event_name="PreToolUse",
        default_harness="claude-code",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        deadline=deadline,
    )

    assert attempts == [(tmp_path, True)]
    assert len(timeouts) == 1 and 0.0 <= timeouts[0] <= 0.4
    assert native_calls == []
    assert receipts == []
    output = actual["hookSpecificOutput"]
    assert isinstance(output, dict) and output["hookEventName"] == "PreToolUse"
    if authority != "unrequired":
        assert output["permissionDecision"] == "deny", (
            "required command authority must block when its review fence fails"
        )
        assert actual["policy_action"] == "block"
        assert actual["reason_code"] == "native_scoped_authority_unavailable"
        assert actual.get("continue") is not True
    else:
        assert output["permissionDecision"] == "allow"
        assert actual["policy_action"] == "warn"
        assert actual["reason_code"] == (
            "native_review_deadline_exceeded" if failure == "timeout" else "native_command_control_fence_unavailable"
        )
    assert routes == ["native_fail_safe"]

from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.daemon.runtime_hook_deadline import RuntimeHookDeadline


@pytest.mark.parametrize(
    ("harness", "event", "expected_cap"),
    [
        ("grok", "UserPromptSubmit", 10),
        ("grok", "user_prompt_submit", 10),
        ("grok", "PreToolUse", 3),
        ("omp", "UserPromptSubmit", 10),
        ("zcode", "UserPromptSubmit", 10),
        ("codex", "user_prompt_submit", 10),
        ("zcode", "PreToolUse", 3),
        ("grok", "SessionStart", 3),
    ],
)
@pytest.mark.parametrize(
    ("hints", "expected_remaining"),
    [
        ({"guard_remaining_ms": 999000}, None),
        ({}, 9.75),
        ({"guard_remaining_ms": 2000}, 1.75),
        ({"guard_remaining_seconds": 1}, 0.75),
        ({"guard_remaining_ms": None}, 2.75),
        ({"guard_remaining_seconds": True}, 2.75),
        ({"guard_remaining_ms": float("nan")}, 2.75),
    ],
)
def test_server_deadline_includes_elapsed_admission_and_missing_policy_blocks(
    monkeypatch, harness, event, expected_cap, hints, expected_remaining
):
    captured = []
    responses = []
    caps = []
    original_factory = RuntimeHookDeadline.from_remaining_hint

    def make_deadline(hint, **kwargs):
        kwargs.setdefault("monotonic", lambda: 106.0)
        return original_factory(hint, **kwargs)

    monkeypatch.setattr(
        RuntimeHookDeadline,
        "from_remaining_hint",
        make_deadline,
    )
    monkeypatch.setattr(server, "_native_mode_requires_rust", lambda: True)
    daemon = SimpleNamespace(
        request_deadline=lambda request, cap: caps.append(cap) or 100.0 + cap,
        store=SimpleNamespace(get_managed_install=lambda _: {"active": True}, connection_scope=nullcontext),
        hook_worker=SimpleNamespace(
            prepare_workspace_policy=lambda workspace, *, deadline: captured.append(deadline),
            metrics=SimpleNamespace(record_route=lambda _: None),
        ),
    )
    handler = SimpleNamespace(
        request=object(),
        _daemon_server=lambda: daemon,
        _optional_string=lambda value: value if isinstance(value, str) else None,
        _validated_hook_directory_string=lambda _kind, value, **kwargs: value,
        _validated_hook_guard_home=lambda value: value,
        _hook_safe_roots=lambda: (),
        _normalized_hook_workspace_string=lambda value: value,
        _runtime_hook_exec_command_workdir=lambda payload: (False, None),
        _runtime_hook_fail_safe_response=lambda *args, **kwargs: {
            "decision": "block",
            "reason_code": kwargs["reason_code"],
        },
        _write_json=responses.append,
    )
    server._GuardDaemonHandler._handle_runtime_hook(
        handler,
        {"hook_event_name": event, "prompt": "synthetic", **hints},
        "",
        default_harness=harness,
    )
    assert caps == [expected_cap]
    expected_deadline = 100.0 + expected_cap
    clock_start = 100.0 if expected_cap == 10 else 106.0
    if expected_remaining is None and expected_cap == 10:
        expected_remaining = 9.75
    if expected_remaining is not None:
        if not hints and expected_cap != 10:
            expected_remaining = 2.75
        expected_deadline = min(expected_deadline, clock_start + expected_remaining)
    assert captured == [expected_deadline]
    assert responses == [{"decision": "block", "reason_code": "native_policy_not_ready"}]


def test_shorter_caller_budget_is_preserved() -> None:
    deadline = RuntimeHookDeadline.from_remaining_hint(2, monotonic=lambda: 100.0, maximum_budget_seconds=10)
    assert deadline.expires_at == 101.75
    assert deadline.remaining(monotonic=lambda: 102.0) == 0


@pytest.mark.parametrize("maximum", [True, -1, 11, float("inf"), float("nan")])
def test_explicit_maximum_cannot_remove_the_hard_cap(maximum) -> None:
    with pytest.raises(ValueError):
        RuntimeHookDeadline.from_remaining_hint(999, maximum_budget_seconds=maximum)

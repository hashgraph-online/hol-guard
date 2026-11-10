"""Pin the daemon runtime identity before an in-place upgrade can relabel it."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import manager


def test_runtime_fingerprint_waits_out_a_cold_capability_probe_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    answers: list[dict[str, object] | None] = [
        None,
        {"tree_sig": "tree", "fingerprint": "a" * 64, "reused": False},
    ]
    waits: list[float] = []
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: answers.pop(0))
    monkeypatch.setattr(manager, "await_native_runtime", lambda budget: waits.append(budget) or 0.6)

    assert manager._measure_runtime_fingerprint(tmp_path, None) == ("tree", "a" * 64, False)
    assert waits == [60.0]


def test_runtime_fingerprint_refuses_when_no_probe_miss_is_waited_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    calls: list[str] = []
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: calls.append("ask"))
    monkeypatch.setattr(manager, "await_native_runtime", lambda _budget: 0.0)

    with pytest.raises(RuntimeError, match="requires the native runtime"):
        manager._measure_runtime_fingerprint(tmp_path, None)
    assert calls == ["ask"]

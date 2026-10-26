"""The review-evidence ask picks its route before it asks the resident."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_exact_action as exact


def _evidence(tmp_path: Path, command: str = "make build") -> tuple[str | None, str | None, str | None]:
    return exact.native_review_evidence(
        harness="codex",
        tool_name="Bash",
        payload={"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(tmp_path)},
        native_result={"reason": "review"},
        native_receipt=None,
        workspace=tmp_path,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
    )


def _route(monkeypatch: pytest.MonkeyPatch, *, offers_combined: bool, combined_fails: bool = False) -> list[str]:
    asked: list[str] = []

    def answer(query: Mapping[str, object], _guard_home: Path | None) -> dict[str, Any]:
        asked.append(str(query["kind"]))
        if combined_fails:
            raise exact.NativeExactActionError("native_exact_action_unavailable")
        return {"kind": "review_evidence", "binding": "combined", "token": "combined-token", "once_only_reason": None}

    def binding(*_args: object, **_kwargs: object) -> str:
        asked.append("review_binding")
        return "binding"

    def action(**_kwargs: object) -> tuple[str, None]:
        asked.append("exact_action")
        return "token", None

    monkeypatch.setattr(exact, "_answer", answer)
    monkeypatch.setattr(exact, "_resident_offers_review_evidence", lambda: offers_combined)
    monkeypatch.setattr(exact, "native_review_binding", binding)
    monkeypatch.setattr(exact, "native_exact_action", action)
    return asked


def test_a_resident_with_the_combined_ask_is_asked_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _route(monkeypatch, offers_combined=True)

    assert _evidence(tmp_path) == ("combined", "combined-token", None)
    assert asked == ["review_evidence"]


def test_a_resident_without_the_combined_ask_answers_each_half(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _route(monkeypatch, offers_combined=False)

    assert _evidence(tmp_path) == ("binding", "token", None)
    assert asked == ["review_binding", "exact_action"]


def test_halves_too_large_for_one_envelope_are_asked_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = _route(monkeypatch, offers_combined=True)

    assert _evidence(tmp_path, "echo " + "x" * (exact._MAX_REQUEST_BYTES // 2)) == ("binding", "token", None)
    assert asked == ["review_binding", "exact_action"]


def test_a_failed_combined_ask_fails_closed_without_asking_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = _route(monkeypatch, offers_combined=True, combined_fails=True)

    assert _evidence(tmp_path) == (None, None, exact.UNPROVEN_LAUNCH)
    assert asked == ["review_evidence"]

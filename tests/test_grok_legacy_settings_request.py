"""The Grok legacy managed-config cleanup asks the native runtime for its edit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.grok_install_settings import remove_legacy_settings

_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "testdata"
    / "grok"
    / "legacy_settings_vectors.json"
)


def _native(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[tuple[str, object]]:
    calls: list[tuple[str, object]] = []

    def native(kind: str, request: object) -> object:
        calls.append((kind, request))
        return answer

    monkeypatch.setattr("codex_plugin_scanner.guard.native_runner_authority.native_runner_authority", native)
    return calls


def test_a_missing_file_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _native(monkeypatch, {"text": "unused"})
    assert remove_legacy_settings(None, {"prior_compat_hooks": {"claude": "true"}}) is None
    assert calls == []


def test_the_request_keeps_the_recorded_vendor_order(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _native(monkeypatch, {"text": "café\n"})
    state: dict[str, object] = {"prior_compat_hooks": {"cursor": None, "claude": "true", "x": 5}}
    assert remove_legacy_settings(b"a = 1\n", state) == "café\n".encode()
    assert calls == [
        (
            "grok_legacy_settings",
            {"text": "a = 1\n", "prior_compat_hooks": [["cursor", None], ["claude", "true"], ["x", 5]]},
        )
    ]


@pytest.mark.parametrize("prior", [None, ["claude", "true"], "claude"])
def test_a_record_without_vendor_values_sends_no_pairs(monkeypatch: pytest.MonkeyPatch, prior: object) -> None:
    calls = _native(monkeypatch, {"text": ""})
    remove_legacy_settings(b"", {"prior_compat_hooks": prior})
    assert calls == [("grok_legacy_settings", {"text": "", "prior_compat_hooks": []})]


def test_every_recorded_request_matches_the_shim(monkeypatch: pytest.MonkeyPatch) -> None:
    cases = json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]
    for case in cases:
        request = case["request"]
        state = {"prior_compat_hooks": dict(request["prior_compat_hooks"])}
        calls = _native(monkeypatch, {"text": case["text"]})
        assert remove_legacy_settings(request["text"].encode(), state) == case["text"].encode()
        assert calls == [("grok_legacy_settings", request)], case["name"]


@pytest.mark.parametrize("answer", [{}, {"text": 1}, {"text": "x", "extra": 1}, ["x"], None])
def test_a_malformed_answer_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _native(monkeypatch, answer)
    with pytest.raises(ValueError, match="malformed"):
        remove_legacy_settings(b"x", {})

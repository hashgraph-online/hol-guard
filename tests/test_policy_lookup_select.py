"""The non-consuming policy lookups are selected by the resident, not in Python."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_policy
from codex_plugin_scanner.guard.native_hook_artifact_compose import NativeHookComposeError


def _lookup(decision: dict[str, object] | None, **overrides: object) -> dict[str, object]:
    lookup: dict[str, object] = {
        "decision": decision,
        "ignored_local_integrity": None,
        "trust_status": {"status": "verified"},
        "authority_revision": 7,
    }
    lookup.update(overrides)
    return lookup


def _answering(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> list[dict[str, object]]:
    asked: list[dict[str, object]] = []

    def fake(kind: str, fields, *, guard_home: Path | None) -> dict[str, object]:
        asked.append({"kind": kind, "fields": dict(fields), "guard_home": guard_home})
        return answer

    monkeypatch.setattr(store_policy, "native_hook_compose", fake)
    return asked


def test_every_probed_lookup_is_sent_and_the_resident_answer_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composed = {
        "decision": {"action": "block", "_approval_authority_revision": 7},
        "ignored_local_integrity": {"reason": "integrity drifted"},
        "trust_status": {"status": "verified"},
        "authority_revision": 7,
    }
    asked = _answering(monkeypatch, composed)
    lookups = [
        _lookup(None, ignored_local_integrity={"reason": "integrity drifted"}),
        _lookup({"action": "block"}),
    ]

    result = store_policy._most_restrictive_policy_lookup(lookups, guard_home=Path("/guard"))

    assert asked[0]["kind"] == "policy_lookup_select"
    assert asked[0]["fields"] == {"lookups": lookups}
    assert asked[0]["guard_home"] == Path("/guard")
    assert result == composed


def test_an_unavailable_resident_does_not_select_in_python(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NativeHookComposeError("native_hook_artifact_compose_unavailable")

    monkeypatch.setattr(store_policy, "native_hook_compose", refuse)

    with pytest.raises(NativeHookComposeError):
        store_policy._most_restrictive_policy_lookup(
            [_lookup({"action": "allow"}), _lookup({"action": "block"})],
            guard_home=None,
        )


def test_nothing_to_select_is_refused_before_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _answering(monkeypatch, {})

    with pytest.raises(ValueError):
        store_policy._most_restrictive_policy_lookup([], guard_home=None)

    assert asked == []


def test_a_single_unmatched_lookup_is_answered_without_the_resident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = _answering(monkeypatch, {"decision": {"action": "block"}})
    lookup = _lookup(None)

    assert store_policy._most_restrictive_policy_lookup([lookup], guard_home=None) == lookup
    # The common hook outcome — one lookup, no saved decision — must not spend
    # a round trip to be told the row it already holds is the answer.
    assert asked == []


def test_a_single_matched_lookup_is_still_selected_by_the_resident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composed = {
        "decision": {"action": "allow", "_approval_authority_revision": 7},
        "ignored_local_integrity": None,
        "trust_status": {"status": "verified"},
        "authority_revision": 7,
    }
    asked = _answering(monkeypatch, composed)

    result = store_policy._most_restrictive_policy_lookup([_lookup({"action": "allow"})], guard_home=None)

    assert result == composed
    assert len(asked) == 1

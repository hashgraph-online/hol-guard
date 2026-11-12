"""The Python side of the resident ``codex_hook_manifest_verify`` round trip."""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_file_integrity as integrity
from codex_plugin_scanner.guard import native_codex_hook_manifest_verify as verify
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError

_UNAVAILABLE = verify._unavailable_state()


def _valid_state() -> dict[str, object]:
    return {**_UNAVAILABLE, "integrity_status": "valid", "integrity_reason": None, "integrity_message": None}


@pytest.fixture
def replies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[object]:
    queue: list[object] = []
    monkeypatch.setattr(verify, "_resolve_existing_digest_home", lambda home: str(tmp_path))
    monkeypatch.setattr(verify, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(verify, "_ask", lambda wire, home: queue.pop(0) if queue else None)
    monkeypatch.setattr(integrity, "_owner_is_only_group_member", lambda uid, gid: True)
    return queue


def _run(tmp_path: Path) -> dict[str, object]:
    return verify.native_codex_hook_manifest_verify(guard_home=tmp_path, hooks={}, failure=("reason", "message"))


def test_unavailable_resident_leaves_the_installation_unverified(replies: list[object], tmp_path: Path) -> None:
    assert _run(tmp_path) == _UNAVAILABLE
    assert _UNAVAILABLE["integrity_status"] == "tampered"


def test_missing_prerequisite_leaves_the_installation_unverified(
    replies: list[object], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(verify, "ensure_resident_prerequisite", lambda home: False)
    replies.append({"private_group_questions": [], "state": _valid_state()})
    assert _run(tmp_path) == _UNAVAILABLE


def test_a_settled_reply_is_returned(replies: list[object], tmp_path: Path) -> None:
    replies.append({"private_group_questions": [], "state": _valid_state()})
    assert _run(tmp_path) == _valid_state()


@pytest.mark.parametrize(
    "reply",
    [
        {"private_group_questions": [], "state": {"integrity_status": "valid"}},
        {"private_group_questions": None, "state": _valid_state()},
        {"private_group_questions": [], "state": None},
        {"private_group_questions": [{"owner_uid": "0", "group_gid": 1}], "state": _valid_state()},
    ],
)
def test_a_malformed_reply_leaves_the_installation_unverified(
    replies: list[object], tmp_path: Path, reply: dict[str, object]
) -> None:
    replies.append(reply)
    assert _run(tmp_path) == _UNAVAILABLE


def test_a_question_asked_twice_is_refused(replies: list[object], tmp_path: Path) -> None:
    question = {"owner_uid": 501, "group_gid": 20}
    replies.extend(
        [
            {"private_group_questions": [question], "state": _UNAVAILABLE},
            {"private_group_questions": [question], "state": _UNAVAILABLE},
            {"private_group_questions": [], "state": _valid_state()},
        ]
    )
    assert _run(tmp_path) == _UNAVAILABLE


def test_answers_carry_into_the_next_round(
    replies: list[object], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[list[object]] = []
    queue = [
        {"private_group_questions": [{"owner_uid": 501, "group_gid": 20}], "state": _UNAVAILABLE},
        {"private_group_questions": [], "state": _valid_state()},
    ]

    def ask(wire: dict[str, object], home: Path) -> object:
        sent.append(list(wire["private_groups"]))
        return queue.pop(0)

    monkeypatch.setattr(verify, "_ask", ask)
    assert _run(tmp_path) == _valid_state()
    assert sent == [[], [{"owner_uid": 501, "group_gid": 20, "private": True}]]


def test_rounds_are_bounded(replies: list[object], tmp_path: Path) -> None:
    replies.extend(
        {"private_group_questions": [{"owner_uid": 501, "group_gid": gid}], "state": _UNAVAILABLE}
        for gid in range(verify._MAX_ROUNDS + 1)
    )
    assert _run(tmp_path) == _UNAVAILABLE


@pytest.mark.parametrize(
    "value",
    [
        (1, 2),
        2**64,
        -(2**63) - 1,
        float("nan"),
        float("inf"),
        {1: "key"},
        object(),
    ],
)
def test_values_json_cannot_carry_are_refused(value: object) -> None:
    with pytest.raises(verify._UnrepresentableError):
        verify._plain(value, 1, verify._MAX_MANIFEST_DEPTH)


def test_nesting_past_the_resident_limit_is_refused() -> None:
    value: object = "leaf"
    for _ in range(verify._MAX_GROUP_DEPTH):
        value = [value]
    with pytest.raises(verify._UnrepresentableError):
        verify._plain(value, 1, verify._MAX_GROUP_DEPTH)
    assert verify._plain_or_none(value) is None


def test_an_unrepresentable_manifest_is_sent_as_invalid() -> None:
    wire = verify._request({}, {"schema_version": (1,)}, {}, None)
    assert wire["manifest"] is None
    assert wire["failure"] == {"reason": verify._MANIFEST_INVALID[0], "message": verify._MANIFEST_INVALID[1]}


def test_a_spent_deadline_while_resolving_paths_is_sent_as_the_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def expired(path: Path) -> str:
        raise CodexHookIntegrityError("codex_hook_validation_deadline_expired", "deadline")

    monkeypatch.setattr(integrity, "canonical_path", expired)
    manifest = {"packaged_files": [{"path": str(Path("/").resolve() / "bridge.py")}]}
    wire = verify._request({}, manifest, {}, None)
    assert wire["failure"] == {"reason": "codex_hook_validation_deadline_expired", "message": "deadline"}


def test_a_spent_deadline_skips_the_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def unexpected(**kwargs: object) -> object:
        raise AssertionError("the resident was asked after the deadline")

    monkeypatch.setattr(verify, "_resident_request", unexpected)
    monkeypatch.setattr(verify, "active_hook_validation_deadline", lambda: time.monotonic() - 1)
    assert verify._ask({}, tmp_path) is None


def test_the_resident_gets_only_the_remaining_budget(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[float] = []

    def request(**kwargs: object) -> object:
        seen.append(float(kwargs["timeout_seconds"]))
        raise OSError("down")

    monkeypatch.setattr(verify, "_resident_request", request)
    monkeypatch.setattr(verify, "active_hook_validation_deadline", lambda: 100.5)
    monkeypatch.setattr(verify, "time", SimpleNamespace(monotonic=lambda: 100.0))
    assert verify._ask({}, tmp_path) is None
    assert seen == [0.5]

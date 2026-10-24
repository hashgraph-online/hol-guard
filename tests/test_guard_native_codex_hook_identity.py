"""The Codex hook identity bridge ships definitions and keeps no fallback."""

from __future__ import annotations

from datetime import date, datetime, time
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import codex_hook_identity
from codex_plugin_scanner.guard import native_codex_hook_identity as bridge


def _resident(monkeypatch: pytest.MonkeyPatch, reply) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/codex-hook-identity-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        sent.append(request)
        return reply(request)

    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)
    return sent


def _digests(request: dict[str, object]) -> dict[str, object]:
    entries = request["entries"]
    assert isinstance(entries, list)
    return {"identities": [{"digest": f"d{index}"} for index in range(len(entries))]}


def test_no_entries_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _digests)
    assert bridge.native_codex_hook_identity([]) == []
    assert sent == []


def test_the_wire_carries_the_coordinates_and_the_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _digests)
    codex_hook_identity.canonical_codex_hook_identity(
        source_scope="user",
        source_hooks_enabled=True,
        event_name="PreToolUse",
        group={"matcher": "*", "hooks": []},
        handler={"type": "command", "command": "echo hi"},
    )
    (wire,) = sent
    assert wire["schema"] == "guard-codex-hook-identity-request.v1"
    assert wire["scalar_tokens"] == {}
    assert wire["entries"] == [
        {
            "kind": "handler",
            "source_scope": "user",
            "source_hooks_enabled": True,
            "event_name": "PreToolUse",
            "group": {"hooks": [], "matcher": "*"},
            "handler": {"command": "echo hi", "type": "command"},
        }
    ]


def test_an_argv_request_sends_only_the_command(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, lambda _request: {"identities": [{"argv": ["echo", "hi"]}]})
    assert codex_hook_identity.canonical_codex_command_argv("echo hi") == ("echo", "hi")
    assert sent[0]["entries"] == [
        {
            "kind": "argv",
            "source_scope": "",
            "source_hooks_enabled": False,
            "event_name": "",
            "command": "echo hi",
        }
    ]


def test_an_argv_answer_of_null_is_not_an_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda _request: {"identities": [{"argv": None}]})
    assert codex_hook_identity.canonical_codex_command_argv("sh -c 'echo $HOME'") is None


def test_conflict_keys_come_back_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda _request: {"identities": [{"digests": ["a", "b"]}]})
    assert codex_hook_identity.canonical_codex_hook_conflict_keys(
        source_scope="user",
        source_hooks_enabled=True,
        event_name="PreToolUse",
        group={"hooks": [{"command": "x"}, {"command": "y"}]},
    ) == ("a", "b")


def test_scalars_json_cannot_carry_travel_as_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """A date, a time, a datetime, a non-finite float and a wide integer."""

    sent = _resident(monkeypatch, _digests)
    codex_hook_identity.canonical_codex_hook_identity(
        source_scope="user",
        source_hooks_enabled=True,
        event_name="PreToolUse",
        group={"since": date(2026, 10, 23), "ratio": float("inf"), "n": 10**40},
        handler={"at": time(9, 30), "stamp": datetime(2026, 1, 2, 3, 4, 5)},
    )
    (wire,) = sent
    tokens = wire["scalar_tokens"]
    assert isinstance(tokens, dict)
    assert sorted(tokens.values(), key=repr) == sorted(
        [
            {"type": "date", "value": "2026-10-23"},
            {"type": "float", "value": "inf"},
            {"__int__": "1" + "0" * 40},
            {"type": "time", "value": "09:30:00"},
            {"type": "datetime", "value": "2026-01-02T03:04:05"},
        ],
        key=repr,
    )
    entries = wire["entries"]
    assert isinstance(entries, list)
    group = entries[0]["group"]
    assert isinstance(group, dict)
    for key in ("since", "ratio", "n"):
        assert group[key] in tokens


def test_a_token_can_never_be_a_string_the_payload_already_holds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The prefix is redrawn until no string in the payload starts with it."""

    sent = _resident(monkeypatch, _digests)
    drawn = iter(["collides", "collides", "clear", "request-id"])
    monkeypatch.setattr(bridge, "uuid4", lambda: type("Hex", (), {"hex": next(drawn)})())
    codex_hook_identity.canonical_codex_hook_identity(
        source_scope="user",
        source_hooks_enabled=True,
        event_name="PreToolUse",
        group={"collides-0": "collides-0", "when": date(2026, 10, 23)},
        handler={},
    )
    tokens = sent[0]["scalar_tokens"]
    assert isinstance(tokens, dict)
    assert list(tokens) == ["clear-0"]


def test_a_key_json_cannot_name_arrives_in_its_canonical_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _digests)
    codex_hook_identity.canonical_codex_hook_identity(
        source_scope="user",
        source_hooks_enabled=True,
        event_name="PreToolUse",
        group={1: "one"},
        handler={},
    )
    entries = sent[0]["entries"]
    assert isinstance(entries, list)
    assert entries[0]["group"] == {"<int>:1": "one"}


def test_an_unusable_reply_leaves_the_caller_without_an_identity() -> None:
    for reply in (
        lambda _request: None,
        lambda _request: {"identities": []},
        lambda _request: {"identities": [["not a mapping"]]},
        lambda _request: {},
    ):
        monkeypatch_context = pytest.MonkeyPatch()
        _resident(monkeypatch_context, reply)
        with pytest.raises(bridge.CodexHookIdentityUnavailableError):
            codex_hook_identity.canonical_codex_hook_identity(
                source_scope="user",
                source_hooks_enabled=True,
                event_name="PreToolUse",
                group={},
                handler={},
            )
        monkeypatch_context.undo()


def test_a_resident_that_cannot_start_is_not_a_missing_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/codex-hook-identity-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(bridge.CodexHookIdentityUnavailableError):
        codex_hook_identity.canonical_codex_hook_group_identity(
            source_scope="user",
            source_hooks_enabled=True,
            event_name="PreToolUse",
            group={},
        )


def _nested(depth: int) -> dict[str, object]:
    """A group mapping whose deepest value sits ``depth`` levels down.

    The mapping itself is the first level, so the innermost string is reached
    after ``depth - 1`` wrappers.
    """

    value: object = "echo hi"
    for _ in range(depth - 1):
        value = {"nested": value}
    return cast("dict[str, object]", value)


def test_a_definition_the_resident_would_read_still_ships(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _digests)
    codex_hook_identity.canonical_codex_hook_group_identity(
        source_scope="user",
        source_hooks_enabled=True,
        event_name="PreToolUse",
        group=_nested(bridge._MAX_DEFINITION_DEPTH),
    )
    assert len(sent) == 1


def test_a_definition_deeper_than_the_resident_reads_names_the_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _digests)
    with pytest.raises(bridge.CodexHookDefinitionTooDeepError) as raised:
        codex_hook_identity.canonical_codex_hook_group_identity(
            source_scope="user",
            source_hooks_enabled=True,
            event_name="PreToolUse",
            group=_nested(bridge._MAX_DEFINITION_DEPTH + 1),
        )
    assert raised.value.code == "native_codex_hook_definition_too_deep"
    # A caller that only knows the broad failure still fails closed on it.
    assert isinstance(raised.value, bridge.CodexHookIdentityUnavailableError)
    assert sent == []


def test_a_deep_list_counts_toward_the_same_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, _digests)
    group: object = ["leaf"]
    for _ in range(bridge._MAX_DEFINITION_DEPTH - 1):
        group = {"nested": group}
    with pytest.raises(bridge.CodexHookDefinitionTooDeepError):
        codex_hook_identity.canonical_codex_hook_group_identity(
            source_scope="user",
            source_hooks_enabled=True,
            event_name="PreToolUse",
            group=cast("dict[str, object]", group),
        )
    assert sent == []

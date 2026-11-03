"""The Codex hook identity bridge ships definitions and keeps no fallback."""

from __future__ import annotations

import json
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


def _identity(**question: object) -> str:
    """Ask the bridge for one handler identity, as a single-entry request."""

    entry = {"kind": "handler", **question}
    return codex_hook_identity._digest_of(bridge.native_codex_hook_identity([entry])[0])


def _argv(command: str | None) -> tuple[str, ...] | None:
    """Ask the bridge to tokenize one command, as a single-entry request."""

    entry: dict[str, object] = {"kind": "argv"}
    if command is not None:
        entry["command"] = command
    argv = bridge.native_codex_hook_identity([entry])[0].get("argv")
    if argv is None:
        return None
    assert isinstance(argv, list)
    return tuple(cast(list[str], argv))


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
    _identity(
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
    assert _argv("echo hi") == ("echo", "hi")
    assert sent[0]["entries"] == [
        {
            "kind": "argv",
            "source_scope": "",
            "source_hooks_enabled": False,
            "event_name": "",
            "command": "echo hi",
        }
    ]


def test_an_inventory_request_leaves_out_empty_binding_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    """The resident digests the request it re-serializes, which drops an empty list."""

    sent = _resident(monkeypatch, lambda _request: {"identities": [{"records": [], "issues": []}]})
    binding = {"event": "Stop", "group": {"matcher": None}, "handler": {"type": "command", "command": "x"}}
    entry = {
        "kind": "inventory",
        "source_scope": "global",
        "source_hooks_enabled": True,
        "source_format": "json",
        "hooks": {"Stop": []},
        "authenticated_bindings": [],
        "legacy_bindings": [binding],
        "self_bindings": (),
    }
    bridge.native_codex_hook_identity([entry], required_feature=bridge.CODEX_HOOK_INVENTORY_FEATURE)
    (wire,) = sent[0]["entries"]
    assert "authenticated_bindings" not in wire
    assert "self_bindings" not in wire
    assert wire["legacy_bindings"] == [binding]
    assert wire["events"] == [["Stop", []]]


def _inventory_entry(**fields: object) -> dict[str, object]:
    return {"kind": "inventory", "source_scope": "user", "source_format": "toml", **fields}


def test_a_binding_scalar_json_cannot_carry_travels_as_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """A binding naming a TOML date still claims its handler instead of being dropped."""

    sent = _resident(monkeypatch, lambda _request: {"identities": [{"records": [], "issues": []}]})
    handler = {"type": "command", "command": "guard-hook", "since": date(2026, 10, 23), "ratio": float("inf")}
    binding = {"event": "Stop", "group": {"matcher": None}, "handler": handler}
    entry = _inventory_entry(hooks={"Stop": [{"hooks": [handler]}]}, self_bindings=[binding])
    bridge.native_codex_hook_identity([entry], required_feature=bridge.CODEX_HOOK_INVENTORY_FEATURE)
    (wire,) = sent[0]["entries"]
    tokens = sent[0]["scalar_tokens"]
    assert isinstance(tokens, dict)
    (wired,) = wire["self_bindings"]
    assert tokens[wired["handler"]["since"]] == {"type": "date", "value": "2026-10-23"}
    assert tokens[wired["handler"]["ratio"]] == {"type": "float", "value": "inf"}


def test_an_event_name_that_is_not_a_string_travels_without_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    """The walk reports it as an unsupported event rather than reading its groups."""

    sent = _resident(monkeypatch, lambda _request: {"identities": [{"records": [], "issues": []}]})
    groups = [{"hooks": [{"type": "command", "command": "x"}]}]
    entry = _inventory_entry(hooks={1: groups, "Stop": groups})
    bridge.native_codex_hook_identity([entry], required_feature=bridge.CODEX_HOOK_INVENTORY_FEATURE)
    (wire,) = sent[0]["entries"]
    assert wire["events"][0] == ["<int>:1", None]
    assert wire["events"][1][0] == "Stop"


def _echo_commands(request: dict[str, object]) -> dict[str, object]:
    entries = request["entries"]
    assert isinstance(entries, list)
    return {"identities": [{"argv": [entry["command"]]} for entry in entries]}


def test_a_batch_too_large_for_one_reply_splits_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(
        monkeypatch, lambda request: {"identities": [{"argv": [e["command"]]} for e in request["entries"]]}
    )
    monkeypatch.setattr(bridge, "_SPLIT_REQUEST_BYTES", 600)
    entries = [{"kind": "argv", "command": f"{index:02d}" + "x" * 120} for index in range(6)]
    answers = bridge.native_codex_hook_identity(entries)
    assert [answer["argv"] for answer in answers] == [[entry["command"]] for entry in entries]
    assert len(sent) > 1
    assert sum(len(request["entries"]) for request in sent) == len(entries)


def test_a_source_with_many_short_handlers_splits_before_its_reply_outgrows_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Thousands of short commands keep the request small but not the reply."""

    sent = _resident(
        monkeypatch, lambda request: {"identities": [{"records": [], "issues": []} for _ in request["entries"]]}
    )
    handlers = [{"type": "command", "command": f"{index:04d}" + "x" * 96} for index in range(1500)]
    groups = [{"matcher": "Bash", "hooks": [handler]} for handler in handlers]
    entries = [_inventory_entry(hooks={event: groups}) for event in ("PreToolUse", "PostToolUse")]
    bridge.native_codex_hook_identity(entries, required_feature=bridge.CODEX_HOOK_INVENTORY_FEATURE)
    assert len(sent) == 2
    assert all(len(json.dumps(request)) < bridge._SPLIT_REQUEST_BYTES for request in sent)


def test_the_reply_estimate_covers_a_real_inventory_record() -> None:
    """Shaped like ``record_json`` in the resident's inventory walk."""

    command = "node ./hooks/guard.js --event pre-tool-use"
    group = {"matcher": "Bash|Edit", "hooks": [{"type": "command", "command": command, "timeout": 30}]}
    record = {
        "event_name": "PreToolUse",
        "group_index": 4095,
        "handler_index": 0,
        "matcher": "Bash|Edit",
        "handler_type": "command",
        "command": command,
        "command_argv": command.split(),
        "timeout": 30,
        "environment_keys": [],
        "active": True,
        "executable": True,
        "ownership": "authenticated",
        "canonical_identity": "f" * 64,
    }
    wire = {"kind": "inventory", "events": [["PreToolUse", [group]]]}
    assert bridge._reply_estimate([wire]) - 2 * len(json.dumps(wire)) >= len(json.dumps(record))


def test_an_argv_answer_of_null_is_not_an_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda _request: {"identities": [{"argv": None}]})
    assert _argv("sh -c 'echo $HOME'") is None


def test_conflict_keys_come_back_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch, lambda _request: {"identities": [{"digests": ["a", "b"]}]})
    assert codex_hook_identity.canonical_codex_hook_group_conflict_keys(
        (
            codex_hook_identity.CodexHookGroupQuestion(
                source_scope="user",
                source_hooks_enabled=True,
                event_name="PreToolUse",
                group={"hooks": [{"command": "x"}, {"command": "y"}]},
            ),
        )
    ) == (("a", "b"),)


def test_scalars_json_cannot_carry_travel_as_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """A date, a time, a datetime, a non-finite float and a wide integer."""

    sent = _resident(monkeypatch, _digests)
    _identity(
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
    _identity(
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
    _identity(
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
            _identity(
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
        codex_hook_identity.canonical_codex_hook_group_identities(
            (
                codex_hook_identity.CodexHookGroupQuestion(
                    source_scope="user",
                    source_hooks_enabled=True,
                    event_name="PreToolUse",
                    group={},
                ),
            )
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
    codex_hook_identity.canonical_codex_hook_group_identities(
        (
            codex_hook_identity.CodexHookGroupQuestion(
                source_scope="user",
                source_hooks_enabled=True,
                event_name="PreToolUse",
                group=_nested(bridge._MAX_DEFINITION_DEPTH),
            ),
        )
    )
    assert len(sent) == 1


def test_a_definition_deeper_than_the_resident_reads_names_the_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _resident(monkeypatch, _digests)
    with pytest.raises(bridge.CodexHookDefinitionTooDeepError) as raised:
        codex_hook_identity.canonical_codex_hook_group_identities(
            (
                codex_hook_identity.CodexHookGroupQuestion(
                    source_scope="user",
                    source_hooks_enabled=True,
                    event_name="PreToolUse",
                    group=_nested(bridge._MAX_DEFINITION_DEPTH + 1),
                ),
            )
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
        codex_hook_identity.canonical_codex_hook_group_identities(
            (
                codex_hook_identity.CodexHookGroupQuestion(
                    source_scope="user",
                    source_hooks_enabled=True,
                    event_name="PreToolUse",
                    group=cast("dict[str, object]", group),
                ),
            )
        )
    assert sent == []

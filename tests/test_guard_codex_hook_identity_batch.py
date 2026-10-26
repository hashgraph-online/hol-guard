"""One walk of a Codex hook source asks the resident once, not once per hook."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_hook_identity
from codex_plugin_scanner.guard import native_codex_hook_identity as bridge
from codex_plugin_scanner.guard.adapters import codex
from codex_plugin_scanner.guard.codex_hook_inventory import (
    CODEX_HOOK_INVENTORY_DEFINITION_TOO_DEEP,
    CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE,
    enumerate_codex_hooks,
)

_SOURCE = Path("/tmp/codex-hook-identity-batch/config.toml")


def _resident(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Stub the transport; the returned list records every request wire sent."""

    sent: list[dict[str, object]] = []
    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda _home: Path("/tmp/codex-hook-identity-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: True)

    def fake(*, request, **_kwargs):
        sent.append(request)
        return {"identities": [_answer(index, entry) for index, entry in enumerate(request["entries"])]}

    monkeypatch.setattr(bridge, "_resident_request", fake)
    monkeypatch.setattr(bridge, "_payload", lambda response, _request, _home: response)
    return sent


def _answer(index: int, entry: dict[str, object]) -> dict[str, object]:
    """Answer one entry the way the resident would, distinctly per position."""

    kind = entry["kind"]
    if kind == "argv":
        command = entry.get("command")
        return {"argv": command.split() if isinstance(command, str) else None}
    if kind == "conflict":
        return {"digests": [f"c{index}"]}
    return {"digest": f"d{index}"}


def _walk(payload: dict[str, object]):
    return enumerate_codex_hooks(
        payload,
        source_path=_SOURCE,
        source_scope="user",
        source_format="toml",
        source_hooks_enabled=True,
    )


def _payload_with_three_handlers() -> dict[str, object]:
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {"type": "command", "command": "echo one"},
                        {"type": "command", "command": "echo two"},
                    ],
                },
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo three"}]},
            ]
        }
    }


def test_a_whole_source_costs_one_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    inventory = _walk(_payload_with_three_handlers())
    assert len(sent) == 1
    assert [record.command for record in inventory.records] == ["echo one", "echo two", "echo three"]


def test_every_record_keeps_its_own_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch)
    inventory = _walk(_payload_with_three_handlers())
    assert [record.command_argv for record in inventory.records] == [
        ("echo", "one"),
        ("echo", "two"),
        ("echo", "three"),
    ]
    assert len({record.canonical_identity for record in inventory.records}) == 3
    assert all(record.canonical_identity for record in inventory.records)


def test_each_handler_asks_for_its_tokens_and_its_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    _walk(_payload_with_three_handlers())
    (wire,) = sent
    entries = wire["entries"]
    assert isinstance(entries, list)
    assert [entry["kind"] for entry in entries] == ["argv", "handler", "argv", "handler", "argv", "handler"]


def test_a_handler_that_is_not_an_object_asks_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    inventory = _walk(
        {
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": ["not a handler", {"type": "command", "command": "echo one"}]}]
            }
        }
    )
    (wire,) = sent
    entries = wire["entries"]
    assert isinstance(entries, list)
    assert [entry["kind"] for entry in entries] == ["argv", "handler"]
    assert [record.command for record in inventory.records] == ["echo one"]
    assert inventory.issues


def test_a_source_without_handlers_never_reaches_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    inventory = _walk({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": []}]}})
    assert sent == []
    assert inventory.records == ()


def test_an_unavailable_resident_leaves_no_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    inventory = _walk(_payload_with_three_handlers())
    assert inventory.records == ()
    assert [issue.reason_code for issue in inventory.issues] == [CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE]
    assert inventory.issues[0].source_path == str(_SOURCE)
    assert not inventory.complete


def test_an_unavailable_resident_stops_an_install_before_it_activates(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    inventory = _walk(_payload_with_three_handlers())
    with pytest.raises(RuntimeError, match=CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE):
        codex._require_complete_preactivation_inventory(inventory)


def test_an_unavailable_resident_stops_a_migration_instead_of_merging(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(RuntimeError, match=CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE):
        codex._append_unique_hook_groups(
            [{"matcher": "*", "hooks": [{"type": "command", "command": "echo one"}]}],
            [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo two"}]}],
            event_name="PreToolUse",
            source_scope="user",
            source_hooks_enabled=True,
        )


def test_an_unavailable_resident_stops_a_readback_instead_of_passing_it(monkeypatch: pytest.MonkeyPatch) -> None:
    _resident(monkeypatch)
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(RuntimeError, match=CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE):
        codex._canonical_hook_semantics(_payload_with_three_handlers(), source_scope="user")


def _group_questions() -> list[codex_hook_identity.CodexHookGroupQuestion]:
    return [
        codex_hook_identity.CodexHookGroupQuestion(
            source_scope="user",
            source_hooks_enabled=True,
            event_name="PreToolUse",
            group={"matcher": matcher},
        )
        for matcher in ("*", "Bash")
    ]


def test_every_group_identity_travels_in_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    assert codex_hook_identity.canonical_codex_hook_group_identities(_group_questions()) == ("d0", "d1")
    (wire,) = sent
    entries = wire["entries"]
    assert isinstance(entries, list)
    assert [entry["kind"] for entry in entries] == ["group", "group"]


def test_every_group_conflict_key_travels_in_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    assert codex_hook_identity.canonical_codex_hook_group_conflict_keys(_group_questions()) == (("c0",), ("c1",))
    (wire,) = sent
    entries = wire["entries"]
    assert isinstance(entries, list)
    assert [entry["kind"] for entry in entries] == ["conflict", "conflict"]


def test_no_questions_never_reach_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    assert codex_hook_identity.canonical_codex_hook_handler_identities([]) == ()
    assert codex_hook_identity.canonical_codex_hook_group_identities([]) == ()
    assert codex_hook_identity.canonical_codex_hook_group_conflict_keys([]) == ()
    assert sent == []


def test_a_definition_the_resident_will_not_read_names_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch)
    handler: object = {"type": "command", "command": "echo one"}
    for _ in range(40):
        handler = {"nested": handler}
    inventory = _walk({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [handler]}]}})
    assert inventory.records == ()
    assert [issue.reason_code for issue in inventory.issues] == [CODEX_HOOK_INVENTORY_DEFINITION_TOO_DEEP]
    assert sent == []

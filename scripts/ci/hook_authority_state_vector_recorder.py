"""Record parity vectors for the signed Claude/Cursor hook authority state.

Run against the Python implementation that preceded the resident
``hook_authority_state`` op (base commit ``d3bf08bbca``)::

    python scripts/ci/hook_authority_state_vector_recorder.py

Each scenario replays a sequence of actions on a fresh store: raw writes that
plant or tamper state, and ``op`` actions that call one retired helper of
``commands_support_hook_state``. After every ``op`` the recorder snapshots the
``sync_state`` rows and the ``guard_events`` audit rows, so the Rust replay can
assert the result and every persisted side effect byte for byte. The integrity
key and the clock are pinned; the approval code is passed to the resident, so no
randomness is recorded.

The output is gzip JSON at
``rust/crates/guard-runtime/tests/fixtures/hook_authority_state_vectors.json.gz``.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
import tempfile
from pathlib import Path

from hook_authority_state_vector_claude_scenarios import claude_scenarios
from hook_authority_state_vector_cursor_scenarios import cursor_scenarios, freshness_scenario
from hook_authority_state_vector_support import CODE, KEY, KEY_ID, OUT, T0, hook_state, key_b64

from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.store import GuardStore


class Clock:
    now = T0


def snapshot(store: GuardStore) -> dict[str, object]:
    with sqlite3.connect(store.path) as connection:
        sync = {
            row[0]: {"payload_json": row[1], "updated_at": row[2]}
            for row in connection.execute("select state_key, payload_json, updated_at from sync_state order by 1")
        }
        events = [
            {"event_name": row[0], "payload": json.loads(row[1]), "occurred_at": row[2]}
            for row in connection.execute(
                "select event_name, payload_json, occurred_at from guard_events order by 1, 2"
            )
        ]
    parsed = {}
    for key, row in sync.items():
        try:
            payload = json.loads(row["payload_json"])
        except ValueError:
            payload = {"__raw__": row["payload_json"]}
        parsed[key] = {"payload": payload, "updated_at": row["updated_at"]}
    return {"sync_state": parsed, "events": events}


def artifact_from(spec: dict[str, object]) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=str(spec["artifact_id"]),
        name=str(spec.get("name", "Bash")),
        harness=str(spec.get("harness", "claude-code")),
        artifact_type=str(spec.get("artifact_type", "tool_action_request")),
        source_scope=str(spec.get("source_scope", "project")),
        config_path=str(spec.get("config_path", "/workspace/.env")),
        command=spec.get("command"),  # type: ignore[arg-type]
        metadata=dict(spec.get("metadata", {})),  # type: ignore[arg-type]
    )


def call_op(store: GuardStore, op: str, args: dict[str, object]) -> object:
    """Call the retired helper that ``op`` replaces and return its JSON result."""

    now = str(args["now"])
    Clock.now = now
    if op == "claude_record_notice":
        spied: list[dict[str, object]] = []
        original = hook_state._store_signed_hook_authority_payload

        def spy(store, *, state_key, payload, purpose, now):
            spied.append(dict(payload))
            return original(store, state_key=state_key, payload=payload, purpose=purpose, now=now)

        hook_state._store_signed_hook_authority_payload = spy
        try:
            payload: dict[str, object] = {"session_id": args["session_id"]}
            if args.get("tool_name") is not None:
                payload["tool_name"] = args["tool_name"]
            hook_state._record_claude_permission_notice(
                store=store,
                payload=payload,
                reason=str(args["reason"]),
                artifact=artifact_from(args["artifact"]),  # type: ignore[arg-type]
                artifact_hash=str(args["artifact_hash"]),
            )
        finally:
            hook_state._store_signed_hook_authority_payload = original
        # The resident receives the notice body the Python wrapper assembles;
        # it is the unsigned payload the first signed store saw.
        return {"notice_payload": spied[0] if spied else None}
    if op == "claude_load_notice":
        payload = {"session_id": args["session_id"]}
        if args.get("tool_name") is not None:
            payload["tool_name"] = args["tool_name"]
        return {"notice": hook_state._load_verified_claude_permission_notice(store, payload)}
    if op == "claude_mark_prompt_seen":
        hook_state._mark_claude_pending_permission_prompt_seen(
            store=store,
            payload={"session_id": args["session_id"]},
            notice={
                "artifact_id": args["artifact_id"],
                "artifact_hash": args["artifact_hash"],
                "command": args["command"],
            },
        )
        return {}
    if op == "claude_load_single_pending":
        pair = hook_state._load_single_claude_pending_permission(store, {"session_id": args["session_id"]})
        if pair is None:
            return {"pending_key": None, "pending": None}
        return {"pending_key": pair[0], "pending": pair[1]}
    if op == "claude_load_pending":
        return {
            "pending": hook_state._load_verified_claude_pending_permission(
                store,
                session_id=str(args["session_id"]),
                pending_key=str(args["pending_key"]),
                expected_artifact_id=args.get("expected_artifact_id"),  # type: ignore[arg-type]
                expected_artifact_hash=args.get("expected_artifact_hash"),  # type: ignore[arg-type]
                expected_command=args.get("expected_command"),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "claude_remove_pending":
        hook_state._remove_claude_pending_permission(
            store, session_id=str(args["session_id"]), pending_key=str(args["pending_key"])
        )
        return {}
    if op == "claude_load_index":
        return {
            "pending_keys": hook_state._load_claude_pending_permission_index(
                store, session_id=str(args["session_id"]), now=now
            )
        }
    if op == "cursor_load_index":
        return {
            "pending_keys": hook_state._load_cursor_pending_shell_index(
                store, conversation_id=str(args["conversation_id"]), now=now
            )
        }
    if op == "cursor_store_index":
        return {
            "stored": hook_state._store_cursor_pending_shell_index(
                store,
                conversation_id=str(args["conversation_id"]),
                pending_keys=list(args["pending_keys"]),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "cursor_append_key":
        return {
            "stored": hook_state._append_cursor_pending_shell_key(
                store,
                conversation_id=str(args["conversation_id"]),
                pending_key=str(args["pending_key"]),
                now=now,
            )
        }
    if op == "cursor_store_pending_state":
        return {
            "stored": hook_state._store_cursor_pending_shell_state(
                store,
                conversation_id=str(args["conversation_id"]),
                command=str(args["command"]),
                payload=dict(args["payload"]),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "cursor_load_pending_state":
        return {
            "pending": hook_state._load_verified_cursor_pending_shell_state(
                store,
                conversation_id=str(args["conversation_id"]),
                command=str(args["command"]),
                state_key=args.get("state_key"),  # type: ignore[arg-type]
                now=now,
            )
        }
    if op == "cursor_record_allow":
        return {
            "stored": hook_state._record_cursor_native_shell_allow_state(
                store=store,
                conversation_id=str(args["conversation_id"]),
                command=str(args["command"]),
                artifact=artifact_from(args["artifact"]),  # type: ignore[arg-type]
                artifact_hash=str(args["artifact_hash"]),
                now=now,
            )
        }
    if op == "cursor_load_allowance":
        return {
            "allowance": hook_state._load_cursor_native_shell_allowance(
                store, {"conversation_id": args["conversation_id"], "command": args["command"], "tool_name": "Shell"}
            )
        }
    if op == "state_is_fresh":
        return {
            "fresh": hook_state._hook_authority_state_is_fresh(
                {"saved_at": args["saved_at"]} if args["saved_at"] is not None else {},
                now=now,
                max_age_seconds=int(args["max_age_seconds"]),  # type: ignore[arg-type]
            )
        }
    raise SystemExit(f"unknown op {op}")


def wire_args(op: str, args: dict[str, object], result: object) -> dict[str, object]:
    """The fields the resident op receives for ``op`` (what the Python wrapper sends)."""

    from codex_plugin_scanner.guard.adapters.cursor_native_approval import normalize_cursor_shell_command

    wire = {name: value for name, value in args.items() if name not in {"artifact", "reason"}}
    if op == "claude_record_notice":
        wire = {"session_id": args["session_id"], "now": args["now"], "payload": dict(result["notice_payload"])}  # type: ignore[index]
        if args.get("tool_name") is not None:
            wire["tool_name"] = args["tool_name"]
    elif op == "cursor_store_pending_state":
        wire = {
            "conversation_id": args["conversation_id"],
            "state_key": hook_state._cursor_pending_shell_state_key(str(args["conversation_id"]), str(args["command"])),
            "payload": args["payload"],
            "now": args["now"],
        }
    elif op == "cursor_load_pending_state":
        normalized = normalize_cursor_shell_command(str(args["command"]))
        expected = hook_state._cursor_pending_shell_state_key(str(args["conversation_id"]), normalized)
        wire = {
            "conversation_id": args["conversation_id"],
            "command": normalized,
            "state_key": args.get("state_key") or expected,
            "expected_key": expected,
            "now": args["now"],
        }
    elif op == "cursor_record_allow":
        normalized = normalize_cursor_shell_command(str(args["command"]))
        artifact = args["artifact"]
        wire = {
            "conversation_id": args["conversation_id"],
            "state_key": hook_state._cursor_native_shell_allow_state_key(str(args["conversation_id"]), normalized),
            "command": normalized,
            "artifact_id": artifact["artifact_id"],  # type: ignore[index]
            "artifact_hash": args["artifact_hash"],
            "artifact_name": artifact["name"],  # type: ignore[index]
            "now": args["now"],
        }
    elif op == "cursor_load_allowance":
        command = hook_state._cursor_shell_command_from_payload({"command": args["command"]})
        wire = {
            "conversation_id": args["conversation_id"],
            "command": command,
            "state_key": hook_state._cursor_native_shell_allow_state_key(str(args["conversation_id"]), str(command)),
            "now": args["now"],
        }
    return wire


def record(scenario_name: str, actions: list[dict[str, object]]) -> dict[str, object]:
    recorded: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as tmp:
        store = GuardStore(Path(tmp) / "home")
        key_state = {"present": True, "key_id": KEY_ID}

        def material(*, create: bool) -> tuple[bytes | None, str | None]:
            if not key_state["present"]:
                return None, None
            return KEY, str(key_state["key_id"])

        store._policy_integrity_secret_material = material  # type: ignore[method-assign]
        hook_state._now = lambda: Clock.now  # type: ignore[assignment]
        for action in actions:
            kind = action["do"]
            if kind == "raw_set":
                store.set_sync_payload(str(action["key"]), action["payload"], str(action.get("now", T0)))  # type: ignore[arg-type]
                recorded.append(dict(action))
            elif kind == "raw_set_text":
                with sqlite3.connect(store.path) as connection:
                    connection.execute(
                        "insert or replace into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
                        (action["key"], action["text"], action.get("now", T0)),
                    )
                recorded.append(dict(action))
            elif kind == "raw_copy":
                value = store.get_sync_payload(str(action["from"]))
                store.set_sync_payload(str(action["to"]), value, T0)  # type: ignore[arg-type]
                recorded.append({"do": "raw_set", "key": action["to"], "payload": value})
            elif kind == "raw_mutate":
                value = store.get_sync_payload(str(action["key"]))
                assert isinstance(value, dict)
                for name, replacement in dict(action["set"]).items():  # type: ignore[arg-type]
                    value[name] = replacement
                for name in action.get("drop", []):  # type: ignore[union-attr]
                    value.pop(name, None)
                store.set_sync_payload(str(action["key"]), value, T0)
                recorded.append({"do": "raw_set", "key": action["key"], "payload": value})
            elif kind == "raw_delete":
                store.delete_sync_payload(str(action["key"]))
                recorded.append(dict(action))
            elif kind == "key":
                key_state["present"] = bool(action["present"])
                key_state["key_id"] = action.get("key_id", KEY_ID)
                recorded.append(dict(action))
            elif kind == "op":
                args = dict(action["args"])  # type: ignore[arg-type]
                result = call_op(store, str(action["op"]), args)
                recorded.append(
                    {
                        "do": "op",
                        "op": action["op"],
                        "args": wire_args(str(action["op"]), args, result),
                        "key_present": key_state["present"],
                        "key_id": key_state["key_id"],
                        "result": result,
                        "after": snapshot(store),
                    }
                )
            else:
                raise SystemExit(f"unknown action {kind}")
    return {"name": scenario_name, "actions": recorded}


def main() -> None:
    import secrets

    secrets.token_hex = lambda _count=0: CODE  # type: ignore[assignment]
    scenarios = claude_scenarios() + cursor_scenarios() + [freshness_scenario()]
    document = {
        "recorded_from": "d3bf08bbca",
        "key_b64": key_b64(),
        "key_id": KEY_ID,
        "approval_code": CODE,
        "scenarios": [record(name, actions) for name, actions in scenarios],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.GzipFile(OUT, "wb", mtime=0) as handle:
        handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    print(f"recorded {len(document['scenarios'])} scenarios -> {OUT}")


if __name__ == "__main__":
    main()

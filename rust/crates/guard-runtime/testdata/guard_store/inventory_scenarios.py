"""Scenarios for the artifact inventory/snapshot/capability parity vectors.

Shared by the recorder (which runs them through the ORIGINAL Python store) and
the Python parity test (which replays them through the new wrappers). Steps are
either `{"sql": [(statement, params), ...]}` or `{"method", "args", "kwargs"}`.
"""

from __future__ import annotations

import dataclasses

from codex_plugin_scanner.guard.models import GuardArtifact

T1 = "2026-07-18T20:00:00+00:00"
T2 = "2026-07-18T20:05:00+00:00"
T3 = "2026-07-18T20:10:00+00:00"
SEQUENCE_KEY = "aibom_trust_attestation_sequence"


def jsonable(value: object) -> object:
    """Dataclass results (CapabilitySet) become plain JSON for comparison."""

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


def artifact(artifact_id: str, harness: str = "codex", **overrides: object) -> GuardArtifact:
    fields: dict[str, object] = {
        "artifact_id": artifact_id,
        "name": f"name-{artifact_id}",
        "harness": harness,
        "artifact_type": "mcp_server",
        "source_scope": "project",
        "config_path": "/work/space/.mcp.json",
        "command": "npx",
        "args": ("-y", "pkg café"),
        "url": None,
        "transport": "stdio",
        "publisher": "acme",
    }
    fields.update(overrides)
    return GuardArtifact(**fields)  # type: ignore[arg-type]


def call(method: str, label: str = "", *args: object, **kwargs: object) -> dict[str, object]:
    return {"method": method, "label": label, "args": args, "kwargs": kwargs}


def sql(label: str, *statements: tuple[str, tuple[object, ...]]) -> dict[str, object]:
    return {"label": label, "sql": list(statements)}


def _inventory_row(artifact_id: str, harness: str, name: str, action: object, approved: str | None, seen: str):
    return (
        "insert into artifact_inventory (artifact_id, harness, artifact_name, artifact_type, source_scope, "
        "config_path, publisher, origin_url, launch_command, transport, first_seen_at, last_seen_at, "
        "last_changed_at, last_approved_at, removed_at, present, last_policy_action, artifact_hash) "
        "values (?, ?, ?, 'mcp_server', 'project', '/p', null, null, null, null, ?, ?, null, ?, null, 1, ?, 'h')",
        (artifact_id, harness, name, T1, seen, approved, action),
    )


def _record(art: GuardArtifact, now: str, action: object = "allow", **overrides: object):
    kwargs: dict[str, object] = {
        "artifact": art,
        "artifact_hash": f"hash-{art.artifact_id}-{now[-14:-9]}",
        "policy_action": action,
        "changed": False,
        "now": now,
        "approved": False,
    }
    kwargs.update(overrides)
    return call("record_inventory_artifact", f"record {art.artifact_id} {action}", **kwargs)


SCENARIOS: list[dict[str, object]] = [
    {
        "name": "snapshots",
        "steps": [
            call("get_snapshot", "missing", "codex", "a1"),
            call("save_snapshot", "first", "codex", "a1", {"b": 1, "a": [1, 2.5, None], "n": "café"}, "h1", T1),
            call("get_snapshot", "present", "codex", "a1"),
            call("save_snapshot", "other artifact", "codex", "a2", {"x": True}, "h2", T1),
            call("save_snapshot", "other harness", "claude-code", "a1", {"y": 2}, "h3", T1),
            call("save_snapshot", "overwrite", "codex", "a1", {"b": 2}, "h4", T2),
            call("get_snapshot", "after overwrite", "codex", "a1"),
            call("list_snapshots", "codex", "codex"),
            call("list_snapshots", "none", "unknown"),
            call("delete_snapshot", "delete", "codex", "a1"),
            call("delete_snapshot", "delete again", "codex", "a1"),
            call("list_snapshots", "after delete", "codex"),
            call("save_snapshot", "scalar snapshot", "codex", "a3", [1, 2], "h5", T3),
            call("get_snapshot", "list snapshot", "codex", "a3"),
        ],
    },
    {
        "name": "diffs",
        "steps": [
            call("record_diff", "with previous", "codex", "a1", ["command", "args"], "old", "new", T1),
            call("record_diff", "no previous", "codex", "a1", [], None, "new2", T2),
            call("record_diff", "unicode field", "claude-code", "a2", ["café"], "new2", "new3", T3),
        ],
    },
    {
        "name": "inventory",
        "steps": [
            call("list_inventory", "empty"),
            call("find_inventory_item", "missing", "a1"),
            _record(artifact("a1"), T1),
            _record(artifact("a1"), T2, changed=True, approved=True),
            _record(artifact("a2", name="alpha"), T2, "warn", approved=True),
            _record(artifact("a1", "claude-code", command=None, args=()), T3, "review"),
            _record(artifact("a3", name="Beta", url="https://x.example/m", command="uvx"), T2, "ask"),
            call("list_inventory", "all"),
            call("list_inventory", "codex only", "codex"),
            call("find_inventory_item", "latest of two harnesses", "a1"),
            _record(artifact("a1"), T3, "block", approved=True),
            _record(artifact("a1"), T3, "bogus"),
            _record(artifact("a1"), T3, None),
            _record(artifact("a1"), T3, 5),
            _record(artifact("a1"), T3, "review", approved=True),
            call(
                "mark_inventory_removed",
                "block",
                harness="codex",
                artifact_id="a1",
                policy_action="block",
                artifact_hash="gone",
                now=T3,
            ),
            call(
                "mark_inventory_removed",
                "keeps approval for allow",
                harness="codex",
                artifact_id="a2",
                policy_action="allow",
                artifact_hash="gone2",
                now=T3,
            ),
            call(
                "mark_inventory_removed",
                "unknown id",
                harness="codex",
                artifact_id="zz",
                policy_action="allow",
                artifact_hash="x",
                now=T3,
            ),
            call(
                "mark_inventory_removed",
                "bad action",
                harness="codex",
                artifact_id="a1",
                policy_action="nonsense",
                artifact_hash="x",
                now=T3,
            ),
            call("list_inventory", "after removal"),
            _record(artifact("a1"), T3, "allow", artifact_hash="back", approved=True),
            call("find_inventory_item", "revived", "a1"),
        ],
    },
    {
        "name": "inventory_stored_actions",
        "steps": [
            sql(
                "seed rows with legacy, unknown and missing actions",
                _inventory_row("s1", "codex", "one", "allow", T1, T2),
                _inventory_row("s2", "codex", "two", "ask", T1, T2),
                _inventory_row("s3", "codex", "three", "garbage", T1, T2),
                _inventory_row("s4", "codex", "four", "", T1, T2),
                _inventory_row("s5", "codex", "five", "block", T1, T2),
                _inventory_row("s6", "codex", "six", "sandbox-required", T1, T2),
                _inventory_row("s7", "codex", "seven", "warn", T1, T2),
            ),
            call("list_inventory", "all"),
            call("find_inventory_item", "legacy ask", "s2"),
            call("find_inventory_item", "garbage", "s3"),
            call("find_inventory_item", "null", "s4"),
        ],
    },
    {
        "name": "capabilities",
        "steps": [
            call("get_artifact_capability", "missing", "codex", "a1"),
            call(
                "save_artifact_capability",
                "full",
                harness="codex",
                artifact_id="a1",
                capability_snapshot={
                    "network_hosts": ["a.example", 3, "b.example"],
                    "network_schemes": ["https"],
                    "filesystem_paths": ["/tmp"],
                    "secret_classes": ["token"],
                    "subprocess_invocation": True,
                    "interpreters": ["python"],
                    "shell_wrappers": ["bash"],
                    "publisher": "acme",
                    "transport": "stdio",
                },
                now=T1,
            ),
            call("get_artifact_capability", "full", "codex", "a1"),
            call(
                "save_artifact_capability",
                "sparse overwrite",
                harness="codex",
                artifact_id="a1",
                capability_snapshot={"publisher": 7, "transport": "carrier-pigeon"},
                now=T2,
            ),
            call("get_artifact_capability", "sparse", "codex", "a1"),
            sql(
                "non-dict row",
                (
                    "insert into artifact_capabilities (artifact_id, harness, capability_json, updated_at) "
                    "values ('n1', 'codex', '[1, 2]', 't')",
                    (),
                ),
            ),
            call("get_artifact_capability", "non-dict payload", "codex", "n1"),
        ],
    },
    {
        "name": "provenance_cache",
        "steps": [
            call("upsert_provenance_cache", "insert", artifact_hash="h1", payload={"k": [1, 2], "u": "café"}, now=T1),
            call("upsert_provenance_cache", "overwrite", artifact_hash="h1", payload={"k": []}, now=T2),
            call("upsert_provenance_cache", "second hash", artifact_hash="h2", payload={}, now=T3),
        ],
    },
    {
        "name": "attestation_sequence",
        "steps": [
            call("next_aibom_trust_attestation_sequence", "first", T1),
            call("next_aibom_trust_attestation_sequence", "second", T2),
            sql(
                "string digits",
                (
                    'update sync_state set payload_json = \'{"sequence": "7"}\' '
                    f"where state_key = '{SEQUENCE_KEY}'",
                    (),
                ),
            ),
            call("next_aibom_trust_attestation_sequence", "from string", T3),
            sql(
                "negative",
                (f"update sync_state set payload_json = '{{\"sequence\": -3}}' where state_key = '{SEQUENCE_KEY}'", ()),
            ),
            call("next_aibom_trust_attestation_sequence", "from negative", T3),
            sql(
                "boolean",
                (
                    f"update sync_state set payload_json = '{{\"sequence\": true}}' where state_key = '{SEQUENCE_KEY}'",
                    (),
                ),
            ),
            call("next_aibom_trust_attestation_sequence", "from boolean", T3),
            sql(
                "float",
                (
                    f"update sync_state set payload_json = '{{\"sequence\": 2.0}}' where state_key = '{SEQUENCE_KEY}'",
                    (),
                ),
            ),
            call("next_aibom_trust_attestation_sequence", "from float", T3),
            sql("not json", (f"update sync_state set payload_json = '{{oops' where state_key = '{SEQUENCE_KEY}'", ())),
            call("next_aibom_trust_attestation_sequence", "from garbage", T3),
            sql(
                "not an object", (f"update sync_state set payload_json = '[5]' where state_key = '{SEQUENCE_KEY}'", ())
            ),
            call("next_aibom_trust_attestation_sequence", "from list", T3),
            sql(
                "empty string",
                (
                    f"update sync_state set payload_json = '{{\"sequence\": \"\"}}' where state_key = '{SEQUENCE_KEY}'",
                    (),
                ),
            ),
            call("next_aibom_trust_attestation_sequence", "from empty string", T3),
        ],
    },
]

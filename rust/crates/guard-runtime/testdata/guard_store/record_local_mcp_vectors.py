#!/usr/bin/env python3
"""Record observed MCP connection vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python implementation
of `find_local_mcp_observation` and `ensure_local_mcp_observation`, never
against the branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Each scenario replays `local_mcp_scenarios.SCENARIOS` through the Python store
on a real `guard.db`, with the wall clock pinned to `NOW`. Per step the
vectors hold the request the native transport must send (`wire_args`,
translated here independently of the new code), the Python result as the
resident's payload (or the error), and the post-step state of every table.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard import store_local_cli_retention, store_local_mcp

if not hasattr(store_local_mcp, "_insert_mcp_observation"):
    sys.exit("refusing to record: the original Python MCP observation implementation is gone")

from local_mcp_scenarios import NOW, SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.store import GuardStore

TABLES = {
    "local_cli_observation": "cli_id",
    "local_cli_grant": "cli_id",
    "local_cli_command_grant": "cli_id, command_id",
    "local_cli_authority": "singleton",
    "local_cli_command": "cli_id, command_id",
    "local_mcp_catalog": "cli_id",
    "local_mcp_tool_authority": "cli_id, identity_hash, tool_name",
    "local_mcp_provider_action": "cli_id, identity_hash, provider, tool_slug",
    "local_mcp_provider_authority": "cli_id, identity_hash",
    "local_mcp_workflow_proposal": "cli_id, identity_hash, proposal_id",
    "local_cli_forgotten": "identity_hash",
    "local_cli_retention_state": "singleton",
}
FIND_KEYS = ("cli_id", "server_identity_hash", "command", "args_hash")
ENSURE_KEYS = (
    "server_identity_hash",
    "server_command",
    "server_args_hash",
    "source_label",
    "connection_identity_hash",
    "replay_now",
)


class _FrozenClock(datetime):
    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return datetime.fromisoformat(NOW).astimezone(tz)


store_local_cli_retention.datetime = _FrozenClock  # type: ignore[misc]


def call_kwargs(kwargs: dict[str, object]) -> dict[str, object]:
    out = dict(kwargs)
    if "identity" in out:
        out["identity"] = UnlistedCliIdentity(**out["identity"])  # type: ignore[arg-type]
    return out


def wire(method: str, kwargs: dict[str, object]) -> dict[str, object]:
    if method == "find_local_mcp_observation":
        return {key: kwargs.get(key) for key in FIND_KEYS}
    if method == "ensure_local_mcp_observation":
        ident = kwargs["identity"]
        assert isinstance(ident, dict)
        out = {
            key: ident[key] for key in ("cli_id", "identity_hash", "kind", "name", "interpreter_name", "example_label")
        }
        out.update({key: kwargs.get(key) for key in ENSURE_KEYS})
        # The vectors hold the outcome after Python closed the policy barrier.
        out.update(
            seen_at=kwargs["seen_at"],
            replayed=kwargs.get("replayed", False),
            barrier_closed=True,
            clock="<NOW>",
        )
        return out
    raise AssertionError(method)


def payload(method: str, result: object) -> object:
    if method == "ensure_local_mcp_observation":
        return {"cli_id": result}
    return json.loads(json.dumps(result))


def ensure_retention_tables(path: Path) -> None:
    connection = sqlite3.connect(path)
    store_local_cli_retention._ensure_retention_tables(connection)
    connection.commit()
    connection.close()


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-local-mcp-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        ensure_retention_tables(path)
        previous = dump(path, TABLES)
        seed = previous
        steps: list[dict[str, object]] = []
        for step in scenario["steps"]:
            record: dict[str, object] = {"label": step.get("label", "")}
            if "sql" in step:
                connection = sqlite3.connect(path)
                for statement, params in step["sql"]:
                    connection.execute(statement, params)
                connection.commit()
                connection.close()
                record.update(method="sql", sql=step["sql"], wire_args=None, native_payload=None, error=None)
            else:
                method, kwargs = step["method"], step.get("kwargs", {})
                record.update(method=method, wire_args=wire(method, kwargs))
                try:
                    result = getattr(store, method)(**call_kwargs(kwargs))
                    record.update(native_payload=payload(method, result), error=None)
                except store_local_cli_retention.LocalCliReplaySkippedError:
                    record.update(native_payload={"replay_skipped": True}, error=None)
                except ValueError as error:
                    record.update(
                        native_payload=None,
                        error={"type": "ValueError", "message": str(error), "message_exact": True},
                    )
            current = dump(path, TABLES)
            record["post_changed"] = {t: rows_ for t, rows_ in current.items() if rows_ != previous[t]}
            previous = current
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-local-mcp-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path)
        ensure_retention_tables(path)
        schema = schema_sql_for_tables(path, TABLES)
    document = {
        "schema": "guard-store-local-mcp-vectors.v1",
        "source": "guard",
        "now": NOW,
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))

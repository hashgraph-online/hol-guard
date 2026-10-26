#!/usr/bin/env python3
"""Record advisory cache vectors from the ORIGINAL Python store.

Run against a checkout that still holds the pre-native Python cache
(`StoreCloudEventsMixin.cache_advisories` writing `publisher_cache` itself),
never against the branch under test and never from Rust output:

    cd <origin-main-worktree>
    PYTHONPATH=$PWD/src python3 <this-file> <output vectors.json>

Per step the vectors hold the request the native transport must send
(`wire_args`, translated here independently of the new code), the Python
result, and the `publisher_cache` rows afterwards. A list result is the
decoded advisories the Python caller saw; the resident returns the stored
rows and the caller decodes them.
"""

from __future__ import annotations

import inspect
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

os.environ["HOL_GUARD_NATIVE"] = "off"
os.environ.pop("HOL_GUARD_NATIVE_BINARY", None)
sys.path.insert(0, str(Path(__file__).resolve().parent))

from codex_plugin_scanner.guard.store_cloud_events import StoreCloudEventsMixin

if "publisher_cache" not in inspect.getsource(StoreCloudEventsMixin.cache_advisories):
    sys.exit("refusing to record: the original Python advisory cache is gone")

from advisory_cache_scenarios import SCENARIOS
from vector_support import dump, schema_sql_for_tables

from codex_plugin_scanner.guard.store import GuardStore

TABLES = {"publisher_cache": "publisher_key"}
WIRE = {
    "cache_advisories": lambda kw: {"payloads": [json.dumps(item) for item in kw["advisories"]], "now": kw["now"]},
    "list_cached_advisories": lambda kw: {"limit": kw.get("limit", 100)},
}


def run_scenario(scenario: dict) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="guard-advisory-cache-vectors-") as root:
        store = GuardStore(Path(root) / "guard-home", prime_policy_integrity=False)
        path = Path(store.path)
        seed = dump(path, TABLES)
        steps: list[dict[str, object]] = []
        for step in scenario["steps"]:
            record: dict[str, object] = {"label": step.get("label", "")}
            if "sql" in step:
                connection = sqlite3.connect(path)
                for statement, params in step["sql"]:
                    connection.execute(statement, params)
                connection.commit()
                connection.close()
                record.update(method="sql", sql=step["sql"], wire_args=None, result=None)
            else:
                method, kwargs = step["method"], step.get("kwargs", {})
                record.update(method=method, wire_args=WIRE[method](kwargs))
                result = getattr(store, method)(**kwargs)
                record.update(result=json.loads(json.dumps(result)))
            record["after"] = dump(path, TABLES)
            steps.append(record)
        return {"name": scenario["name"], "seed": seed, "steps": steps}


def main(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="guard-advisory-cache-schema-") as root:
        path = Path(GuardStore(Path(root) / "guard-home", prime_policy_integrity=False).path)
        schema = schema_sql_for_tables(path, TABLES)
    document = {
        "schema": "guard-store-advisory-cache-vectors.v1",
        "source": "guard",
        "order_by": TABLES,
        "schema_sql": schema,
        "scenarios": [run_scenario(scenario) for scenario in SCENARIOS],
    }
    output.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]))

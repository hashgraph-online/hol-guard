"""Shared-vector end-to-end check of Cloud-connected package supply-chain evaluation.

``tests/fixtures/supply-chain-eval/cloud-cases.v1.json`` was recorded from the
pre-migration Python evaluator (see ``record_cloud_vectors.py`` and the file's
``recorded_from_commit``) and is language-neutral: the Rust crate replays every
case, including the ones that talk to a Cloud service. This test drives the real
resident through the Python transport for the offline cases (no live Cloud
service). There is no Python oracle; the vectors are the contract.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
    js_target,
)
from codex_plugin_scanner.guard.store import GuardStore

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "supply-chain-eval" / "cloud-cases.v1.json").read_text(encoding="utf-8")
)
OFFLINE_CASES = [case for case in VECTORS["cases"] if case["network"] is None]

pytestmark = pytest.mark.skipif(
    os.environ.get("HOL_GUARD_NATIVE_REGRESSION") != "1",
    reason="needs the resident runtime (HOL_GUARD_NATIVE_REGRESSION=1)",
)


def _artifact(targets: list[str], lockfile_paths: list[str]):
    tokens = ("npm", "install", *targets)
    intent = PackageIntent(
        package_manager="npm",
        intent_kind="install",
        command_tokens=tokens,
        redacted_command=" ".join(tokens),
        targets=tuple(js_target(target) for target in targets),
        manifest_paths=(),
        lockfile_paths=tuple(lockfile_paths),
        flags=(),
        notes=(),
    )
    return build_package_request_artifact("codex", intent, config_path="codex.json", source_scope="project")


def _seed_rows(db_path: Path, rows: dict[str, list[dict[str, object]]]) -> None:
    connection = sqlite3.connect(db_path)
    try:
        for table, table_rows in rows.items():
            connection.execute(f"DELETE FROM {table}")
            for row in table_rows:
                columns = ", ".join(row)
                placeholders = ", ".join("?" for _ in row)
                connection.execute(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})", tuple(row.values()))
        connection.commit()
    finally:
        connection.close()


def test_vector_set_covers_saved_policy_reuse_of_cached_cloud_errors() -> None:
    cached = [case for case in VECTORS["cases"] if case["name"].startswith("cached_cloud_error_")]
    assert {case["saved_policy"]["action"] if case["saved_policy"] else None for case in cached} == {
        "block",
        "allow",
        "warn",
        None,
    }
    assert all(case["saved_policy_probe"] is not None for case in cached)


def test_vector_set_covers_offline_and_cloud_cases() -> None:
    assert VECTORS["recorded_from_commit"]
    assert len(OFFLINE_CASES) >= 10
    assert len(VECTORS["cases"]) > len(OFFLINE_CASES)


@pytest.mark.parametrize("case", OFFLINE_CASES, ids=lambda case: case["name"])
def test_resident_cloud_connected_evaluation_matches_vector(case: dict, tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for name, spec in case["files"].items():
        (workspace / name).write_text(spec["text"], encoding="utf-8")
    home = tmp_path / "home"
    store = GuardStore(home)
    _seed_rows(home / "guard.db", case["rows"])
    if case["saved_policy"] is not None:
        # The saved row is seeded through the public store API, as the recorder did, so the
        # Python transport hydrates the same lookup the resident is asked to judge.
        store.upsert_policy(
            PolicyDecision(harness="codex", scope="global", action=case["saved_policy"]["action"], source="manual"),
            VECTORS["now"],
        )
    evaluation = evaluate_package_request_artifact(
        artifact=_artifact(case["targets"], case["lockfile_paths"]),
        store=store,
        workspace_dir=workspace,
        now=VECTORS["now"],
    )
    # Evidence ids come from Python-side persistence of the reply, not from the verdict.
    actual = {key: value for key, value in evaluation.to_dict().items() if key != "evidence_ids"}
    expected = {key: value for key, value in case["expect"].items() if key != "evidence_ids"}
    assert actual == expected

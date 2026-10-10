"""Shared-vector end-to-end check of resident package supply-chain evaluation.

The expectations live in ``tests/fixtures/supply-chain-eval/cases.v1.json`` and
are language-neutral: the Rust crate replays the lockfile vectors, and this test
drives the real resident through the Python transport. There is no Python
oracle; the vectors are the contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_supply_chain import evaluate_package_request_artifact
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
    js_target,
)
from codex_plugin_scanner.guard.store import GuardStore

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "supply-chain-eval" / "cases.v1.json").read_text(encoding="utf-8")
)

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


def _file_bytes(spec: dict[str, str]) -> bytes:
    return bytes.fromhex(spec["bytes_hex"]) if "bytes_hex" in spec else spec["text"].encode("utf-8")


@pytest.mark.parametrize("case", VECTORS["evaluation"], ids=lambda case: case["name"])
def test_resident_evaluation_matches_vector(case: dict, tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    for name, spec in case["files"].items():
        (workspace / name).write_bytes(_file_bytes(spec))
    home = tmp_path / "home"
    home.mkdir()
    for name, spec in case.get("home_files", {}).items():
        (home / name).write_bytes(_file_bytes(spec))
    store = GuardStore(home)
    evaluation = evaluate_package_request_artifact(
        artifact=_artifact(case["targets"], case["lockfile_paths"]),
        store=store,
        workspace_dir=workspace,
        now="2026-05-19T00:00:00Z",
    )
    expect = case["expect"]
    for field in ("decision", "policy_action", "enforcement", "entitlement_state", "policy_version"):
        assert getattr(evaluation, field) == expect[field], field
    assert [reason["code"] for reason in evaluation.reasons] == expect["reason_codes"]
    if "summary_contains" in expect:
        assert expect["summary_contains"] in evaluation.user_copy.summary
    assert [
        [package.get("ecosystem"), package.get("name") or package.get("package_name"), package.get("decision")]
        for package in evaluation.packages
    ] == expect["packages"]

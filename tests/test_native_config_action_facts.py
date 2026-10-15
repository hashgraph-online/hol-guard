"""The Python facts projection reproduces the recorded configured-action queries."""

from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path

import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifact_policy import (
    _runtime_artifact_policy_action,
    runtime_policy_artifact_facts,
    runtime_policy_config_facts,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/config_action_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_config_action_vectors.py"


def _recorder():
    spec = importlib.util.spec_from_file_location("record_config_action_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vectors() -> list[dict]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def test_facts_projection_reproduces_recorded_queries(tmp_path: Path) -> None:
    recorder = _recorder()
    vectors = _vectors()
    assert len(vectors) >= 900
    for vector in vectors:
        config = recorder.build_config(vector["spec"]["config"], tmp_path)
        artifact = recorder.build_artifact(vector["spec"]["artifact"])
        assert {
            "policy_config": runtime_policy_config_facts(config, recorder.HARNESS),
            "artifact": runtime_policy_artifact_facts(config, artifact, recorder.HARNESS),
        } == vector["query"], vector["name"]


def test_recorded_actions_cover_every_action_and_auto_stops() -> None:
    vectors = _vectors()
    assert {item["expected"]["action"] for item in vectors} >= {
        "allow",
        "warn",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }
    assert any(item["expected"]["auto_stop_events"] for item in vectors)


def test_native_action_matches_recorded_python_actions(native_approval_reuse_runtime: Path) -> None:
    recorder = _recorder()
    for vector in _vectors()[:60]:
        config = recorder.build_config(vector["spec"]["config"], native_approval_reuse_runtime)
        artifact = recorder.build_artifact(vector["spec"]["artifact"])
        assert (
            _runtime_artifact_policy_action(
                config, artifact, recorder.HARNESS, guard_home=native_approval_reuse_runtime
            )
            == vector["expected"]["action"]
        ), vector["name"]

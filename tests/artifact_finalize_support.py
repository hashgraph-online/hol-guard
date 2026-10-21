"""Shared helpers for the artifact final-settle parity suites.

``scripts/ci/record_artifact_finalize_vectors.py`` recorded the retired Python
settle; the suites in ``tests/test_artifact_finalize_*.py`` hand its vectors to
the new executor.
"""

from __future__ import annotations

import copy
import gzip
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_finalize as finalize
from codex_plugin_scanner.guard import native_hook_decision as decision
from codex_plugin_scanner.guard.cli import commands_hook_native_state as state_module

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "rust/crates/guard-runtime/tests/fixtures/artifact_finalize_vectors.json.gz"
RECORDER = ROOT / "scripts/ci/record_artifact_finalize_vectors.py"
FEATURE = finalize.HOOK_DECISION_ARTIFACT_FINALIZE_FEATURE


def load_recorder() -> Any:
    spec = importlib.util.spec_from_file_location("record_artifact_finalize_vectors", RECORDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_vectors() -> dict[str, Any]:
    return json.loads(gzip.decompress(VECTORS.read_bytes()))


def vector_key(facts: object) -> str:
    return json.dumps(facts, sort_keys=True)


def settle_reply(vector: dict[str, Any]) -> dict[str, Any]:
    """The resident's payload: the objects whose key order is persisted are rebuilt from their wire text."""

    payload = copy.deepcopy(vector["answer"])
    payload["evidence_patch"]["fields"] = json.loads(vector["wire"]["fields"])
    if vector["wire"]["resolution"] is not None:
        payload["receipt"]["appended_evidence"] = [json.loads(vector["wire"]["resolution"])]
    return {"kind": "artifact_finalize", **payload}


def resident_stub(monkeypatch: pytest.MonkeyPatch, answer: Any) -> list[dict[str, Any]]:
    """Stand in for the resident behind the wrapper's real shape validation."""

    asked: list[dict[str, Any]] = []

    def decide(query: dict[str, Any], guard_home: object, validate: Any, feature: str = "") -> dict[str, Any]:
        assert feature == FEATURE
        asked.append(query)
        payload = answer(query)
        validate(payload)
        return payload

    monkeypatch.setattr(finalize, "_decide", decide)
    return asked


def stub_renderers(monkeypatch: pytest.MonkeyPatch, recorder: Any) -> None:
    monkeypatch.setattr(state_module, "build_decision_v2", recorder.stub_decision_v2)
    monkeypatch.setattr(state_module, "build_incident_context", recorder.stub_incident_context)


def plan_state() -> SimpleNamespace:
    state = load_recorder().SettleCase(previous_action="review", policy_action="block").state()
    state.event_name = "PreToolUse"
    state.runtime_artifact = SimpleNamespace(artifact_type="tool_action_request", source_scope="s", config_path="c")
    return state


def unavailable(*_args: object, **_kwargs: object) -> dict[str, Any]:
    raise decision.NativeHookDecisionError("native_hook_decision_unavailable")

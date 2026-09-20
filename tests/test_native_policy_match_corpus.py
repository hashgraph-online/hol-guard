"""Shared matcher cases come from real protected and signed policy lookups.

These fixtures test generic matching only. They are not resident, installed
package, native classification, managed-control, or application evidence.
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_authority_contract import (
    NATIVE_SCOPED_AUTHORITY_FEATURE,
    NativePolicyAuthorityCapabilities,
)
from codex_plugin_scanner.guard.native_policy_authority_read import read_native_policy_authority_inputs
from codex_plugin_scanner.guard.runtime.approval_context import parse_approval_context_token
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import (
    _global_runtime_scoped_exact_match_key,
    _runtime_scoped_exact_match_key,
    runtime_tool_action_exact_match_context,
    runtime_tool_action_portable_match_context,
)
from tests.test_canonical_policy_row_authority import _ARTIFACT, _NOW, _activated_store
from tests.test_guard_approval_reuse import _approval_context_token
from tests.test_policy_workspace_hash_authority import _store_with_workspace_rule

_TIME = datetime.fromisoformat(_NOW.replace("Z", "+00:00")).timestamp()
_REQUEST = {
    "harness": "codex", "artifact_id": "codex:project:tool-action:synthetic-action",
    "artifact_hash": "synthetic-hash", "workspace": "synthetic-workspace", "publisher": "synthetic-publisher",
}
_FIXTURE = Path(__file__).parents[1] / "rust/crates/guard-policy-snapshot/src/scoped_authority_match_fixture.json"
_V4 = NativePolicyAuthorityCapabilities(4, frozenset({NATIVE_SCOPED_AUTHORITY_FEATURE}))


def _row(scope: str = "artifact", action: str = "allow", **values: object) -> dict[str, object]:
    row: dict[str, object] = {"scope": scope, "action": action, "harness": "codex", "source": "local"}
    if scope in {"artifact", "workspace", "harness", "global"}:
        row["artifact_id"] = _REQUEST["artifact_id"]
    if scope == "workspace":
        row["workspace"] = _REQUEST["workspace"]
    if scope == "publisher":
        row["publisher"] = _REQUEST["publisher"]
    return {**row, **values}


def _cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []

    def add(name: str, rows: list[dict[str, object]], **values: object) -> None:
        cases.append({"name": name, "rows": rows, "request": dict(_REQUEST), **values})

    for digest in ("synthetic-hash", "different-hash", None):
        suffix = digest or "missing"
        add(f"artifact-{suffix}", [_row(artifact_hash="synthetic-hash")],
            request={**_REQUEST, "artifact_hash": digest})
        add(f"workspace-hash-{suffix}", [_row("workspace", artifact_id=None, artifact_hash="synthetic-hash")],
            request={**_REQUEST, "artifact_hash": digest})
        add(f"signed-workspace-hash-{suffix}", [], source="signed-workspace",
            request={**_REQUEST, "artifact_hash": digest})
    add("workspace-family", [_row("workspace", artifact_id="family:tool-action")])
    add("workspace-family-miss", [_row("workspace", artifact_id="family:prompt")])
    add("workspace-other", [_row("workspace", workspace="different-workspace")])
    add("workspace-windows-normalization", [_row("workspace", workspace="C:\\Synthetic\\Project\\")],
        request={**_REQUEST, "workspace": "c:/synthetic/project"})
    add("publisher", [_row("publisher")])
    add("publisher-miss", [_row("publisher", publisher="different-publisher")])
    add("harness-miss", [_row(harness="cursor")])
    add("harness-wildcard", [_row(harness="*")])
    add("local-family-without-exact-context", [_row("harness")])
    add("local-family-legacy-exact", [_row(
        "harness", artifact_hash=_runtime_scoped_exact_match_key(_REQUEST["artifact_id"]),
    )])
    token = _approval_context_token(content="synthetic-content")
    add("local-family-context-token", [_row("harness", artifact_hash=token)],
        request={**_REQUEST, "artifact_hash": token})
    add("local-family-context-miss", [_row("harness", artifact_hash=token)])
    context = runtime_tool_action_exact_match_context(
        config_path="/synthetic/project/config", source_scope="project", raw_command_text="printf synthetic",
    )
    portable = runtime_tool_action_portable_match_context(context)
    add("global-portable-exact", [_row("global", artifact_hash=_global_runtime_scoped_exact_match_key(
        _REQUEST["artifact_id"], portable,
    ))], request={**_REQUEST, "runtime_exact_match_context": context})
    add("global-broad", [_row("global", artifact_id=None)])
    add("expired-at-boundary", [_row(expires_at="2026-09-17T00:00:10Z")], now_ms=int((_TIME + 10) * 1_000))
    for first, second in (
        ("artifact", "workspace"), ("workspace", "publisher"), ("publisher", "harness"), ("harness", "global"),
    ):
        artifact = "codex:project:prompt-env-read:synthetic-priority"
        add(f"scope-{first}-over-{second}", [
            _row(first, artifact_id=artifact, updated_at="2026-09-17T00:00:01Z"),
            _row(second, "block", artifact_id=artifact, updated_at="2026-09-17T00:00:02Z"),
        ], request={**_REQUEST, "artifact_id": artifact})
    for local_time, label in (("2026-09-16T23:59:59Z", "older"), ("2026-09-17T00:00:01Z", "newer"), (_NOW, "tied")):
        add(f"signed-recency-{label}", [_row("artifact", "allow", artifact_id=_ARTIFACT,
            artifact_hash="synthetic-hash", updated_at=local_time)], source="signed-artifact",
            request={**_REQUEST, "artifact_id": _ARTIFACT})
    return cases


def _produce_case(case: dict[str, object], tmp_path: Path) -> dict[str, object]:
    if case.get("source") == "signed-artifact":
        store = _activated_store(tmp_path, action="block")
    elif case.get("source") == "signed-workspace":
        store = _store_with_workspace_rule(tmp_path, source="signed", digest="synthetic-hash")
    else:
        store = GuardStore(tmp_path / "guard-home")
        store.get_device_metadata()
    for raw in case["rows"]:
        value = dict(raw)
        updated_at = value.pop("updated_at", _NOW)
        store.upsert_policy(PolicyDecision(**value), updated_at)
    request = dict(case["request"])
    now_ms = case.get("now_ms", int((_TIME + 3) * 1_000))
    current = datetime.fromtimestamp(now_ms / 1_000, tz=timezone.utc).isoformat()
    selected = store.resolve_policy_decision(**request, now=current, consume_one_shot=False)
    consumed = store.resolve_policy_decision(**request, now=current, consume_one_shot=True)
    expected = {key: selected[key] for key in ("scope", "action")} if selected else None
    assert ({key: consumed[key] for key in ("scope", "action")} if consumed else None) == expected
    authority = read_native_policy_authority_inputs(store, now=_TIME + 2).authority.for_snapshot(_V4)
    context = request.pop("runtime_exact_match_context", None)
    artifact, digest = request["artifact_id"], request["artifact_hash"]
    portable = runtime_tool_action_portable_match_context(context)
    exact = {
        "artifact_legacy": _runtime_scoped_exact_match_key(artifact),
        "runtime": _runtime_scoped_exact_match_key(artifact, context) if digest is not None else None,
        "portable": (
            _runtime_scoped_exact_match_key(artifact, portable) if digest is not None and context is not None else None
        ),
        "global": (
            _global_runtime_scoped_exact_match_key(artifact, portable)
            if digest is not None and context is not None else None
        ),
        "approval": digest if parse_approval_context_token(digest) is not None else None,
    }
    return {"name": case["name"], "authority": authority, "request": {**request, "exact": exact},
        "now_ms": now_ms, "expected": expected}


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_shared_matcher_fixture_matches_authenticated_python_consumers(case, tmp_path: Path) -> None:
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    expected = next(value for value in fixture["cases"] if value["name"] == case["name"])
    assert _produce_case(deepcopy(case), tmp_path) == expected

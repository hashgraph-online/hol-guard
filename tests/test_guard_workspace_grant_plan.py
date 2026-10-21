"""The grant fields of a workspace sandbox plan, checked as Rust checks them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import restricted_workspace as workspace_sink
from codex_plugin_scanner.guard.runtime.restricted_pytest import RestrictedPytestError
from codex_plugin_scanner.guard.runtime.restricted_workspace_grants import (
    PLAN_FIELDS,
    ExpectedGrant,
    grant_script_roots,
)
from tests.test_guard_restricted_workspace import plan

VECTORS = Path(__file__).parent / "fixtures" / "workspace_grant_plan" / "parity_vectors.json"


def _expected(value: dict[str, object] | None) -> ExpectedGrant | None:
    if value is None:
        return None
    return ExpectedGrant(
        identity_hash=str(value["identity_hash"]),
        capabilities=tuple(value["capabilities"]),
        state_dir=value["state_dir"],
    )


def _cases() -> list[dict[str, object]]:
    return json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["name"])
def test_parity_vectors_match_rust(case: dict[str, object]) -> None:
    assert grant_script_roots(case["plan"], _expected(case["expected"])) == case["result"]


def test_the_plan_names_its_grant_fields() -> None:
    assert {"grant_identity_hash", "capabilities"} <= PLAN_FIELDS
    assert len(PLAN_FIELDS) == 20


@pytest.fixture(autouse=True)
def macos_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace_sink, "_host_backend", lambda: "macos-seatbelt")


def test_a_base_plan_with_empty_grant_fields_is_accepted(tmp_path: Path) -> None:
    accepted = workspace_sink._validated_plan(plan(tmp_path, "make"), "make", tmp_path)
    assert accepted["grant_identity_hash"] is None
    assert accepted["capabilities"] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"capabilities": ["network"]},
        {"capabilities": ["loopback-network"]},
        {"capabilities": "loopback-network"},
        {"grant_identity_hash": "a" * 64},
        {
            "profile_version": "workspace-contained-grant-v1",
            "grant_identity_hash": "a" * 64,
            "capabilities": ["loopback-network"],
        },
    ],
)
def test_a_grant_the_runner_was_not_given_is_rejected(tmp_path: Path, changes: dict[str, object]) -> None:
    with pytest.raises(RestrictedPytestError):
        workspace_sink._validated_plan(plan(tmp_path, "make", **changes), "make", tmp_path)


def test_a_plan_missing_a_grant_field_is_rejected(tmp_path: Path) -> None:
    missing = plan(tmp_path, "make")
    del missing["capabilities"]
    with pytest.raises(RestrictedPytestError):
        workspace_sink._validated_plan(missing, "make", tmp_path)


def test_the_state_directory_is_split_from_the_script_roots() -> None:
    expected = ExpectedGrant("a" * 64, ("state-dir-read", "state-dir-write"), "/home/dev/.lanectl")
    granted = {
        "profile_version": "workspace-contained-grant-v1",
        "grant_identity_hash": "a" * 64,
        "capabilities": ["state-dir-write"],
        "read_only_roots": ["/opt/tool/run.js", "/home/dev/.lanectl"],
    }
    assert grant_script_roots(granted, expected) == ["/opt/tool/run.js"]
    assert grant_script_roots(granted | {"capabilities": ["state-dir-write", "unknown"]}, expected) is None

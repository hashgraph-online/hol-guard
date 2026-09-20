"""Source component proof for generic commands with independently loaded origins.

These calls use the explicit Python test oracle. They neither execute commands
nor claim native, installed, interactive-approval, or capability acceptance.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from itertools import combinations, product
from pathlib import Path
from typing import Literal, cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook import _run_guard_hook_command
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import (
    _artifact_id_from_event,
    _hook_runtime_artifact,
)
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.mdm.policy import load_managed_policy
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.store import GuardStore

Selector = Literal["default", "harness", "publisher", "artifact"]
Mode = Literal["enforce", "observe"]
SELECTORS: tuple[Selector, ...] = ("default", "harness", "publisher", "artifact")
ACTIONS: tuple[GuardAction, ...] = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
ARTIFACT = "codex:project:Shell"
PUBLISHER = "synthetic-publisher"
COMMANDS = ("ssh synthetic@example.invalid", "printf '%s' Synthetic")


@dataclass(frozen=True)
class Case:
    name: str
    local: dict[str, object]
    managed: dict[str, object]
    selected: GuardAction


def setting(selector: Selector, action: GuardAction) -> dict[str, object]:
    if selector == "default":
        return {"default_action": action}
    key, target = {
        "harness": ("harnesses", "codex"),
        "publisher": ("publishers", PUBLISHER),
        "artifact": ("artifacts", ARTIFACT),
    }[selector]
    return {key: {target: action}}


def cases() -> tuple[Case, ...]:
    result: list[Case] = []
    for local, managed, restricted in product(SELECTORS, SELECTORS, ("local", "managed")):
        result.append(
            Case(
                f"{restricted}-block-local-{local}-managed-{managed}",
                setting(local, "block" if restricted == "local" else "allow"),
                setting(managed, "block" if restricted == "managed" else "allow"),
                "block",
            )
        )
    # Lower-priority selectors are not independent floors within one origin.
    for broad, narrow in combinations(SELECTORS, 2):
        for origin in ("local", "managed"):
            settings = {**setting(broad, "block"), **setting(narrow, "allow")}
            result.append(
                Case(
                    f"{origin}-{narrow}-allow-over-{broad}-block",
                    settings if origin == "local" else {},
                    settings if origin == "managed" else {"default_action": "allow"},
                    "allow",
                )
            )
    for action in ACTIONS:
        result.append(Case(f"managed-default-{action}", {}, {"default_action": action}, action))
    result.extend(
        (
            Case("managed-default-absent-local-warn", {"default_action": "warn"}, {}, "warn"),
            Case(
                "managed-default-explicit-allow-local-warn",
                {"default_action": "warn"},
                {"default_action": "allow"},
                "warn",
            ),
            Case("unrelated-managed-artifact", {}, {"artifacts": {"synthetic:other": "block"}}, "allow"),
            Case("unrelated-managed-publisher", {}, {"publishers": {"synthetic-other": "block"}}, "allow"),
        )
    )
    return tuple(result)


CASES = cases()


def _toml(payload: dict[str, object], prefix: tuple[str, ...] = ()) -> str:
    lines = [f"[{'.'.join(json.dumps(key) for key in prefix)}]"] if prefix else []
    for key, value in payload.items():
        if not isinstance(value, dict):
            assert isinstance(value, (str, int)) and not isinstance(value, bool)
            lines.append(f"{json.dumps(key)} = {json.dumps(value)}")
    for key, value in payload.items():
        if isinstance(value, dict):
            assert all(isinstance(child, str) for child in value)
            lines.append(_toml(cast(dict[str, object], value), (*prefix, key)))
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
@pytest.mark.parametrize("command", COMMANDS, ids=("destination-only", "ordinary-printf"))
@pytest.mark.parametrize("mode", ("enforce", "observe"))
def test_actual_generic_hook_preserves_origin_priority_and_observe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], case: Case, command: str, mode: Mode
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)
    store = GuardStore(home / "guard")
    local: dict[str, object] = {
        "mode": mode,
        "default_action": "allow",
        "unknown_publisher_action": "allow",
        "approval_wait_timeout_seconds": 0,
        **case.local,
    }
    _ = (store.guard_home / "config.toml").write_text(_toml(local))
    profile = home / "synthetic-managed.json"
    _ = profile.write_text(
        json.dumps(
            {
                "schemaVersion": "hol-guard-mdm-policy.v1",
                "settings": case.managed,
                "lockedSettings": list(case.managed),
            }
        )
    )
    managed = load_managed_policy(policy_path=profile, write_cache=False)
    assert managed.status == "active" and managed.policy is not None
    config = load_guard_config(store.guard_home, workspace=workspace, managed_policy_state=managed)
    assert config.managed_policy is managed.policy and config.local_policy_origin is not None
    assert config.local_policy_origin.managed_policy is None
    raw: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": command},
        "source_scope": "project",
        "publisher": PUBLISHER,
        # The decision and renderer remain real. Interactive approval delivery is
        # outside this component proof and does not launch a background service.
        "approval_requests": [],
    }
    payload = _normalize_hook_payload(raw, harness="codex")
    envelope = _hook_action_envelope(harness="codex", payload=payload, home_dir=home, workspace=workspace)
    assert envelope is not None
    assert (
        _hook_runtime_artifact(
            harness="codex",
            payload=payload,
            action_envelope=envelope,
            home_dir=home,
            guard_home=store.guard_home,
            workspace=workspace,
        )
        is None
    )
    assert _artifact_id_from_event("codex", payload) == ARTIFACT
    result = _run_guard_hook_command(
        argparse.Namespace(harness="codex", artifact_id=None, artifact_name=None, json=True, policy_action=None),
        guard_home=store.guard_home,
        workspace=workspace,
        context=HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=store.guard_home),
        store=store,
        config=config,
        input_text=json.dumps(raw),
    )
    output = cast(dict[str, object], json.loads(capsys.readouterr().out))
    composition = output["policy_composition"]
    assert isinstance(composition, dict)
    assert composition["configured_policy_action"] == case.selected
    # These requests have no modeled runtime artifact or verified-benign
    # default exemption. Their generic source selectors remain authoritative.
    current = case.selected
    observed = current if mode == "observe" and current not in {"allow", "warn"} else None
    final = "allow" if observed is not None else current
    assert composition["current_config_action"] == current
    assert composition["current_composed_action"] == current
    assert composition["configured_default_disposition"] == "applied"
    assert composition["observed_policy_action"] == observed
    assert composition["saved_policy_action"] is None
    assert output["artifact_id"] == ARTIFACT
    assert output["policy_action"] == final
    assert result == (0 if final in {"allow", "warn"} else 1)
    if current not in {"allow", "warn"}:
        receipt = store.list_receipts(limit=1)[0]
        assert receipt["artifact_id"] == ARTIFACT
        assert receipt["policy_decision"] == final

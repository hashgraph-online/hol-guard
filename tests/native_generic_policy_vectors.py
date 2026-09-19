"""Actual generic command producer and renderer evidence for native parity."""

from __future__ import annotations

import argparse
import io
import json
import os
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from unittest.mock import patch

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
from codex_plugin_scanner.guard.native_managed_configuration import project_managed_configuration
from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_generic_managed_origin_outer import CASES, COMMANDS, PUBLISHER, Case, Mode, _toml


@dataclass(frozen=True)
class GenericCase:
    configuration: Case
    command: str
    mode: Mode
    tool: str = "Shell"
    relax: bool = False


def cases() -> list[GenericCase]:
    result = [
        GenericCase(case, command, mode) for case in CASES for command in COMMANDS for mode in ("enforce", "observe")
    ]
    for tool in ("Shell", "Bash", "shell", "exec_command"):
        for action in ("review", "require-reapproval"):
            for selector in ("default", "artifact"):
                managed: dict[str, object] = (
                    {"default_action": action}
                    if selector == "default"
                    else {"artifacts": {f"codex:project:{tool}": action}}
                )
                config = Case(f"pwd-{selector}-{action}", {}, managed, action)
                for mode in ("enforce", "observe"):
                    result.append(
                        GenericCase(config, "pwd", mode, tool, selector == "default" and tool != "exec_command")
                    )
    # The selector matrix uses Shell. Independently exercise each other admitted
    # tool spelling through the real producer; a name alone proves no exemption.
    for tool in ("Bash", "shell", "exec_command"):
        for command in COMMANDS:
            for mode in ("enforce", "observe"):
                result.append(
                    GenericCase(Case("tool-contract", {}, {"default_action": "review"}, "review"), command, mode, tool)
                )
    return result


def evaluate_case(case: GenericCase, root: Path) -> dict[str, object]:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    store = GuardStore(root / "guard")
    local: dict[str, object] = {
        "mode": case.mode,
        "default_action": "allow",
        "unknown_publisher_action": "allow",
        "approval_wait_timeout_seconds": 0,
        **case.configuration.local,
    }
    _ = (store.guard_home / "config.toml").write_text(_toml(local))
    managed_input = {
        "schemaVersion": "hol-guard-mdm-policy.v1",
        "settings": case.configuration.managed,
        "lockedSettings": list(case.configuration.managed),
    }
    profile = root / "synthetic-managed.json"
    _ = profile.write_text(json.dumps(managed_input))
    managed = load_managed_policy(policy_path=profile, write_cache=False)
    assert managed.status == "active" and managed.policy is not None
    config = load_guard_config(store.guard_home, workspace=workspace, managed_policy_state=managed)
    assert config.managed_policy is managed.policy and config.local_policy_origin is not None
    payload: dict[str, object] = {
        "hook_event_name": "PreToolUse",
        "tool_name": case.tool,
        "tool_input": {"command": case.command},
        "source_scope": "project",
        "publisher": PUBLISHER,
        "approval_requests": [],
    }
    normalized = _normalize_hook_payload(payload, harness="codex")
    envelope = _hook_action_envelope(harness="codex", payload=normalized, home_dir=root, workspace=workspace)
    assert envelope is not None
    assert (
        _hook_runtime_artifact(
            harness="codex",
            payload=normalized,
            action_envelope=envelope,
            home_dir=root,
            guard_home=store.guard_home,
            workspace=workspace,
        )
        is None
    )
    artifact_id = _artifact_id_from_event("codex", normalized)
    output = io.StringIO()
    with (
        patch.dict(
            os.environ,
            {
                "HOL_GUARD_NATIVE": "off",
                "HOL_GUARD_PYTHON_ORACLE": "1",
                "HOL_GUARD_TEST_MODE": "1",
            },
            clear=False,
        ),
        redirect_stdout(output),
    ):
        code = _run_guard_hook_command(
            argparse.Namespace(harness="codex", artifact_id=None, artifact_name=None, json=True, policy_action=None),
            guard_home=store.guard_home,
            workspace=workspace,
            context=HarnessContext(home_dir=root, workspace_dir=workspace, guard_home=store.guard_home),
            store=store,
            config=config,
            input_text=json.dumps(payload),
        )
    rendered = cast(dict[str, object], json.loads(output.getvalue()))
    composition = rendered["policy_composition"]
    assert isinstance(composition, dict)
    current: GuardAction = "warn" if case.relax else case.configuration.selected
    observed = current if case.mode == "observe" and current not in {"allow", "warn"} else None
    final = "allow" if observed is not None else current
    assert composition["configured_policy_action"] == case.configuration.selected
    assert composition["current_config_action"] == current
    assert composition["current_composed_action"] == current
    assert composition["configured_default_disposition"] == ("relaxed_verified_benign" if case.relax else "applied")
    assert composition["observed_policy_action"] == observed
    assert composition["saved_policy_action"] is None
    assert rendered["artifact_id"] == artifact_id
    assert rendered["policy_action"] == final and code == (0 if final in {"allow", "warn"} else 1)
    origin = project_managed_configuration(config)
    return {
        "name": f"{case.tool}-{case.mode}-{case.configuration.name}-{case.command}",
        "harness": "codex",
        "mode": case.mode,
        "payload": payload,
        "artifactId": artifact_id,
        "configInputs": {"local": local, "managed": managed_input},
        "localEffectivePolicy": effective_native_policy_v3(config.local_policy_origin),
        "managedConfiguration": origin.to_mapping() if origin is not None else None,
        "expected": {
            "configuredPolicyAction": case.configuration.selected,
            "currentConfigAction": current,
            "observedPolicyAction": observed,
            "finalPolicyAction": final,
            "exitCode": code,
        },
    }


def generate_vectors(root: Path) -> dict[str, object]:
    return {
        "schema": "native-generic-origin-policy-fixtures.v1",
        "source": "actual local/MDM loader, generic producer, outer evaluator and renderer",
        "scope": "explicit Python component evidence; no native, installed, approval or capability acceptance",
        "context": (
            "Each case uses an isolated existing temporary workspace; "
            "no workspace selector or content identity is present."
        ),
        "cases": [evaluate_case(case, root / str(index)) for index, case in enumerate(cases())],
    }

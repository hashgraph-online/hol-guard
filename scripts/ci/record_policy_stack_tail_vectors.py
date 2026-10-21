#!/usr/bin/env python3
"""Record policy-stack tail vectors from the Python hook evaluation.

``evaluate_native_artifact_hook`` made four decisions around the policy stack
that the resident answers now:

* whether the native command floor is skipped (``skip_native_floor``, an
  artifact fact in ``hook_artifact_facts_op.rs``);
* whether local tool-grant eligibility is required (``local_eligibility_required``,
  a ``policy_stack`` answer);
* which composition trace the settled verdict records (``policy_composition``);
* the receipt's ``approval_source`` (``policy_composition``).

The functions below are that Python as it stood at 3b8ac2e848, kept here so the
oracle never calls the code it checks:

    PYTHONPATH=src .venv/bin/python scripts/ci/record_policy_stack_tail_vectors.py

Each vector names its ``kind`` and holds the inputs the resident is sent and the
answer the old Python produced.  The Rust ``hook_artifact_compose_policy_tail_tests``
replays every vector; ``tests/test_policy_stack_tail_parity.py`` replays them
through the Python bridge against the resident.

``approval_source`` and ``policy_composition`` are written into the persisted
receipt and the hook response, so the vectors pin them exactly: the same
inputs must produce the same key set, values and label.
"""

from __future__ import annotations

import copy
import gzip
import itertools
import json
import random
from collections.abc import Mapping, Sequence
from pathlib import Path

from codex_plugin_scanner.guard.action_lattice import normalize_guard_action

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/policy_stack_tail_vectors.json.gz")

ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "Stop", "pretooluse", "")
ARTIFACT_TYPES = (
    "tool_action_request",
    "package_request",
    "file_read_request",
    "prompt_request",
    "mcp_server",
    "",
)
PERMISSION: dict[str, object] = {
    "command_action_floor": "allow",
    "extension_control_resolution": {"blocked": False, "explicitly_enabled_permission_ids": ["command.git.stash"]},
    "command_decision_plane": {
        "action": "allow",
        "proof_routes": ["verified"],
        "controlling_reasons": [{"source": "control", "reason_code": "control.explicitly-enabled-permission"}],
    },
}


# --- The recorded Python -----------------------------------------------------


def _recorded_explicit_permission_allow(metadata: Mapping[str, object], command_action_floor: object) -> bool:
    if command_action_floor != "allow":
        return False
    resolution = metadata.get("extension_control_resolution")
    if not isinstance(resolution, Mapping) or resolution.get("blocked") is not False:
        return False
    permission_ids = resolution.get("explicitly_enabled_permission_ids")
    if (
        not isinstance(permission_ids, Sequence)
        or isinstance(permission_ids, str)
        or not permission_ids
        or any(not isinstance(item, str) or not item.startswith("command.") for item in permission_ids)
    ):
        return False
    decision = metadata.get("command_decision_plane")
    if not isinstance(decision, Mapping) or decision.get("action") != "allow":
        return False
    routes = decision.get("proof_routes")
    reasons = decision.get("controlling_reasons")
    return (
        isinstance(routes, Sequence)
        and not isinstance(routes, str)
        and "verified" in routes
        and isinstance(reasons, Sequence)
        and not isinstance(reasons, str)
        and any(
            isinstance(reason, Mapping)
            and reason.get("source") == "control"
            and reason.get("reason_code") == "control.explicitly-enabled-permission"
            for reason in reasons
        )
    )


def _recorded_command_action_floor(metadata: Mapping[str, object]) -> object:
    if "command_action_floor" not in metadata:
        return None
    return normalize_guard_action(metadata.get("command_action_floor"), unknown_action="block")


def recorded_skip_native_floor(artifact_type: str, metadata: Mapping[str, object]) -> bool:
    """``native_floor = None if <this> else native_pre_tool_floor(...)``."""

    return artifact_type == "package_request" or _recorded_explicit_permission_allow(
        metadata, _recorded_command_action_floor(metadata)
    )


def recorded_local_eligibility_required(event_name: str, artifact_type: str, has_raw_command: bool) -> bool:
    """The condition guarding ``local_tool_approval_eligibility``."""

    return (
        event_name == "PreToolUse" and artifact_type in {"tool_action_request", "package_request"} and has_raw_command
    )


def recorded_policy_composition(inputs: Mapping[str, object]) -> dict[str, object]:
    """The ``policy_composition`` dict, its evidence entry and ``approval_source``."""

    policy_composition = {
        "current_config_action": inputs["current_config_action"],
        "current_action_override": inputs["current_action_override"],
        "trusted_cli_override": inputs["trusted_cli_action"],
        "untrusted_hook_payload_hint": inputs["untrusted_payload_action"],
        "package_action": inputs["package_policy_action"],
        "data_flow_action": inputs["data_flow_action"],
        "scanner_action": inputs["scanner_action"],
        "current_composed_action": inputs["current_composed_action"],
        "saved_policy_action": inputs["saved_policy_action"],
        "approval_reuse_source": inputs["approval_reuse_source"],
        "trusted_request_override": inputs["trusted_request_override"],
        "trusted_request_override_reason": inputs["trusted_request_override_reason"],
        "authoritative_action": inputs["authoritative_action"],
    }
    evidence = {"source": "policy_composition", **policy_composition}
    approval_source = (
        "inline"
        if inputs["claude_native_approval_observed"] or inputs["user_override_present"]
        else "approval_center"
        if inputs["authoritative_action"] == "require-reapproval"
        else "policy"
    )
    return {"policy_composition": policy_composition, "evidence": evidence, "approval_source": approval_source}


# --- The cases ---------------------------------------------------------------


_MISSING = object()


def _permission(**changes: object) -> dict[str, object]:
    metadata = copy.deepcopy(PERMISSION)
    for key, value in changes.items():
        if value is _MISSING:
            metadata.pop(key, None)
        else:
            metadata[key] = value
    return metadata


def _resolution(**changes: object) -> dict[str, object]:
    resolution = copy.deepcopy(PERMISSION["extension_control_resolution"])
    assert isinstance(resolution, dict)
    for key, value in changes.items():
        if value is _MISSING:
            resolution.pop(key, None)
        else:
            resolution[key] = value
    return resolution


def _decision(**changes: object) -> dict[str, object]:
    decision = copy.deepcopy(PERMISSION["command_decision_plane"])
    assert isinstance(decision, dict)
    for key, value in changes.items():
        if value is _MISSING:
            decision.pop(key, None)
        else:
            decision[key] = value
    return decision


def permission_metadata() -> list[dict[str, object]]:
    """Every shape of the explicit-permission metadata the old reader judged."""

    reason = {"source": "control", "reason_code": "control.explicitly-enabled-permission"}
    shapes: list[dict[str, object]] = [
        {},
        copy.deepcopy(PERMISSION),
        {"command_action_floor": "allow"},
        {"extension_control_resolution": _resolution()},
        _permission(command_action_floor="review"),
        _permission(command_action_floor="warn"),
        _permission(command_action_floor="block"),
        _permission(command_action_floor="bogus"),
        _permission(command_action_floor=7),
        _permission(command_action_floor=None),
        _permission(command_action_floor=_MISSING),
        _permission(command_action_floor="ALLOW"),
        _permission(command_action_floor=" allow "),
        _permission(extension_control_resolution=_MISSING),
        _permission(extension_control_resolution="resolved"),
        _permission(extension_control_resolution=[]),
        _permission(extension_control_resolution=_resolution(blocked=True)),
        _permission(extension_control_resolution=_resolution(blocked=_MISSING)),
        _permission(extension_control_resolution=_resolution(blocked="false")),
        _permission(extension_control_resolution=_resolution(blocked=0)),
        _permission(extension_control_resolution=_resolution(blocked=None)),
        _permission(extension_control_resolution=_resolution(explicitly_enabled_permission_ids=[])),
        _permission(extension_control_resolution=_resolution(explicitly_enabled_permission_ids=_MISSING)),
        _permission(extension_control_resolution=_resolution(explicitly_enabled_permission_ids="command.git")),
        _permission(extension_control_resolution=_resolution(explicitly_enabled_permission_ids=["git.stash"])),
        _permission(extension_control_resolution=_resolution(explicitly_enabled_permission_ids=["command.a", "x"])),
        _permission(extension_control_resolution=_resolution(explicitly_enabled_permission_ids=["command.a", 5])),
        _permission(
            extension_control_resolution=_resolution(explicitly_enabled_permission_ids=["command.a", "command.b"])
        ),
        _permission(command_decision_plane=_MISSING),
        _permission(command_decision_plane="allow"),
        _permission(command_decision_plane=_decision(action="review")),
        _permission(command_decision_plane=_decision(action=_MISSING)),
        _permission(command_decision_plane=_decision(proof_routes=[])),
        _permission(command_decision_plane=_decision(proof_routes=["static"])),
        _permission(command_decision_plane=_decision(proof_routes=["static", "verified"])),
        _permission(command_decision_plane=_decision(proof_routes="verified")),
        _permission(command_decision_plane=_decision(proof_routes=_MISSING)),
        _permission(command_decision_plane=_decision(controlling_reasons=[])),
        _permission(command_decision_plane=_decision(controlling_reasons=_MISSING)),
        _permission(command_decision_plane=_decision(controlling_reasons="control")),
        _permission(command_decision_plane=_decision(controlling_reasons=["control"])),
        _permission(command_decision_plane=_decision(controlling_reasons=[{**reason, "source": "policy"}])),
        _permission(command_decision_plane=_decision(controlling_reasons=[{**reason, "reason_code": "other"}])),
        _permission(command_decision_plane=_decision(controlling_reasons=[{"source": "control"}])),
        _permission(command_decision_plane=_decision(controlling_reasons=[{"source": "policy"}, reason])),
    ]
    return shapes


def skip_cases(rng: random.Random) -> list[dict[str, object]]:
    cases = [
        {"artifact_type": artifact_type, "metadata": metadata}
        for artifact_type in ARTIFACT_TYPES
        for metadata in permission_metadata()
    ]
    for _ in range(300):
        metadata = copy.deepcopy(rng.choice(permission_metadata()))
        if rng.random() < 0.4:
            metadata["risk_classes"] = rng.sample(["execution", "persistence", "destructive_shell"], rng.randint(0, 2))
        if rng.random() < 0.3:
            metadata["reason_code"] = rng.choice(("shell_local_script_execution_review", "other"))
        if rng.random() < 0.3:
            metadata["command_action_floor"] = rng.choice((*ACTIONS, "bogus", 3, None))
        cases.append({"artifact_type": rng.choice(ARTIFACT_TYPES), "metadata": metadata})
    return cases


def eligibility_cases() -> list[dict[str, object]]:
    return [
        {"event_name": event_name, "artifact_type": artifact_type, "has_raw_command": has_raw_command}
        for event_name, artifact_type, has_raw_command in itertools.product(EVENTS, ARTIFACT_TYPES, (False, True))
    ]


_NULLABLE = (*ACTIONS, None)
_REUSE_SOURCES = (None, "saved_policy", "approval_center", "once", "workflow", "bogus-source", "")
_OVERRIDE_REASONS = (None, "token_match", "claim_succeeded", "")


def _composition_inputs(rng: random.Random, **fixed: object) -> dict[str, object]:
    inputs: dict[str, object] = {
        "current_config_action": rng.choice(ACTIONS),
        "current_action_override": rng.choice(_NULLABLE),
        "trusted_cli_action": rng.choice(_NULLABLE),
        "untrusted_payload_action": rng.choice(_NULLABLE),
        "package_policy_action": rng.choice(_NULLABLE),
        "data_flow_action": rng.choice(_NULLABLE),
        "scanner_action": rng.choice(_NULLABLE),
        "current_composed_action": rng.choice(ACTIONS),
        "saved_policy_action": rng.choice((*_NULLABLE, "bogus", "")),
        "approval_reuse_source": rng.choice(_REUSE_SOURCES),
        "trusted_request_override": rng.random() < 0.3,
        "trusted_request_override_reason": rng.choice(_OVERRIDE_REASONS),
        "authoritative_action": rng.choice(ACTIONS),
        "claude_native_approval_observed": rng.random() < 0.3,
        "user_override_present": rng.random() < 0.3,
    }
    inputs.update(fixed)
    return inputs


def composition_cases(rng: random.Random) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    # Every verdict under every way the approval source is decided.
    for authoritative, claude, override in itertools.product(ACTIONS, (False, True), (False, True)):
        for _ in range(20):
            cases.append(
                _composition_inputs(
                    rng,
                    authoritative_action=authoritative,
                    claude_native_approval_observed=claude,
                    user_override_present=override,
                )
            )
    # The three actions the trace records beside the verdict, in every pairing.
    for config, composed, authoritative in itertools.product(ACTIONS, repeat=3):
        cases.append(
            _composition_inputs(
                rng,
                current_config_action=config,
                current_composed_action=composed,
                authoritative_action=authoritative,
            )
        )
    cases.extend(_composition_inputs(rng) for _ in range(1500))
    return cases


def vectors() -> list[dict[str, object]]:
    rng = random.Random(20261020)
    out: list[dict[str, object]] = []
    for case in skip_cases(rng):
        out.append(
            {
                "kind": "skip_native_floor",
                "artifact": case,
                "expected": recorded_skip_native_floor(str(case["artifact_type"]), case["metadata"]),  # type: ignore[arg-type]
            }
        )
    for case in eligibility_cases():
        out.append(
            {
                "kind": "local_eligibility_required",
                "stack": case,
                "expected": recorded_local_eligibility_required(
                    str(case["event_name"]), str(case["artifact_type"]), bool(case["has_raw_command"])
                ),
            }
        )
    for inputs in composition_cases(rng):
        out.append({"kind": "policy_composition", "inputs": inputs, "expected": recorded_policy_composition(inputs)})
    return out


def main() -> int:
    recorded = vectors()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(recorded, sort_keys=True, separators=(",", ":")).encode()
    OUTPUT.write_bytes(gzip.compress(body, compresslevel=9, mtime=0))
    by_kind: dict[str, int] = {}
    for vector in recorded:
        by_kind[str(vector["kind"])] = by_kind.get(str(vector["kind"]), 0) + 1
    print(f"wrote {len(recorded)} vectors to {OUTPUT}: {by_kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

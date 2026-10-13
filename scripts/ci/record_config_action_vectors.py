#!/usr/bin/env python3
"""Record configured-policy-action vectors from the Python implementation.

Run at the commit that still carries ``_runtime_artifact_policy_action`` in
``cli/commands_support_runtime_artifact_policy.py`` (32cfe23f49), in a checkout
that has the generated command catalog:

    PYTHONPATH=src .venv/bin/python scripts/ci/record_config_action_vectors.py

Each vector records the config and artifact specification, the typed native
query a Python projection of that specification produces, and the action plus
the protection auto-stop events the Python code returned. The Rust
``hook_policy_config`` replays every vector; ``tests/test_config_action_facts``
checks the Python facts builder reproduces each recorded query.
"""

from __future__ import annotations

import gzip
import json
import random
import sys
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import GuardArtifact

OUTPUT = Path("rust/crates/guard-runtime/tests/fixtures/config_action_vectors.json.gz")
HARNESS = "codex"
RISKS = (
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "execution",
    "persistence",
    "malicious_skill",
    "prompt_injection",
    "guard_bypass",
    "encoded_exfiltration",
    "package_script",
    "not_a_risk_class",
)
ACTIONS = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
PERMISSION = {
    "command_action_floor": "allow",
    "extension_control_resolution": {"blocked": False, "explicitly_enabled_permission_ids": ["command.git.stash"]},
    "command_decision_plane": {
        "action": "allow",
        "proof_routes": ["verified"],
        "controlling_reasons": [{"source": "control", "reason_code": "control.explicitly-enabled-permission"}],
    },
}


def build_config(spec: dict[str, object], guard_home: Path) -> GuardConfig:
    fields = dict(spec)
    fields["managed_locked_settings"] = tuple(fields.get("managed_locked_settings", ()))  # type: ignore[call-overload]
    return GuardConfig(guard_home=guard_home, workspace=None, **fields)  # type: ignore[arg-type]


def build_artifact(spec: dict[str, object]) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=str(spec["artifact_id"]),
        name="case",
        harness=HARNESS,
        artifact_type=str(spec["artifact_type"]),
        source_scope="project",
        config_path="/workspace/.guard/config.toml",
        publisher=spec.get("publisher"),  # type: ignore[arg-type]
        metadata=dict(spec["metadata"]),  # type: ignore[call-overload]
    )


def _pick_map(rng: random.Random, keys: tuple[str, ...], width: int) -> dict[str, str]:
    return {key: rng.choice(ACTIONS) for key in rng.sample(keys, rng.randint(0, width))}


def random_case(rng: random.Random) -> dict[str, object]:
    posture = rng.choice(("protected", "protected", "extra_careful", "watch"))
    config: dict[str, object] = {
        "default_action": rng.choice((*ACTIONS[:3], "???")),
        "security_level": rng.choice(("balanced", "balanced", "paranoid", "relaxed", "unknown-level")),
        "protection_posture": posture,
        "protection_posture_explicit": rng.random() < 0.6,
        "managed_locked_settings": ["security_level"] if rng.random() < 0.2 else [],
        "risk_actions": _pick_map(rng, RISKS[:-1], 3) if rng.random() < 0.5 else None,
        "harness_risk_actions": (
            {HARNESS: _pick_map(rng, RISKS[:-1], 3), "claude-code": _pick_map(rng, RISKS[:-1], 2)}
            if rng.random() < 0.4
            else None
        ),
        "harness_postures": {HARNESS: rng.choice(("extra_careful", "protected", "watch"))}
        if rng.random() < 0.3
        else None,
        "artifact_actions": {"case:artifact": rng.choice((*ACTIONS, "???", "", 7))} if rng.random() < 0.18 else None,
        "publisher_actions": {"acme": rng.choice(ACTIONS)} if rng.random() < 0.08 else None,
        "harness_actions": {HARNESS: rng.choice(ACTIONS)} if rng.random() < 0.08 else None,
    }
    if rng.random() < 0.08:
        config["harness_risk_actions"] = {HARNESS: {"data_flow_exfiltration": rng.choice(("???", ""))}}
    metadata: dict[str, object] = {}
    kind = rng.choice(("tool_action_request",) * 6 + ("file_read_request", "package_request", "prompt_request"))
    if kind == "tool_action_request":
        metadata["risk_classes"] = rng.sample(RISKS, rng.randint(0, 3))
    if kind == "prompt_request":
        metadata["prompt_request_classes"] = rng.sample(
            ["secret_read", "exfil_intent", "destructive_intent", "guard_bypass_intent", "prompt_injection_intent"],
            rng.randint(0, 3),
        )
    if rng.random() < 0.3:
        metadata["command_action_floor"] = rng.choice((*ACTIONS, "bogus"))
    if rng.random() < 0.25:
        metadata.update(PERMISSION)
    if rng.random() < 0.35:
        metadata["guard_default_action"] = rng.choice((*ACTIONS, "bogus", 7))
    if rng.random() < 0.3:
        metadata["reason_code"] = rng.choice(
            ("shell_local_script_execution_review", "pytest_restricted_profile_required")
        )
    if rng.random() < 0.2:
        metadata["action_class"] = rng.choice(
            ("pytest repository-code execution", "launchctl load agent", "npm install")
        )
    if rng.random() < 0.2:
        metadata["restricted_profile_version"] = rng.choice(("v1", 3))
    if rng.random() < 0.3:
        metadata["risk_confidence"] = rng.choice(("strong", "weak", " Strong ", 5))
    if rng.random() < 0.1:
        metadata["risk_signals"] = [{"confidence": rng.choice(("strong", "weak"))}]
    if rng.random() < 0.1:
        metadata["known_bad_skill"] = True
    if rng.random() < 0.1:
        metadata["persistence_writes_launch_agent"] = True
    publisher = "acme" if rng.random() < 0.3 else None
    artifact_id = "case:artifact" if rng.random() < 0.3 else f"case:{rng.randint(0, 99)}"
    return {
        "config": {key: value for key, value in config.items() if value is not None},
        "artifact": {"artifact_id": artifact_id, "artifact_type": kind, "publisher": publisher, "metadata": metadata},
    }


def _typed_override(value: object) -> object:
    return value if value is None or isinstance(value, str) else ""


def _old_data_flow_action(config: GuardConfig, strong: bool) -> object:
    """The configured data-flow action the previous Python hook evaluation sent."""
    from codex_plugin_scanner.guard.config import resolve_risk_action
    from codex_plugin_scanner.guard.protection_posture import apply_posture_confidence

    action = resolve_risk_action(config, "data_flow_exfiltration", harness=HARNESS)
    if action is None:
        return None
    return apply_posture_confidence(
        posture=config.protection_posture,
        explicit=config.protection_posture_explicit,
        risk_class="data_flow_exfiltration",
        action=action,
        confidence="strong" if strong else None,
    )


def record() -> list[dict[str, object]]:
    import codex_plugin_scanner.guard.cli.commands  # noqa: F401  (wires the shared command namespace)
    from codex_plugin_scanner.guard import protection_events
    from codex_plugin_scanner.guard.cli import commands_support_runtime_artifact_policy as policy
    from codex_plugin_scanner.guard.cli import commands_support_runtime_policy as runtime_policy
    from codex_plugin_scanner.guard.cli.commands_support_prompts import _prompt_requires_hard_block
    from codex_plugin_scanner.guard.harness_posture import harness_posture_override
    from codex_plugin_scanner.guard.protection_posture import is_high_confidence

    events: list[dict[str, object]] = []
    protection_events.record_protection_event = lambda _home, _name, payload: events.append(dict(payload))
    guard_home = Path(tempfile.mkdtemp())
    rng = random.Random(20260512)
    cases = [random_case(rng) for _ in range(900)]
    vectors = []
    for index, case in enumerate(cases):
        config = build_config(case["config"], guard_home)  # type: ignore[arg-type]
        artifact = build_artifact(case["artifact"])  # type: ignore[arg-type]
        events.clear()
        action = policy._runtime_artifact_policy_action(config, artifact, HARNESS)
        metadata = artifact.metadata
        default = metadata.get("guard_default_action")
        confidence = runtime_policy._artifact_risk_confidence(artifact)
        query = {
            "policy_config": {
                "default_action": config.default_action,
                "risk_actions": dict(config.risk_actions or {}),
                "harness_risk_actions": {k: dict(v) for k, v in (config.harness_risk_actions or {}).items()},
                "security_level": config.security_level,
                "protection_posture": config.protection_posture,
                "protection_posture_explicit": config.protection_posture_explicit,
                "managed_locks_level": "security_level" in config.managed_locked_settings,
                "harness": HARNESS,
                "harness_posture_override": harness_posture_override(config, HARNESS),
            },
            "artifact": {
                "hard_block": _prompt_requires_hard_block(artifact),
                "configured_override": _typed_override(
                    config.resolve_action_override(HARNESS, artifact.artifact_id, artifact.publisher)
                ),
                "command_action_floor": policy._runtime_artifact_command_action_floor(artifact),
                "explicit_permission_allow": policy._runtime_artifact_has_explicit_permission_allow(artifact),
                "risk_classes": runtime_policy._runtime_artifact_risk_classes(artifact),
                "pytest_restricted_sandbox": (
                    metadata.get("action_class") == "pytest repository-code execution"
                    and metadata.get("reason_code") == "pytest_restricted_profile_required"
                    and isinstance(metadata.get("restricted_profile_version"), str)
                ),
                "shell_local_script_review": metadata.get("reason_code") == "shell_local_script_execution_review",
                "guard_default_action": default if default is None or isinstance(default, str) else "",
                "confidence_text": str(confidence or ""),
                "confidence_strong": is_high_confidence(confidence),
                "writes_launch_agent": runtime_policy._artifact_writes_launch_agent(artifact),
                "skill_is_known_bad": runtime_policy._artifact_skill_is_known_bad(artifact),
            },
        }
        data_flow = {
            "weak": _old_data_flow_action(config, False),
            "strong": _old_data_flow_action(config, True),
        }
        vectors.append(
            {
                "name": f"case_{index:04d}",
                "data_flow": data_flow,
                "spec": case,
                "query": query,
                "expected": {"action": action, "auto_stop_events": list(events)},
            }
        )
    return vectors


def main() -> int:
    vectors = record()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(vectors, sort_keys=True, separators=(",", ":"))
    with gzip.GzipFile(OUTPUT, "wb", mtime=0) as handle:
        handle.write(text.encode("utf-8"))
    actions = sorted({str(item["expected"]["action"]) for item in vectors})  # type: ignore[index]
    stops = sum(1 for item in vectors if item["expected"]["auto_stop_events"])  # type: ignore[index]
    print(f"recorded {len(vectors)} vectors; actions={actions}; with auto_stop={stops}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

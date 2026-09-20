"""Generate native sensitive-read vectors from the real Python runtime path."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Literal, cast

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_hook_runtime_eval import _evaluate_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_runtime_finish import _finalize_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_hook_runtime_review import _review_runtime_artifact_hook
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _hook_action_envelope, _normalize_hook_payload
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3
from codex_plugin_scanner.guard.protection_posture import dual_write_from_posture
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_sensitive_read_sources import FIXTURE as SOURCE_FIXTURE
from tests.test_native_sensitive_read_sources import produce_sensitive_read

ACTIONS: tuple[GuardAction, ...] = ("allow", "warn", "review", "require-reapproval", "sandbox-required", "block")
Mode = Literal["enforce", "observe"]


@dataclass(frozen=True)
class Configuration:
    name: str
    default_action: GuardAction = "allow"
    harness_action: GuardAction | None = None
    artifact_action: GuardAction | None = None
    risk_action: GuardAction | None = None
    harness_risk_action: GuardAction | None = None
    security_level: str = "balanced"
    protection_posture: str | None = None


def configurations() -> list[Configuration]:
    cases: list[Configuration] = []
    for action in ACTIONS:
        cases.extend(
            [
                Configuration(f"default-{action}", default_action=action),
                Configuration(f"harness-{action}", harness_action=action),
                Configuration(f"artifact-{action}", artifact_action=action),
                Configuration(f"risk-{action}", risk_action=action),
                Configuration(f"harness-risk-{action}", harness_risk_action=action),
            ]
        )
    cases.extend(
        [
            Configuration(
                "artifact-allow-harness-block-risk-allow",
                harness_action="block",
                artifact_action="allow",
                risk_action="allow",
            ),
            Configuration(
                "artifact-block-harness-allow-risk-allow",
                harness_action="allow",
                artifact_action="block",
                risk_action="allow",
            ),
            Configuration(
                "harness-allow-default-block-risk-allow",
                default_action="block",
                harness_action="allow",
                risk_action="allow",
            ),
            Configuration(
                "artifact-allow-default-block-risk-allow",
                default_action="block",
                artifact_action="allow",
                risk_action="allow",
            ),
            Configuration("risk-block-artifact-allow", artifact_action="allow", risk_action="block"),
            Configuration("harness-risk-allow-global-risk-block", risk_action="block", harness_risk_action="allow"),
            Configuration("harness-risk-block-global-risk-allow", risk_action="allow", harness_risk_action="block"),
            Configuration("harness-risk-allow-artifact-block", artifact_action="block", harness_risk_action="allow"),
            Configuration("level-relaxed", security_level="relaxed"),
            Configuration("level-strict", security_level="strict"),
            Configuration("level-relaxed-explicit-warn", security_level="relaxed", risk_action="warn"),
        ]
    )
    for level in ("gentle", "paranoid", "custom"):
        cases.append(Configuration(f"level-{level}", security_level=level))
    for posture in ("protected", "extra_careful", "watch"):
        _, level = dual_write_from_posture(posture, current_security_level="balanced")
        assert level is not None
        for risk in (None, "allow", "block"):
            cases.append(
                Configuration(
                    f"posture-{posture}-risk-{risk or 'default'}",
                    protection_posture=posture,
                    security_level=level,
                    risk_action=risk,
                )
            )
    return cases


def config_for(
    case: Configuration, *, harness: str, artifact_id: str, store: GuardStore, workspace: Path, mode: Mode
) -> GuardConfig:
    config = GuardConfig(
        guard_home=store.guard_home,
        workspace=workspace,
        mode=mode,
        security_level=case.security_level,
        default_action=case.default_action,
        unknown_publisher_action="review",
        harness_actions={harness: case.harness_action} if case.harness_action is not None else {},
        artifact_actions={artifact_id: case.artifact_action} if case.artifact_action is not None else {},
        risk_actions={"local_secret_read": case.risk_action} if case.risk_action is not None else {},
        harness_risk_actions={harness: {"local_secret_read": case.harness_risk_action}}
        if case.harness_risk_action is not None
        else {},
    )
    if case.protection_posture is not None:
        # The actual loader binds an explicit Watch posture to Observe mode.
        (store.guard_home / "config.toml").write_text(
            f'mode = "{mode}"\nsecurity_level = "{case.security_level}"\n'
            f'protection_posture = "{case.protection_posture}"\n'
        )
        loaded = load_guard_config(
            store.guard_home,
            workspace=workspace,
            managed_policy_state=ManagedPolicyState("absent", "synthetic-fixture"),
        )
        assert loaded.protection_posture == case.protection_posture
        assert loaded.protection_posture_explicit is True
        config = replace(
            config,
            mode=loaded.mode,
            security_level=loaded.security_level,
            protection_posture=loaded.protection_posture,
            protection_posture_explicit=loaded.protection_posture_explicit,
        )
    return config


def finite_emitted_decision(value: object) -> dict[str, object]:
    """Retain decision fields, never dynamic receipts, context, paths, or reasons."""
    assert isinstance(value, dict)
    result: dict[str, object] = {}
    for key in ("decision", "continue", "permissionDecision", "policy_action"):
        item = value.get(key)
        if item is not None:
            assert isinstance(item, (str, bool))
            result[key] = item
    specific = value.get("hookSpecificOutput")
    if isinstance(specific, dict):
        result["hookSpecificOutput"] = {
            key: specific[key] for key in ("hookEventName", "permissionDecision") if key in specific
        }
    return result


def evaluate_case(source: dict[str, object], case: Configuration, mode: Mode, guard_home: Path) -> dict[str, object]:
    harness = source["harness"]
    assert isinstance(harness, str)
    context_source = source["source"]
    raw = source["payload"]
    assert isinstance(context_source, dict) and isinstance(raw, dict)
    home, workspace = Path(str(context_source["home_dir"])), Path(str(context_source["cwd"]))
    artifact = produce_sensitive_read(source)
    payload = _normalize_hook_payload(raw, harness=harness)
    action = _hook_action_envelope(harness=harness, payload=payload, home_dir=home, workspace=workspace)
    assert action is not None and action.action_type == "file_read"
    store = GuardStore(guard_home)
    config = config_for(
        case, harness=harness, artifact_id=artifact.artifact_id, store=store, workspace=workspace, mode=mode
    )
    assert config.mode in {"enforce", "observe"}
    mode = cast(Mode, config.mode)
    context = HarnessContext(home_dir=home, workspace_dir=workspace, guard_home=store.guard_home)
    args = argparse.Namespace(harness=harness, policy_action=None, json=True)
    state = _evaluate_runtime_artifact_hook(
        args,
        action_envelope=action,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=store.guard_home,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace,
        store=store,
    )
    assert not isinstance(state, int)
    expected: dict[str, object] = {
        "evaluatedPolicyAction": state.policy_action,
        "evaluatedDecision": state.decision_v2_payload["action"],
    }
    if mode == "observe":
        # This actual branch queues a nonblocking observation and projects its
        # executable action. It does not enter Cloud/interactive approval.
        stream, standard = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(standard):
            result = _review_runtime_artifact_hook(
                state,
                args,
                config=config,
                context=context,
                guard_home=store.guard_home,
                managed_install=None,
                output_stream=stream,
                payload=payload,
                store=store,
                workspace=workspace,
            )
            assert result is None
            exit_code = _finalize_runtime_artifact_hook(
                state,
                args,
                config=config,
                output_stream=stream,
                payload=payload,
                store=store,
            )
        output = stream.getvalue() or standard.getvalue()
        parsed = json.loads(output) if output.strip() else {}
        expected.update(
            finalPolicyAction=state.policy_action,
            finalDecision=state.decision_v2_payload["action"],
            observedPolicyAction=state.response_payload.get("observed_policy_action"),
            rendererExitCode=exit_code,
            renderedDecision=finite_emitted_decision(parsed),
        )
    return {
        "name": f"{harness}-{mode}-{case.name}",
        "harness": harness,
        "source": context_source,
        "payload": raw,
        "artifactId": artifact.artifact_id,
        "mode": mode,
        "configInputs": asdict(case),
        "effectivePolicy": effective_native_policy_v3(config),
        "expected": expected,
    }


def generate_vectors(root: Path) -> dict[str, object]:
    sources = json.loads(SOURCE_FIXTURE.read_text())["cases"]
    selected: dict[str, dict[str, object]] = {}
    for source in sources:
        selected.setdefault(source["harness"], source)
    cases: list[dict[str, object]] = []
    for harness, source in sorted(selected.items()):
        configs = (
            configurations()
            if harness == "codex"
            else [Configuration(f"risk-{action}", risk_action=action) for action in ACTIONS]
        )
        for case in configs:
            modes: tuple[Mode, ...] = ("enforce",) if case.protection_posture else ("enforce", "observe")
            for mode in modes:
                cases.append(evaluate_case(source, case, mode, root / str(len(cases))))
    return {
        "schema": "native-sensitive-read-policy-fixtures.v1",
        "source": "actual normalized producer, runtime evaluator, and Observe review/finalizer",
        "contentBinding": "request path and tool identity only; no secret file bytes",
        "enforceScope": "evaluated action before interactive review; no approval consumption",
        "observeScope": "actual nonblocking Observe review and renderer; no installed or native acceptance",
        "cases": cases,
    }

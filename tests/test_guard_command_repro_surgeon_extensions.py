"""Opt-in Repro Surgeon execution review over parsed commands, without running them."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import matcher_index_hints
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from codex_plugin_scanner.guard.runtime.package_intent import parse_package_intent
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request
from tests.command_extension_contracts import (
    assert_review_required_cases,
    assert_reviewed_command_cases,
    assert_safe_command_cases,
)

_ID = "command.repro-surgeon"
_RULE = "command.repro-surgeon.execute"
_ACTION = "Repro Surgeon project-command execution command"


def _layer(state: ControlState) -> ExtensionControlLayer:
    return ExtensionControlLayer(
        schema_version=CONTROL_SCHEMA_VERSION,
        kind=ControlLayerKind.LOCAL_ADMIN,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        global_lockdown=False,
        controls=(ExtensionControl(target=ControlTarget(ControlTargetKind.EXTENSION, _ID), state=state),),
    )


@pytest.fixture
def enabled() -> Iterator[None]:
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(
        ExtensionControlAuthorityView(
            AuthorityHealth.PROTECTED,
            1,
            BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
            (_layer(ControlState.ENABLED),),
        )
    )
    with use_extension_control_snapshot(snapshot):
        yield


@pytest.mark.parametrize(
    "command",
    (
        "repro-surgeon reduce ./app --out ./repro",
        "repro-surgeon --json resume ./run --max-evaluations 100",
        "repro-surgeon verify ./repro --json",
        "repro-surgeon demo --out ./demo",
        "repro-surgeon --config='./config with spaces.json' --out './output dir' reduce './app dir'",
        "repro-surgeon --match reduce --forbid verify --exit 1 --max-seconds=30 reduce ./app",
        "repro-surgeon reduce ./app --match=--help",
        "repro-surgeon verify ./repro --config=--version",
        "repro-surgeon reduce ./app --",
        "repro-surgeon reduce ./app -- --help",
        "repro-surgeon demo -- --version",
        "/opt/tools/repro-surgeon verify ./repro",
        "'/opt/tools with spaces/repro-surgeon' verify './repro dir'",
        "env CI=1 repro-surgeon demo --json",
        "zsh -lc 'repro-surgeon reduce ./app'",
        "repro-surgeon reduce --help; repro-surgeon verify ./repro",
        "repro-surgeon demo; repro-surgeon demo --version",
        "repro-surgeon verify ./repro | cat",
        'printf "%s" "$(repro-surgeon demo)"',
    ),
)
def test_enabled_execution_reaches_inspection_and_runtime(command: str, enabled: None, tmp_path: Path) -> None:
    assert_reviewed_command_cases(((command, _ACTION, _RULE),), tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "repro-surgeon doctor ./app --json",
        "repro-surgeon init ./app -- node fail.js",
        "repro-surgeon report ./run",
        "repro-surgeon --config reduce doctor ./app",
        "repro-surgeon --out=verify report ./run",
        "repro-surgeon doctor ./reduce",
        "repro-surgeon report ./verify",
        "echo 'repro-surgeon reduce ./app'",
        "printf '%s' 'repro-surgeon demo'",
        "repro-surgeon --help",
        "repro-surgeon reduce --help",
        'repro-surgeon reduce "$PROJECT" --help',
        "repro-surgeon --help reduce ./app",
        "repro-surgeon resume -h",
        "repro-surgeon verify --version",
        "repro-surgeon demo -v",
        "repro-surgeon --json -hv demo",
        "repro-surgeon reduce --help -- node fail.js",
        "repro-surgeon -- reduce",
        "repro-surgeon init ./app -- repro-surgeon reduce ./app",
        "node .repro/verify.mjs",
        "node dist/cli.js reduce ./app",
    ),
)
def test_non_execution_and_unsupported_launchers_have_no_own_evidence(
    command: str, enabled: None, tmp_path: Path
) -> None:
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert all(
        item.extension.extension_id != _ID or not item.effective_evidence for item in evaluation.extension_observations
    )
    assert evaluation.controlling_rule_id != _RULE
    if not command.startswith("node "):
        assert_safe_command_cases((command,), tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "repro-surgeon reduce --unknown",
        "repro-surgeon --unknown reduce ./app",
        "repro-surgeon reduce --config",
        "repro-surgeon reduce --help --unknown",
        "repro-surgeon reduce --help --config",
        "repro-surgeon reduce --help=true",
        "repro-surgeon reduce --version=1",
        "repro-surgeon reduce --help=false",
        "repro-surgeon reduce --HELP",
        "repro-surgeon reduce --help --JSON",
        "repro-surgeon reduce --config --help",
        "repro-surgeon reduce --out --version",
    ),
)
def test_malformed_options_cannot_claim_safe_help(command: str, enabled: None, tmp_path: Path) -> None:
    assert_reviewed_command_cases(((command, _ACTION, _RULE),), tmp_path)


@pytest.mark.parametrize(
    "command",
    (
        "$TOOL reduce ./app",
        "$TOOL reduce --help",
        '"${TOOL}" demo -v',
        "repro-${SUFFIX} verify ./repro --help",
        "repro-surgeon $ACTION ./app --help",
        'repro-surgeon "${ACTION}" ./app --version',
    ),
)
def test_variable_built_commands_remain_explicitly_unsupported(command: str, enabled: None, tmp_path: Path) -> None:
    # no_match means this extension did not recognize the command, not that
    # resolving or executing these shell variables would be safe.
    inspection = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    runtime = extract_sensitive_tool_action_request("Shell", {"command": command}, cwd=tmp_path, home_dir=tmp_path)
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert inspection["status"] == "no_match"
    assert runtime is None
    assert all(item.extension.extension_id != _ID for item in evaluation.extension_observations)


@pytest.mark.parametrize(
    "command",
    (
        'repro-surgeon reduce "$PROJECT"',
        'repro-surgeon resume "${RUN_ROOT}" --json',
        'repro-surgeon verify "$EXPORT" --config "${CONFIG}"',
        'repro-surgeon demo --out "$OUTPUT"',
        "repro-surgeon reduce --match ${HELP:---help}",
        'repro-surgeon reduce --config "$HELP"',
    ),
)
def test_literal_execution_with_dynamic_values_is_reviewed(command: str, enabled: None, tmp_path: Path) -> None:
    assert_reviewed_command_cases(((command, _ACTION, _RULE),), tmp_path)
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    own = [item for item in evaluation.extension_observations if item.extension.extension_id == _ID]
    assert own
    assert all(item.safe_variants == () for item in own)


@pytest.mark.parametrize("subcommand", ("reduce", "resume", "verify", "demo"))
def test_external_extension_is_inert_by_default_and_when_disabled(subcommand: str, tmp_path: Path) -> None:
    command = f"repro-surgeon {subcommand} ./fixture"
    assert_safe_command_cases((command,), tmp_path)
    for layers in ((), (_layer(ControlState.DISABLED),)):
        evaluation = evaluate_command(
            command,
            cwd=tmp_path,
            home_dir=tmp_path,
            extension_control_layers=layers,
            compatibility_action_class=_ACTION,
        )
        assert all(item.extension.extension_id != _ID for item in evaluation.extension_observations)
        assert evaluation.controlling_rule_id != _RULE


@pytest.mark.parametrize(
    "command",
    (
        "repro-surgeon reduce --help; git reset --hard HEAD",
        'repro-surgeon reduce --help --out "$(git reset --hard HEAD)"',
    ),
)
def test_help_does_not_remove_other_command_evidence(command: str, enabled: None, tmp_path: Path) -> None:
    baseline = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path, extension_control_layers=())
    active = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert baseline.controlling_rule_id is not None
    assert active.controlling_rule_id == baseline.controlling_rule_id
    baseline_rules = {item.match.rule.rule_id for item in baseline.matches}
    assert baseline_rules <= {item.match.rule.rule_id for item in active.matches}
    assert all(
        item.extension.extension_id != _ID or not item.effective_evidence for item in active.extension_observations
    )


@pytest.mark.parametrize(
    "command",
    (
        "npx --yes repro-surgeon@0.2.1 reduce --help",
        "npm exec --yes --package=repro-surgeon@0.2.1 -- repro-surgeon demo --help",
    ),
)
def test_package_launcher_help_retains_package_firewall_intent(command: str, enabled: None, tmp_path: Path) -> None:
    intent = parse_package_intent(command, workspace=tmp_path)
    assert intent is not None
    assert intent.intent_kind == "execute"
    assert intent.targets[0].package_name == "repro-surgeon"
    assert intent.targets[0].requested_specifier == "0.2.1"
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert all(item.extension.extension_id != _ID for item in evaluation.extension_observations)


@pytest.mark.parametrize("command", ("repro-surgeon reduce ./app > --help", "repro-surgeon demo 2>--version"))
def test_redirection_destinations_cannot_be_help_flags(command: str, enabled: None, tmp_path: Path) -> None:
    assert_review_required_cases((command,), tmp_path)
    evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
    own = [item for item in evaluation.extension_observations if item.extension.extension_id == _ID]
    assert len(own) == 1
    assert own[0].effective_evidence
    assert own[0].safe_variants == ()


def test_catalog_registers_optional_external_ownership_and_action_risks() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_ID)
    assert extension is not None
    payload = extension.to_dict()
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["enabled"] is False
    assert payload["publisher"]["id"] == "community.pavangupta352"
    assert risk_classes_for_command_action(_ACTION) == ("execution", "network_egress")
    assert tuple(rule.rule_id for rule in extension.rules) == (_RULE,)


def test_execution_matcher_stays_indexed_without_becoming_a_global_candidate() -> None:
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(_ID)
    assert extension is not None
    matcher = extension.rules[0].matcher
    assert matcher is not None
    hints = matcher_index_hints(matcher)
    assert hints.complete
    assert hints.executables == frozenset({"repro-surgeon", "repro-surgeon.cmd", "repro-surgeon.exe"})
    assert hints.keywords == frozenset({"reduce", "resume", "verify", "demo"})
    assert _RULE in BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(
        parse_shell_command("'/opt/tools with spaces/repro-surgeon' --json demo")
    )
    assert _RULE not in BUILT_IN_COMMAND_EXTENSION_REGISTRY.candidate_rule_ids(parse_shell_command("echo unrelated"))


def test_signed_cloud_cannot_activate_external_execution_review(tmp_path: Path) -> None:
    cloud_enable = replace(_layer(ControlState.ENABLED), kind=ControlLayerKind.SIGNED_CLOUD)
    evaluation = evaluate_command(
        "repro-surgeon demo",
        cwd=tmp_path,
        home_dir=tmp_path,
        extension_control_layers=(cloud_enable,),
        compatibility_action_class=_ACTION,
    )
    assert all(item.extension.extension_id != _ID for item in evaluation.extension_observations)
    assert evaluation.controlling_rule_id != _RULE


def test_rule_evidence_does_not_copy_config_paths_or_values() -> None:
    command = parse_shell_command(
        "repro-surgeon --config /invented/private/project.json reduce ./app --match=private-diagnostic"
    )
    observations = [
        item for item in BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(command) if item.extension.extension_id == _ID
    ]
    assert len(observations) == 1
    evidence = observations[0].effective_evidence
    assert evidence
    serialized = json.dumps([item.detail for item in evidence])
    assert "private" not in serialized
    assert "project.json" not in serialized

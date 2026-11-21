"""AgentBridge opt-in protection exercised through the actual native evaluator."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.native_command_test_support import real_native_command_evaluation

EXTENSION = "command.agentbridge"
SCAFFOLD = "command.agentbridge.scaffold-plugin-force"
RUN = "command.agentbridge.run-tool-registry"


def evaluate(command: str, tmp_path: Path, *, enabled: bool = True):
    return real_native_command_evaluation(
        command,
        cwd=tmp_path,
        home_dir=tmp_path,
        controls=(("extension", EXTENSION, "enabled"),) if enabled else (),
    ).evaluation


def observations(evaluation):
    return tuple(item for item in evaluation.extension_observations if item.extension.extension_id == EXTENSION)


@pytest.mark.parametrize(
    ("command", "rule_id", "action", "risk"),
    [
        (
            "agentbridge scaffold-plugin --force",
            SCAFFOLD,
            "AgentBridge forced plugin scaffold command",
            "destructive_shell",
        ),
        (
            "agentbridge scaffold-plugin --force=true",
            SCAFFOLD,
            "AgentBridge forced plugin scaffold command",
            "destructive_shell",
        ),
        (
            "agentbridge.exe scaffold-plugin --force=1",
            SCAFFOLD,
            "AgentBridge forced plugin scaffold command",
            "destructive_shell",
        ),
        (
            "agentbridge.cmd scaffold-plugin --force",
            SCAFFOLD,
            "AgentBridge forced plugin scaffold command",
            "destructive_shell",
        ),
        (
            "./bin/agentbridge scaffold-plugin --force",
            SCAFFOLD,
            "AgentBridge forced plugin scaffold command",
            "destructive_shell",
        ),
        ("agentbridge run --tool-registry app.tools", RUN, "AgentBridge run with tool registry command", "execution"),
        ("agentbridge run --tool-registry=app.tools", RUN, "AgentBridge run with tool registry command", "execution"),
        ("agentbridge run --tool-registry=false", RUN, "AgentBridge run with tool registry command", "execution"),
        (
            "sudo agentbridge scaffold-plugin --force",
            SCAFFOLD,
            "AgentBridge forced plugin scaffold command",
            "destructive_shell",
        ),
    ],
)
def test_risky_operations_publish_native_reviews(command, rule_id, action, risk, tmp_path):
    evaluation = evaluate(command, tmp_path)
    matching = [item for item in observations(evaluation) if item.rule.rule_id == rule_id]
    assert matching, command
    assert matching[0].rule.action_classes == (action,)
    assert matching[0].rule.risk_classes == (risk,)
    assert evaluation.minimum_action in {"review", "block"}, command


@pytest.mark.parametrize(
    "command",
    [
        "agentbridge scaffold-plugin $FLAGS",
        "agentbridge run ${REGISTRY_ARGS}",
        "env MODE=dev agentbridge run --tool-registry app.tools",
        "exec agentbridge scaffold-plugin --force",
        "xargs -n 1 agentbridge.exe run --tool-registry app.tools",
        "env MODE=dev agentbridge run $FLAGS",
        "exec agentbridge.cmd scaffold-plugin $FLAGS",
        "xargs -n 1 agentbridge.exe run $FLAGS",
        "agentbridge.cmd run %REGISTRY_ARGS%",
        "agentbridge scaffold-plugin --force=$FORCE",
        "agentbridge run --tool-registry=$REGISTRY",
    ],
)
def test_wrappers_and_unresolved_arguments_cannot_hide_risk(command, tmp_path):
    evaluation = evaluate(command, tmp_path)
    assert evaluation.minimum_action in {"review", "block"}, command


@pytest.mark.parametrize(
    "command",
    [
        "agentbridge scaffold-plugin",
        "agentbridge scaffold-plugin --force=false",
        "agentbridge scaffold-plugin --force=0",
        "agentbridge run spec.json",
        "agentbridge validate spec.json",
        "agentbridge compare before.json after.json",
        "agentbridge list-backends",
        "agentbridge inspect-backend local",
        "agentbridge validate $SPEC",
        "printf 'agentbridge scaffold-plugin --force'",
        "agentbridge scaffold-plugin -- --force",
        "agentbridge run -- --tool-registry=app.tools",
    ],
)
def test_safe_commands_have_no_agentbridge_risk(command, tmp_path):
    evaluation = evaluate(command, tmp_path)
    assert not observations(evaluation), command
    assert not any(item.extension.extension_id == EXTENSION for item in evaluation.matches), command


@pytest.mark.parametrize(
    "command",
    [
        "agentbridge scaffold-plugin --force --help",
        "agentbridge scaffold-plugin --force=true -h",
        "agentbridge run --tool-registry app.tools --help",
        "agentbridge run --tool-registry=app.tools -h",
        "exec agentbridge scaffold-plugin --force --help",
        "xargs -n 1 agentbridge.exe run --tool-registry app.tools --help",
    ],
)
def test_help_takes_precedence_over_risky_options(command, tmp_path):
    evaluation = evaluate(command, tmp_path)
    assert not any(item.extension.extension_id == EXTENSION for item in evaluation.matches), command
    assert evaluation.controlling_rule_id not in {SCAFFOLD, RUN}, command


@pytest.mark.parametrize(
    "command",
    [
        "agentbridge run --tool-registry --help",
        "agentbridge run --tool-registry=app.tools -- --help",
        "agentbridge scaffold-plugin --force --unknown --help",
    ],
)
def test_consumed_or_ambiguous_help_does_not_suppress_review(command, tmp_path):
    evaluation = evaluate(command, tmp_path)
    assert evaluation.minimum_action in {"review", "block"}, command
    assert any(item.extension.extension_id == EXTENSION for item in evaluation.matches), command


@pytest.mark.parametrize(
    "command", ["agentbridge scaffold-plugin --force", "agentbridge run --tool-registry app.tools"]
)
def test_external_protection_requires_explicit_activation(command, tmp_path):
    inert = evaluate(command, tmp_path, enabled=False)
    assert not observations(inert)
    assert not any(item.extension.extension_id == EXTENSION for item in inert.matches)
    enabled = evaluate(command, tmp_path)
    assert any(item.extension.extension_id == EXTENSION for item in enabled.matches)

from __future__ import annotations

import importlib
import json
import sys
import types
from dataclasses import dataclass

import pytest


@dataclass(frozen=True)
class _Proceed:
    reason: str | None = None


@dataclass(frozen=True)
class _Deny:
    reason: str = ""


class _InterventionHandler:
    pass


class _BeforeToolCallEvent:
    def __init__(self, tool_use: dict) -> None:
        self.tool_use = tool_use


def _load_module(monkeypatch: pytest.MonkeyPatch):
    hooks = types.ModuleType("strands.hooks")
    hooks.BeforeToolCallEvent = _BeforeToolCallEvent
    interventions = types.ModuleType("strands.interventions")
    interventions.Deny = _Deny
    interventions.InterventionHandler = _InterventionHandler
    interventions.OnError = str
    interventions.Proceed = _Proceed
    strands = types.ModuleType("strands")
    strands.hooks = hooks
    strands.interventions = interventions
    monkeypatch.setitem(sys.modules, "strands", strands)
    monkeypatch.setitem(sys.modules, "strands.hooks", hooks)
    monkeypatch.setitem(sys.modules, "strands.interventions", interventions)
    sys.modules.pop("codex_plugin_scanner.guard.strands_intervention", None)
    return importlib.import_module("codex_plugin_scanner.guard.strands_intervention")


def _event(command: str = "echo ok") -> _BeforeToolCallEvent:
    return _BeforeToolCallEvent({"name": "shell", "input": {"command": command}})


def test_strands_intervention_allows_only_explicit_benign(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module(monkeypatch)
    result = {
        "classification": {"explicitly_benign": True},
        "minimum_action": "allow",
        "policy_evaluation": "not_run",
    }

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr=""),
    )

    intervention = module.HolGuardIntervention({"shell": "command"})
    decision = intervention.before_tool_call(_event())

    assert isinstance(decision, _Proceed)
    assert intervention.on_error == "deny"


@pytest.mark.parametrize(
    "result",
    [
        {"classification": {"explicitly_benign": False}, "minimum_action": "review"},
        {"classification": {}, "minimum_action": "allow"},
        {"classification": {"explicitly_benign": True}, "minimum_action": "review"},
    ],
)
def test_strands_intervention_denies_non_benign_results(monkeypatch: pytest.MonkeyPatch, result: dict) -> None:
    module = _load_module(monkeypatch)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr=""),
    )

    decision = module.HolGuardIntervention({"shell": "command"}).before_tool_call(_event("rm -rf ./tmp"))

    assert isinstance(decision, _Deny)


def test_strands_intervention_denies_cli_failure_and_invalid_output(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module(monkeypatch)
    intervention = module.HolGuardIntervention({"shell": "command"})

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=2, stdout="", stderr="failure"),
    )
    assert isinstance(intervention.before_tool_call(_event()), _Deny)

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: types.SimpleNamespace(returncode=0, stdout="not-json", stderr=""),
    )
    assert isinstance(intervention.before_tool_call(_event()), _Deny)


def test_strands_intervention_leaves_unmapped_tools_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module(monkeypatch)
    intervention = module.HolGuardIntervention({"shell": "command"})
    event = _BeforeToolCallEvent({"name": "search", "input": {"query": "HOL Guard"}})

    decision = intervention.before_tool_call(event)

    assert isinstance(decision, _Proceed)

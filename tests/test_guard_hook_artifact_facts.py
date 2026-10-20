"""The policy action's artifact facts come from the resident, not from here."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_support_runtime_artifact_policy as policy
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_hook_artifact_facts import HookArtifactFactsUnavailableError


class _Config:
    """The settings surface ``runtime_policy_artifact_facts`` still reads."""

    def __init__(self, override: object = None, guard_home: Path | None = None) -> None:
        self._override = override
        self.guard_home = guard_home or Path("/guard-home")
        self.overrides: list[tuple[str, str, str | None]] = []

    def resolve_action_override(self, harness: str, artifact_id: str, publisher: str | None) -> object:
        self.overrides.append((harness, artifact_id, publisher))
        return self._override


def _artifact() -> GuardArtifact:
    return GuardArtifact(
        artifact_id="shell:rm",
        name="rm",
        harness="claude-code",
        artifact_type="tool_action_request",
        source_scope="workspace",
        config_path="/workspace/.claude/settings.json",
        publisher="local",
        metadata={"action_class": "destructive shell command", "risk_confidence": "strong"},
    )


def _recorder(captured: list[dict[str, object]], answers: list[dict[str, object]] | None = None):
    """Stand in for the resident bridge, recording what it was asked."""

    def fake(artifacts, *, guard_home=None):  # type: ignore[no-untyped-def]
        captured.append({"artifacts": [dict(item) for item in artifacts], "guard_home": guard_home})
        return answers if answers is not None else [{} for _ in artifacts]

    return fake


def test_the_facts_are_the_residents_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    answer = {"hard_block": True, "risk_classes": ["destructive_shell"]}

    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured, [answer]))
    config = _Config()
    artifact = _artifact()
    assert policy.runtime_policy_artifact_facts(config, artifact, "claude-code") is answer
    assert captured == [
        {
            "artifacts": [
                {
                    "artifact_type": "tool_action_request",
                    "metadata": artifact.metadata,
                    "configured_override": None,
                }
            ],
            "guard_home": config.guard_home,
        }
    ]


def test_an_evaluations_artifacts_are_asked_for_together(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    runtime = {"hard_block": False}
    approval_context = {"hard_block": True}

    monkeypatch.setattr(
        policy,
        "native_hook_artifact_facts",
        _recorder(captured, [runtime, approval_context]),
    )
    artifact = _artifact()
    answers = policy.runtime_policy_artifact_facts_batch(_Config(), ((artifact, "claude-code"), (artifact, "codex")))
    assert answers == [runtime, approval_context]
    assert len(captured) == 1
    assert len(captured[0]["artifacts"]) == 2


def test_nothing_about_the_artifact_is_decided_here(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    artifact = _artifact()
    policy.runtime_policy_artifact_facts(_Config(), artifact, "claude-code")
    # The metadata travels as the artifact carries it: no derived fact rides along.
    asked = captured[0]["artifacts"][0]
    assert set(asked) == {"artifact_type", "metadata", "configured_override"}
    assert asked["metadata"] == artifact.metadata


def test_the_configured_override_is_the_one_local_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    config = _Config(override="review")
    policy.runtime_policy_artifact_facts(config, _artifact(), "claude-code")
    assert captured[0]["artifacts"][0]["configured_override"] == "review"
    assert config.overrides == [("claude-code", "shell:rm", "local")]


def test_a_non_string_override_arrives_as_the_unknown_action(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    policy.runtime_policy_artifact_facts(_Config(override=7), _artifact(), "claude-code")
    assert captured[0]["artifacts"][0]["configured_override"] == ""


def test_an_explicit_guard_home_wins_over_the_config(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    home = Path("/other-home")
    policy.runtime_policy_artifact_facts(_Config(), _artifact(), "claude-code", guard_home=home)
    assert captured[0]["guard_home"] == home


def test_an_unavailable_resident_yields_no_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(artifacts, *, guard_home=None):  # type: ignore[no-untyped-def]
        raise HookArtifactFactsUnavailableError

    monkeypatch.setattr(policy, "native_hook_artifact_facts", unavailable)
    with pytest.raises(HookArtifactFactsUnavailableError):
        policy.runtime_policy_artifact_facts(_Config(), _artifact(), "claude-code")

"""The policy action's artifact facts come from the resident, not from here."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_artifact_facts as bridge
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


# --- The digest a saved approval is keyed by is the resident's answer too ----


def test_the_digest_is_only_asked_for_when_a_caller_needs_one(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    artifact = _artifact()
    identity = {"action_class": "destructive shell command"}
    policy.runtime_policy_artifact_facts_batch(
        _Config(),
        ((artifact, "claude-code"), (artifact, "codex")),
        hash_metadata=(None, identity),
    )
    plain, hashed = captured[0]["artifacts"]
    assert set(plain) == {"artifact_type", "metadata", "configured_override"}
    assert hashed["hash_metadata"] is identity
    assert hashed["artifact_id"] == "shell:rm"
    assert hashed["name"] == "rm"
    assert hashed["harness"] == "claude-code"
    assert hashed["source_scope"] == "workspace"
    assert hashed["config_path"] == "/workspace/.claude/settings.json"
    assert hashed["publisher"] == "local"
    assert hashed["args"] == []
    assert hashed["command"] is None
    assert hashed["url"] is None
    assert hashed["transport"] is None


def test_the_identity_metadata_is_not_the_artifacts_current_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """The caller fixes the identity before its posture stamp lands on the artifact."""

    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    artifact = _artifact()
    identity = dict(artifact.metadata)
    artifact.metadata["risk_signals"] = [{"category": "exfiltration"}]
    policy.runtime_policy_artifact_facts_batch(_Config(), ((artifact, "claude-code"),), hash_metadata=(identity,))
    asked = captured[0]["artifacts"][0]
    assert "risk_signals" in asked["metadata"]
    assert "risk_signals" not in asked["hash_metadata"]


def test_one_identity_per_artifact_or_nothing_is_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(policy, "native_hook_artifact_facts", _recorder(captured))
    with pytest.raises(ValueError):
        policy.runtime_policy_artifact_facts_batch(
            _Config(), ((_artifact(), "claude-code"),), hash_metadata=(None, None)
        )
    assert captured == []


def test_the_content_hash_is_the_residents_digest() -> None:
    assert policy.artifact_fact_content_hash({"content_sha256": "a" * 64}) == "a" * 64


@pytest.mark.parametrize("facts", [{}, {"content_sha256": None}, {"content_sha256": ""}, {"content_sha256": 7}])
def test_a_missing_or_malformed_digest_fails_closed(facts: dict[str, object]) -> None:
    with pytest.raises(HookArtifactFactsUnavailableError):
        policy.artifact_fact_content_hash(facts)


def test_every_entry_names_every_field_the_contract_serializes() -> None:
    """The resident binds its reply to the request as it parsed it.

    An entry that left a contract field out would be answered under a digest
    this side never computed, and the reply would read as unbound: the facts
    would be unavailable for every caller that asks for no digest.
    """

    artifact = _artifact()
    asked = {
        "artifact_type": artifact.artifact_type,
        "metadata": artifact.metadata,
        "configured_override": None,
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": list(artifact.args),
        "url": artifact.url,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
    }
    plain = bridge._wire_artifact(asked)
    hashed = bridge._wire_artifact({**asked, "hash_metadata": artifact.metadata})
    assert set(hashed) - set(plain) == {"metadata_stamp"}
    assert set(plain) == {
        "artifact_type",
        "metadata",
        "configured_override",
        "artifact_id",
        "name",
        "harness",
        "source_scope",
        "config_path",
        "command",
        "args",
        "url",
        "transport",
        "publisher",
    }
    assert bridge._wire_artifact({"artifact_type": "tool_action_request"}).keys() == plain.keys()


def test_the_identity_metadata_rides_as_the_stamp_rather_than_a_second_copy() -> None:
    """A second full copy would push a large metadata past the envelope limit.

    The metadata carries command text and has no size bound of its own, so a
    request that fit before would stop fitting and the hook would be left with
    no facts at all. Only the keys the stamp touched go on the wire.
    """

    artifact = _artifact()
    identity = dict(artifact.metadata)
    artifact.metadata["risk_signals"] = [{"category": "exfiltration"}]
    entry = bridge._wire_artifact(
        {"artifact_type": artifact.artifact_type, "metadata": artifact.metadata, "hash_metadata": identity}
    )
    # `action_class` and `risk_confidence` are already what the digest covers,
    # so the stamp names neither of them, only the key the hook added.
    assert entry["metadata_stamp"] == {"added": ["risk_signals"], "replaced": {}}


def test_the_stamp_carries_back_a_key_the_caller_overwrote() -> None:
    identity = {"action_class": "shell", "reason_code": "r"}
    entry = bridge._wire_artifact(
        {
            "artifact_type": "tool_action_request",
            "metadata": {"action_class": "shell", "reason_code": "stamped", "risk_confidence": "strong"},
            "hash_metadata": identity,
        }
    )
    assert entry["metadata_stamp"] == {"added": ["risk_confidence"], "replaced": {"reason_code": "r"}}


def test_the_stamp_restores_a_key_the_caller_dropped() -> None:
    """Putting a key back is the same operation whether or not it is still there."""

    entry = bridge._wire_artifact(
        {
            "artifact_type": "tool_action_request",
            "metadata": {"action_class": "shell"},
            "hash_metadata": {"action_class": "shell", "reason_code": "r"},
        }
    )
    assert entry["metadata_stamp"] == {"added": [], "replaced": {"reason_code": "r"}}

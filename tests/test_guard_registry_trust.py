"""HOL Registry trust lookups and the low-trust review floor."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import registry_trust
from codex_plugin_scanner.guard.config import GuardConfig, risk_action_config_facts
from codex_plugin_scanner.guard.consumer.low_trust import low_trust_floor
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.native_consumer_artifact_compose import NativeConsumerComposeError
from codex_plugin_scanner.guard.registry_trust import registry_trust_score


class _Response(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200) -> None:
        super().__init__(body)
        self.status = status


class _Opener:
    def __init__(self, *bodies: object) -> None:
        self.bodies = list(bodies)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> _Response:
        self.requests.append(request)
        body = self.bodies.pop(0)
        if isinstance(body, Exception):
            raise body
        return _Response(json.dumps(body).encode("utf-8"))


def _plugins(*entries: tuple[str, str, object]) -> dict[str, object]:
    plugins = [{"slug": slug, "displayName": display, "trustScore": score} for slug, display, score in entries]
    return {"plugins": plugins}


@pytest.fixture(autouse=True)
def _enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(registry_trust.REGISTRY_TRUST_ENV, raising=False)


def test_plugin_score_comes_from_the_exact_catalog_match(tmp_path: Path) -> None:
    opener = _Opener(_plugins(("acme/github-helper", "GitHub Helper", 61), ("other/github", "GitHub", 94)))

    score = registry_trust_score(tmp_path, artifact_type="plugin", name="github-helper", opener=opener)

    assert score == 61
    request = opener.requests[0]
    assert request.full_url.startswith("https://hol.org/api/guard/plugins/search?")
    assert request.get_header("Authorization") is None
    assert request.get_header("Cookie") is None


@pytest.mark.parametrize(
    "payload",
    [
        _plugins(("acme/github-helper-pro", "GitHub Helper Pro", 40)),
        _plugins(("acme/helper", "Helper", 40), ("other/helper", "helper", 90)),
        _plugins(("acme/helper", "Helper", None)),
        {"plugins": "nope"},
    ],
    ids=["fuzzy-only", "ambiguous", "unscored", "malformed"],
)
def test_unmatched_or_ambiguous_answers_have_no_score(tmp_path: Path, payload: object) -> None:
    opener = _Opener(payload)

    assert registry_trust_score(tmp_path, artifact_type="plugin", name="helper", opener=opener) is None


def test_answers_are_cached_and_transport_failures_pause_lookups_briefly(tmp_path: Path) -> None:
    failing = _Opener(urllib.error.URLError("offline"))
    assert registry_trust_score(tmp_path, artifact_type="plugin", name="helper", opener=failing, now=1000) is None
    # An offline origin is not asked again for a few minutes, for any plugin.
    quiet = _Opener()
    assert registry_trust_score(tmp_path, artifact_type="plugin", name="other", opener=quiet, now=1100) is None
    assert quiet.requests == []

    opener = _Opener(_plugins(("acme/helper", "Helper", 55)))
    assert registry_trust_score(tmp_path, artifact_type="plugin", name="helper", opener=opener, now=1000 + 6 * 60) == 55
    # The cached answer is reused without another request.
    assert registry_trust_score(tmp_path, artifact_type="plugin", name="Helper", opener=_Opener(), now=2000) == 55

    expired = 1000 + 25 * 60 * 60
    refreshed = _Opener(_plugins(("acme/helper", "Helper", 88)))
    assert registry_trust_score(tmp_path, artifact_type="plugin", name="helper", opener=refreshed, now=expired) == 88


def test_lookup_is_skipped_for_unscored_kinds_and_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opener = _Opener()
    for artifact_type in ("skill", "mcp_server", "hook", None):
        assert registry_trust_score(tmp_path, artifact_type=artifact_type, name="helper", opener=opener) is None
    monkeypatch.setenv(registry_trust.REGISTRY_TRUST_ENV, "off")
    assert registry_trust_score(tmp_path, artifact_type="plugin", name="helper", opener=opener) is None
    assert opener.requests == []


def _artifact(artifact_type: str = "plugin") -> GuardArtifact:
    return GuardArtifact(
        artifact_id=f"codex:global:{artifact_type}:helper",
        name="helper",
        harness="codex",
        artifact_type=artifact_type,
        source_scope="global",
        config_path="/home/user/.codex/config.toml",
    )


_SIGNAL = {
    "signal_id": "low_trust_artifact:codex:global:plugin:helper",
    "category": "publisher",
    "severity": "medium",
    "confidence": "likely",
    "detector": "hol_registry_trust",
    "title": "Low HOL Registry trust score",
    "plain_reason": "helper has a HOL Registry trust score of 42, below the 80 Guard asks you to review.",
    "technical_detail": "registry trust score 42 < 80",
    "evidence_ref": None,
    "redaction_level": "none",
    "false_positive_hint": (
        "Allow it if you trust this publisher; set low_trust_artifact to allow to stop these reviews."
    ),
    "advisory_id": None,
}


class _Resident:
    """Record the queries the client sends and answer them like the resident."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.queries: list[dict[str, object]] = []

    def __call__(self, kind: str, fields: Mapping[str, object], *, guard_home: Path | None) -> dict[str, object]:
        assert kind == "low_trust_floor"
        self.queries.append(dict(fields))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return cast(dict[str, object], answer)


def _lookup(monkeypatch: pytest.MonkeyPatch, score: int | None) -> list[str]:
    calls: list[str] = []

    def fake(guard_home: Path | None, *, artifact_type: str | None, name: str | None) -> int | None:
        calls.append(f"{artifact_type}:{name}")
        return score

    monkeypatch.setattr("codex_plugin_scanner.guard.consumer.low_trust.registry_trust_score", fake)
    return calls


def _resident(monkeypatch: pytest.MonkeyPatch, *answers: object) -> _Resident:
    resident = _Resident(*answers)
    monkeypatch.setattr("codex_plugin_scanner.guard.consumer.low_trust.native_consumer_compose", resident)
    return resident


def _floor(config: GuardConfig, **overrides: object):
    arguments: dict[str, object] = {
        "harness": "codex",
        "artifact": _artifact(),
        "configured_action": None,
        "fresh_decision": True,
    }
    arguments.update(overrides)
    return low_trust_floor(config.guard_home, config, **arguments)  # type: ignore[arg-type]


def test_the_resident_decides_the_floor_from_the_score_it_asks_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _lookup(monkeypatch, 42)
    resident = _resident(
        monkeypatch,
        {"score_required": True, "floor": None},
        {"score_required": False, "floor": {"action": "require-reapproval", "score": 42, "signal": _SIGNAL}},
    )
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    floor = _floor(config)

    assert floor is not None
    assert floor.action == "require-reapproval"
    assert floor.score == 42
    assert floor.signal.signal_id == "low_trust_artifact:codex:global:plugin:helper"
    assert calls == ["plugin:helper"]
    assert [query["trust_score"] for query in resident.queries] == [None, 42]


def test_the_sent_facts_carry_the_configuration_and_the_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _lookup(monkeypatch, None)
    resident = _resident(monkeypatch, {"score_required": False, "floor": None})
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=None,
        risk_actions={"low_trust_artifact": "block"},
    )

    assert _floor(config) is None

    sent = resident.queries[0]
    assert sent["risk_action_config"] == risk_action_config_facts(config)
    assert sent["harness"] == "codex"
    assert sent["artifact_type"] == "plugin"
    assert sent["artifact_id"] == "codex:global:plugin:helper"
    assert sent["artifact_name"] == "helper"
    assert sent["configured_action"] is None
    assert sent["fresh_decision"] is True
    assert sent["trust_score"] is None


@pytest.mark.parametrize(
    "overrides",
    [{"configured_action": "allow"}, {"fresh_decision": False}, {"artifact": _artifact("hook")}],
    ids=["configured", "settled", "unscored-kind"],
)
def test_an_answer_that_asks_for_no_score_runs_no_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    calls = _lookup(monkeypatch, 10)
    resident = _resident(monkeypatch, {"score_required": False, "floor": None})
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    assert _floor(config, **overrides) is None
    assert calls == []
    assert len(resident.queries) == 1


def test_an_unknown_score_never_asks_the_resident_again(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _lookup(monkeypatch, None)
    resident = _resident(monkeypatch, {"score_required": True, "floor": None})
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    assert _floor(config) is None
    assert calls == ["plugin:helper"]
    assert len(resident.queries) == 1


def test_an_unreachable_resident_fails_the_artifact_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _lookup(monkeypatch, 42)
    _resident(monkeypatch, NativeConsumerComposeError("native_consumer_artifact_compose_unavailable"))
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    with pytest.raises(NativeConsumerComposeError) as unreachable:
        _floor(config)

    assert unreachable.value.code == "native_consumer_artifact_compose_unavailable"
    assert calls == []


@pytest.mark.parametrize(
    "floor",
    [
        {"action": 7, "score": 42, "signal": _SIGNAL},
        {"action": "block", "score": "42", "signal": _SIGNAL},
        {"action": "block", "score": 42, "signal": {"signal_id": "x"}},
    ],
    ids=["action", "score", "signal"],
)
def test_a_floor_that_does_not_decode_fails_the_artifact_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, floor: dict[str, object]
) -> None:
    _lookup(monkeypatch, 42)
    _resident(monkeypatch, {"score_required": False, "floor": floor})
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    with pytest.raises(NativeConsumerComposeError) as undecodable:
        _floor(config)

    assert undecodable.value.code == "native_consumer_artifact_compose_low_trust_floor_invalid"

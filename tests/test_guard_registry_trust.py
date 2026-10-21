"""HOL Registry trust lookups and the low-trust review floor."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import registry_trust
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.consumer.low_trust import low_trust_floor
from codex_plugin_scanner.guard.models import GuardArtifact
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


def _score(monkeypatch: pytest.MonkeyPatch, score: int | None) -> list[str]:
    calls: list[str] = []

    def fake(guard_home: Path | None, *, artifact_type: str | None, name: str | None) -> int | None:
        calls.append(f"{artifact_type}:{name}")
        return score

    monkeypatch.setattr("codex_plugin_scanner.guard.consumer.low_trust.registry_trust_score", fake)
    return calls


def _floor(config: GuardConfig, **overrides: object):
    arguments: dict[str, object] = {
        "harness": "codex",
        "artifact": _artifact(),
        "configured_action": None,
        "fresh_decision": True,
    }
    arguments.update(overrides)
    return low_trust_floor(config.guard_home, config, **arguments)  # type: ignore[arg-type]


def test_low_score_on_a_fresh_artifact_raises_the_configured_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _score(monkeypatch, 42)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    floor = _floor(config)

    assert floor is not None
    assert floor.action == "require-reapproval"
    assert floor.score == 42
    assert floor.signal.signal_id == "low_trust_artifact:codex:global:plugin:helper"
    assert "42" in floor.signal.plain_reason


@pytest.mark.parametrize("score", [80, 97, None])
def test_trusted_or_unknown_scores_add_no_floor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, score: object) -> None:
    _score(monkeypatch, score)  # type: ignore[arg-type]
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    assert _floor(config) is None


@pytest.mark.parametrize(
    "overrides",
    [{"configured_action": "allow"}, {"fresh_decision": False}, {"artifact": _artifact("hook")}],
    ids=["configured", "settled", "unscored-kind"],
)
def test_configured_settled_or_unscored_artifacts_skip_the_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    calls = _score(monkeypatch, 10)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)

    assert _floor(config, **overrides) is None
    assert calls == []


def test_allowing_low_trust_artifacts_skips_the_lookup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _score(monkeypatch, 10)
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=None,
        risk_actions={"low_trust_artifact": "allow"},
    )

    assert _floor(config) is None
    assert calls == []

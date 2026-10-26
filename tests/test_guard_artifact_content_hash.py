"""The approval key an artifact is stored under comes from the resident.

``GuardStore`` keys every saved decision by this hash, so a caller that spelled
it itself could mint an allowance under a key no saved approval uses. These
tests pin what the callers ship, that they ask once per batch, and that an
unavailable resident leaves the approval unminted rather than guessed.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_artifact_content_hash as bridge
from codex_plugin_scanner.guard.cli import prompt as prompt_module
from codex_plugin_scanner.guard.models import GuardArtifact

_HASH_A = "a" * 64
_HASH_B = "b" * 64


def _artifact(artifact_id: str = "mcp:acme") -> GuardArtifact:
    return GuardArtifact(
        artifact_id=artifact_id,
        name="acme",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="workspace",
        config_path="/workspace/.mcp.json",
        command="npx",
        args=["--token=supersecret"],
        url="https://acme.test/mcp?api_key=supersecret",
        transport="stdio",
        publisher="acme",
        metadata={"env": {"ACME_TOKEN": "supersecret"}, "env_keys": ["ACME_TOKEN"]},
    )


def _serve(monkeypatch: pytest.MonkeyPatch, payload: object, captured: list[dict[str, object]]) -> None:
    """Stand in for the resident, recording the request it was handed."""

    def fake_request(**kwargs: object) -> dict[str, object]:
        captured.append(dict(kwargs))
        return {"schema": "guard-artifact-content-hash-result.v1"}

    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda home: Path("/guard-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(bridge, "_resident_request", fake_request)
    monkeypatch.setattr(bridge, "_payload", lambda response, request, home: payload)


def test_the_artifact_reaches_the_resident_unredacted() -> None:
    fields = bridge.artifact_content_hash_fields(_artifact())
    assert fields["args"] == ["--token=supersecret"]
    assert fields["url"] == "https://acme.test/mcp?api_key=supersecret"
    assert fields["metadata"] == {"env": {"ACME_TOKEN": "supersecret"}, "env_keys": ["ACME_TOKEN"]}


def test_nothing_to_hash_never_crosses_to_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(**kwargs: object) -> dict[str, object]:
        raise AssertionError("an empty request must not reach the resident")

    monkeypatch.setattr(bridge, "_resident_request", refuse)
    assert bridge.native_artifact_content_hashes([]) == []


def test_a_batch_answers_in_the_order_it_was_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []
    _serve(monkeypatch, {"content_hashes": [_HASH_A, _HASH_B]}, captured)

    artifacts = [_artifact("mcp:acme"), _artifact("mcp:other")]
    assert bridge.native_artifact_content_hashes(artifacts) == [_HASH_A, _HASH_B]
    assert len(captured) == 1
    request = captured[0]["request"]
    assert isinstance(request, dict)
    assert [item["artifact_id"] for item in request["artifacts"]] == ["mcp:acme", "mcp:other"]


@pytest.mark.parametrize(
    "payload",
    [
        {"content_hashes": ["not-a-hash"]},
        {"content_hashes": [_HASH_A, _HASH_B]},
        {"content_hashes": _HASH_A},
        {},
    ],
)
def test_an_answer_that_is_not_a_hash_is_refused(payload: object, monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, payload, [])
    with pytest.raises(bridge.ArtifactContentHashUnavailableError):
        bridge.native_artifact_content_hash(_artifact())


def test_a_prompt_asks_for_its_hashes_in_one_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def batched(artifacts, *, guard_home: Path | None = None) -> list[str]:  # type: ignore[no-untyped-def]
        calls.append(len(artifacts))
        return [_HASH_A, _HASH_B][: len(artifacts)]

    monkeypatch.setattr(prompt_module, "native_artifact_content_hashes", batched)
    artifacts = [_artifact("mcp:acme"), _artifact("mcp:other")]
    evaluation = [
        {"artifact_id": "mcp:acme", "policy_action": "review"},
        {"artifact_id": "mcp:other", "policy_action": "review"},
    ]

    rows = prompt_module.build_prompt_artifacts("claude-code", artifacts, evaluation)
    assert calls == [2]
    assert [row.artifact_hash for row in rows] == [_HASH_A, _HASH_B]
    assert [row.snapshot_hash for row in rows] == [_HASH_A, _HASH_B]


def test_a_prompt_whose_rows_carry_their_hashes_never_crosses_to_the_resident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(artifacts, *, guard_home: Path | None = None) -> list[str]:  # type: ignore[no-untyped-def]
        raise AssertionError("a prompt with every hash in hand must not ask the resident")

    monkeypatch.setattr(prompt_module, "native_artifact_content_hashes", refuse)
    evaluation = [
        {
            "artifact_id": "mcp:acme",
            "policy_action": "review",
            "approval_context_hash": _HASH_A,
            "artifact_hash": _HASH_B,
        }
    ]

    rows = prompt_module.build_prompt_artifacts("claude-code", [_artifact("mcp:acme")], evaluation)
    assert [row.artifact_hash for row in rows] == [_HASH_A]
    assert [row.snapshot_hash for row in rows] == [_HASH_B]


def test_only_the_rows_missing_a_hash_are_asked_for(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[list[str]] = []

    def batched(artifacts, *, guard_home: Path | None = None) -> list[str]:  # type: ignore[no-untyped-def]
        asked.append([artifact.artifact_id for artifact in artifacts])
        return [_HASH_B] * len(artifacts)

    monkeypatch.setattr(prompt_module, "native_artifact_content_hashes", batched)
    artifacts = [_artifact("mcp:acme"), _artifact("mcp:other")]
    evaluation = [
        {
            "artifact_id": "mcp:acme",
            "policy_action": "review",
            "approval_context_hash": _HASH_A,
            "artifact_hash": _HASH_A,
        },
        {"artifact_id": "mcp:other", "policy_action": "review"},
    ]

    rows = prompt_module.build_prompt_artifacts("claude-code", artifacts, evaluation)
    assert asked == [["mcp:other"]]
    assert [row.artifact_hash for row in rows] == [_HASH_A, _HASH_B]


def test_a_batch_splits_before_it_outgrows_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[list[str]] = []

    def fake_request(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        sent.append([item["artifact_id"] for item in request["artifacts"]])
        return {"schema": "guard-artifact-content-hash-result.v1"}

    monkeypatch.setattr(bridge, "_resolve_digest_home", lambda home: Path("/guard-home"))
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda home: True)
    monkeypatch.setattr(bridge, "_resident_request", fake_request)
    monkeypatch.setattr(
        bridge,
        "_payload",
        lambda response, request, home: {"content_hashes": [_HASH_A] * len(request["artifacts"])},
    )
    monkeypatch.setattr(bridge, "_MAX_BATCH_BYTES", 2048)

    def wide(artifact_id: str) -> GuardArtifact:
        return replace(_artifact(artifact_id), args=["x" * 1200])

    artifacts = [wide("mcp:one"), wide("mcp:two"), wide("mcp:three")]
    assert bridge.native_artifact_content_hashes(artifacts) == [_HASH_A] * 3
    assert sent == [["mcp:one"], ["mcp:two"], ["mcp:three"]]


def test_a_batch_fits_the_request_the_transport_actually_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    """The split measures an artifact the way the request spells it on the wire.

    The envelope is written with the separators ``json.dumps`` uses by default,
    so a compact measurement undercounts every comma and colon it carries. An
    artifact with many short arguments is mostly separators, and a batch of them
    was counted under the cap and refused whole once it was sent, which lost
    every hash in it.
    """

    monkeypatch.setattr(bridge, "_MAX_BATCH_BYTES", 8192)

    def busy(artifact_id: str) -> GuardArtifact:
        return replace(_artifact(artifact_id), args=[f"a{index}" for index in range(120)])

    artifacts = [busy(f"mcp:acme{index}") for index in range(24)]
    batches = list(bridge._batches(artifacts))
    assert [item for batch in batches for item in batch] == artifacts
    for batch in batches:
        on_the_wire = json.dumps([bridge.artifact_content_hash_fields(item) for item in batch])
        assert len(on_the_wire.encode("utf-8")) <= bridge._MAX_BATCH_BYTES

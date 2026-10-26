"""The checked-in fleet-posture/v1 contract and its fixtures agree with each other."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

CONTRACT_DIR = Path(__file__).resolve().parents[1] / "contracts" / "fleet-posture" / "v1"
MAX_PAYLOAD_BYTES = 65536
VALID_FIXTURES = ("solo-macos", "team-linux-delta", "digest-only")


def _schema() -> dict[str, object]:
    return json.loads((CONTRACT_DIR / "schema.json").read_text(encoding="utf-8"))


def _fixture(name: str) -> dict[str, object]:
    return json.loads((CONTRACT_DIR / "fixtures" / f"{name}.json").read_text(encoding="utf-8"))


def _serialized_size(payload: object) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def test_schema_is_a_valid_draft_2020_12_document() -> None:
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://guard.hashgraphonline.com/schema/fleet-posture/v1"


@pytest.mark.parametrize("name", VALID_FIXTURES)
def test_valid_fixtures_pass_the_schema_and_the_size_limit(name: str) -> None:
    payload = _fixture(name)
    Draft202012Validator(_schema()).validate(payload)
    assert _serialized_size(payload) <= MAX_PAYLOAD_BYTES


def test_too_large_fixture_is_schema_valid_but_over_the_byte_limit() -> None:
    payload = _fixture("too-large")
    Draft202012Validator(_schema()).validate(payload)
    assert _serialized_size(payload) > MAX_PAYLOAD_BYTES


def test_fixtures_cover_every_inventory_mode() -> None:
    modes = {_fixture(name)["inventory"]["mode"] for name in (*VALID_FIXTURES, "too-large")}  # type: ignore[index]
    assert modes == {"full", "delta", "digest_only"}


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schemaVersion",), "fleet-posture/v2"),
        (("client", "version"), "latest"),
        (("collectedAt",), "2026-10-16T12:00:00+02:00"),
        (("inventory", "mode"), "everything"),
        (("machine", "hostnameHash"), "sha256:abc"),
        (("aiTools", 0, "protectionState"), "unknown"),
    ],
)
def test_schema_rejects_malformed_values(path: tuple[object, ...], value: object) -> None:
    payload = _fixture("solo-macos")
    target: object = payload
    for key in path[:-1]:
        target = target[key]  # type: ignore[index]
    target[path[-1]] = value  # type: ignore[index]
    assert not Draft202012Validator(_schema()).is_valid(payload)


def test_schema_rejects_unknown_top_level_fields() -> None:
    payload = _fixture("solo-macos")
    payload["extra"] = True
    assert not Draft202012Validator(_schema()).is_valid(payload)

"""Closed secret-provider contract and fixture checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).parents[1]
SCHEMA_DIR = ROOT / "contracts" / "secret-providers"
MANIFEST = ROOT / "contributions" / "secret-providers" / "provider.examplevault.json"
TRUST = ROOT / "contracts" / "secret-providers" / "provider.examplevault.trust.v1.json"
FIXTURE = ROOT / "tests" / "fixtures" / "secret-providers" / "provider.examplevault.v1.json"


def load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def test_manifest_and_trust_binding_match_closed_schemas() -> None:
    manifest = load(MANIFEST)
    trust = load(TRUST)
    Draft202012Validator(load(SCHEMA_DIR / "secret-provider.v1.schema.json")).validate(manifest)
    Draft202012Validator(load(SCHEMA_DIR / "secret-provider-trust.v1.schema.json")).validate(trust)
    assert manifest["default_enabled"] is False
    assert trust["default_enabled"] is False
    assert trust["local_enablement_required"] is True
    assert manifest["id"] == trust["provider_id"]
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    assert trust["manifest_digest"] == hashlib.sha256(canonical).hexdigest()


def test_fixture_never_promotes_value_to_outward_metadata() -> None:
    fixture = load(FIXTURE)
    assert fixture["privacy"] == {"value_in_outward_response": False, "value_in_journal": False}
    assert fixture["expected"]["secret_debug"] == "REDACTED"
    assert "fixture-value-7" in json.dumps(fixture["response"])
    assert "fixture-value-7" not in json.dumps(fixture["expected"])


def test_manifest_rejects_unknown_fields_and_unsafe_defaults() -> None:
    schema = load(SCHEMA_DIR / "secret-provider.v1.schema.json")
    invalid = load(MANIFEST)
    invalid["execute"] = "fixture-program"
    assert not Draft202012Validator(schema).is_valid(invalid)
    invalid = load(MANIFEST)
    invalid["default_enabled"] = True
    assert not Draft202012Validator(schema).is_valid(invalid)

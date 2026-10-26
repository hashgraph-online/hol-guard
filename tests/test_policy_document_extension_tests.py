from __future__ import annotations

import copy
import json
from dataclasses import asdict
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.policy_document import (
    canonical_policy_document_bytes,
    policy_document_digest,
)
from codex_plugin_scanner.guard.policy_document_compile import PolicyCompilationError, compile_policy_document
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.store import GuardStore

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec" / "guard-policy" / "v1alpha1"
FIXTURES = SPEC / "fixtures"
EXTENSION_SCHEMA = SPEC / "extensions" / "x-hol.tests.schema.json"
COMPILED_ROWS = FIXTURES / "compiled" / "rows.json"
TESTED_FIXTURES = ("valid/with-tests.yaml", "valid/enforceable-scopes.yaml")
IMPORT_TIME = "2026-01-01T00:00:00Z"
DEFAULT_EVENT_TIME = "2026-10-14T12:00:00Z"


def _validator() -> Draft202012Validator:
    schema = json.loads(EXTENSION_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _mapping(relative: str) -> dict[str, object]:
    document = parse_policy_document_yaml((FIXTURES / relative).read_bytes())
    return json.loads(canonical_policy_document_bytes(document))


def _rows(document_mapping: dict[str, object]) -> list[dict[str, object]]:
    source = yaml.safe_dump(document_mapping, allow_unicode=True, sort_keys=False)
    rows = compile_policy_document(parse_policy_document_yaml(source))
    return [
        {"rule_id": row.rule_id, "decision": asdict(row.decision), "provenance_json": row.provenance_json}
        for row in rows
    ]


def _fixture_test_ids() -> list[tuple[str, str]]:
    # Collection runs before the native runtime is bound, so read only the test ids with plain YAML here.
    return [
        (relative, test["id"])
        for relative in TESTED_FIXTURES
        for test in yaml.safe_load((FIXTURES / relative).read_text(encoding="utf-8"))["spec"]["x-hol.tests"]
    ]


def test_tested_fixtures_are_in_the_manifest() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))

    assert set(TESTED_FIXTURES) <= set(manifest["valid"])
    tested = {relative for relative in manifest["valid"] if "x-hol.tests" in _mapping(relative)["spec"]}
    assert tested == set(TESTED_FIXTURES)


@pytest.mark.parametrize("relative", TESTED_FIXTURES)
def test_fixture_extension_value_matches_registered_schema(relative: str) -> None:
    mapping = _mapping(relative)
    tests = mapping["spec"]["x-hol.tests"]
    rule_ids = {rule["id"] for rule in mapping["spec"]["rules"]}

    assert list(_validator().iter_errors(tests)) == []
    assert len({test["id"] for test in tests}) == len(tests)
    for test in tests:
        expected_rule = test["expect"].get("ruleId")
        if expected_rule is not None:
            assert expected_rule in rule_ids


@pytest.mark.parametrize("relative", TESTED_FIXTURES)
def test_extension_changes_digest_but_not_compiled_rows(relative: str) -> None:
    with_tests = _mapping(relative)
    without_tests = copy.deepcopy(with_tests)
    del without_tests["spec"]["x-hol.tests"]

    with_digest = policy_document_digest(parse_policy_document_yaml((FIXTURES / relative).read_bytes()))
    without_digest = policy_document_digest(
        parse_policy_document_yaml(yaml.safe_dump(without_tests, allow_unicode=True, sort_keys=False))
    )

    assert with_digest != without_digest
    assert _rows(with_tests) == _rows(without_tests)


def test_compiled_rows_match_recorded_vectors() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    recorded = json.loads(COMPILED_ROWS.read_text(encoding="utf-8"))["vectors"]

    assert [vector["document"] for vector in recorded] == manifest["valid"]
    for vector in recorded:
        if "error" in vector:
            with pytest.raises(PolicyCompilationError) as raised:
                _rows(_mapping(vector["document"]))
            code, _, rule_id = str(raised.value).partition(": ")
            assert {"code": code, "ruleId": rule_id} == vector["error"], vector["document"]
        else:
            assert _rows(_mapping(vector["document"])) == vector["rows"], vector["document"]


@pytest.mark.parametrize(
    ("relative", "test_id"),
    _fixture_test_ids(),
    ids=[f"{relative}::{test_id}" for relative, test_id in _fixture_test_ids()],
)
def test_fixture_tests_match_the_runtime_lookup(tmp_path: Path, relative: str, test_id: str) -> None:
    document = parse_policy_document_yaml((FIXTURES / relative).read_bytes())
    test = next(test for test in _mapping(relative)["spec"]["x-hol.tests"] if test["id"] == test_id)
    store = GuardStore(tmp_path / "guard")
    store.import_policy_document(
        document,
        compile_policy_document(document),
        mode="replace",
        now=IMPORT_TIME,
        approval_gate_grant=None,
    )
    event = test["event"]
    tool = event.get("tool")
    artifact_id = event.get("artifact") or (f"family:{'tool-action' if tool == 'shell' else tool}" if tool else None)

    lookup = store.resolve_policy_decision_lookup(
        event["harness"],
        artifact_id,
        workspace=event.get("workspace"),
        publisher=event.get("publisher"),
        now=event.get("at", DEFAULT_EVENT_TIME),
        consume_one_shot=False,
    )

    decision = lookup["decision"]
    expect = test["expect"]
    if expect["effect"] == "default":
        assert decision is None
        return
    assert decision is not None
    assert decision["action"] == expect["effect"]
    if "ruleId" in expect:
        with store._connect() as connection:
            row = connection.execute(
                "select policy_rule_id from policy_decisions where decision_id = ?",
                (decision["decision_id"],),
            ).fetchone()
        assert row[0] == expect["ruleId"]


@pytest.mark.parametrize(
    "value",
    [
        {"id": "not-a-list"},
        [{"id": "missing-event", "expect": {"effect": "allow"}}],
        [{"id": "no-harness", "event": {"tool": "mcp"}, "expect": {"effect": "allow"}}],
        [{"id": "bad-tool", "event": {"harness": "codex", "tool": "browser"}, "expect": {"effect": "block"}}],
        [{"id": "review", "event": {"harness": "codex"}, "expect": {"effect": "review"}}],
        [
            {
                "id": "local-time",
                "event": {"harness": "codex", "at": "2026-11-01T00:00:00+02:00"},
                "expect": {"effect": "allow"},
            }
        ],
        [{"id": "raw-command", "event": {"harness": "codex", "command": "rm -rf /"}, "expect": {"effect": "block"}}],
        [{"id": "-leading-dash", "event": {"harness": "codex"}, "expect": {"effect": "default"}}],
        [
            {
                "id": "artifact-and-tool",
                "event": {"harness": "codex", "artifact": "pkg:npm/example", "tool": "mcp"},
                "expect": {"effect": "block"},
            }
        ],
        [{"id": f"t{index}", "event": {"harness": "codex"}, "expect": {"effect": "default"}} for index in range(257)],
    ],
    ids=[
        "not-an-array",
        "missing-event",
        "missing-harness",
        "unknown-tool-family",
        "unsupported-effect",
        "non-utc-timestamp",
        "raw-command-field",
        "invalid-identifier",
        "artifact-and-tool",
        "too-many-tests",
    ],
)
def test_invalid_extension_values_are_rejected(value: object) -> None:
    assert list(_validator().iter_errors(value)) != []

from __future__ import annotations

import copy
import subprocess
import sys
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard.contracts import guard_cloud_review as contract_adapter
from codex_plugin_scanner.guard.contracts.guard_cloud_review import (
    COMMAND_RESULT_CONTRACT_PATH,
    COMMAND_RESULT_CONTRACT_VERSION,
    CONTRACT_PATH,
    CONTRACT_VERSION,
    FIXTURES_PATH,
    PUBLIC_DOCUMENTATION_PATH,
    expected_artifact_digests,
    load_contract,
    load_exact_command_result_contract,
    load_fixtures,
    render_public_documentation,
    resolve_json_pointer,
    result_validation_schema,
    status_values,
    validate_exact_command_result,
    validate_generated_artifacts,
    validate_review_result,
    validate_reviewability_case,
)


def _mapping_items(value: object, label: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        raise AssertionError(f"{label} must be a list of objects")
    raw_items = cast(list[object], value)
    items: list[Mapping[str, object]] = []
    for item in raw_items:
        items.append(_string_keyed_mapping(item, label))
    return items


def _string_keyed_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AssertionError(f"{label} must be an object")
    raw_mapping = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        raise AssertionError(f"{label} must use string object keys")
    return cast(Mapping[str, object], raw_mapping)


def _schema_validate(schema: Mapping[str, object], instance: object) -> None:
    validate = cast(Callable[[object], None], Draft202012Validator(schema).validate)
    validate(instance)


def _result_cases(name: str) -> list[Mapping[str, object]]:
    return _mapping_items(load_fixtures().get(name), name)


def _set_path(payload: dict[str, object], path: list[object], value: object) -> None:
    cursor: dict[str, object] = payload
    for part in path[:-1]:
        if not isinstance(part, str):
            raise AssertionError("fixture paths must contain string keys")
        child = cursor.get(part)
        if not isinstance(child, dict):
            raise AssertionError(f"fixture path does not resolve: {part}")
        cursor = cast(dict[str, object], child)
    final_part = path[-1]
    if not isinstance(final_part, str):
        raise AssertionError("fixture paths must contain string keys")
    cursor[final_part] = value


def _delete_path(payload: dict[str, object], path: list[object]) -> None:
    cursor: dict[str, object] = payload
    for part in path[:-1]:
        if not isinstance(part, str):
            raise AssertionError("fixture paths must contain string keys")
        child = cursor.get(part)
        if not isinstance(child, dict):
            raise AssertionError(f"fixture path does not resolve: {part}")
        cursor = cast(dict[str, object], child)
    final_part = path[-1]
    if not isinstance(final_part, str) or final_part not in cursor:
        raise AssertionError("fixture deletion path must resolve")
    del cursor[final_part]


def _result_by_name(name: object) -> Mapping[str, object]:
    if not isinstance(name, str):
        raise AssertionError("fixture source name must be a string")
    for case in _result_cases("validResults"):
        if case.get("name") == name:
            result = case.get("result")
            if isinstance(result, Mapping):
                return cast(Mapping[str, object], result)
    raise AssertionError(f"missing fixture source: {name}")


def test_contract_and_fixtures_are_versioned_and_present() -> None:
    assert CONTRACT_PATH.is_file()
    assert COMMAND_RESULT_CONTRACT_PATH.is_file()
    assert FIXTURES_PATH.is_file()
    metadata = load_contract()["x-hol-contract"]
    assert isinstance(metadata, Mapping)
    assert metadata["contractVersion"] == CONTRACT_VERSION
    assert load_fixtures()["contractVersion"] == CONTRACT_VERSION


def test_command_result_contract_is_runtime_backed_and_maps_cloud_aggregation() -> None:
    command_result = load_exact_command_result_contract()
    metadata = command_result["x-hol-contract"]
    assert isinstance(metadata, Mapping)
    assert metadata["contractVersion"] == COMMAND_RESULT_CONTRACT_VERSION
    correlation = metadata["correlation"]
    assert isinstance(correlation, Mapping)
    assert correlation["field"] == "correlationId"
    aggregation = correlation["cloudAggregation"]
    assert aggregation == {
        "agentContinuationStatus": "/continuationStatus",
        "commandJobId": "/correlationId",
        "decisionReceiptId": "/receiptId",
        "localApplicationStatus": "/applicationStatus",
        "reviewRequestLocalId": "/localRequestId",
    }
    result = {
        "applicationReason": None,
        "applicationStatus": "applied",
        "applicationUpdatedAt": "2026-08-24T00:03:00+00:00",
        "continuationReason": None,
        "continuationStatus": "resumed",
        "continuationUpdatedAt": "2026-08-24T00:03:00+00:00",
        "contractVersion": COMMAND_RESULT_CONTRACT_VERSION,
        "correlationId": "command-123",
        "localRequestId": "request-123",
        "receiptId": "receipt-123",
    }
    validate_exact_command_result(result)
    result.pop("receiptId")
    with pytest.raises(ValueError, match="receiptId"):
        validate_exact_command_result(result)


def test_result_schema_is_valid_draft_2020_12_with_root_addressable_references() -> None:
    contract = load_contract()
    assert "resultSchema" not in contract
    Draft202012Validator.check_schema(contract)
    Draft202012Validator.check_schema(result_validation_schema())
    with pytest.raises(ValidationError, match="required property"):
        _schema_validate(contract, {})


def test_contract_defines_phase_zero_glossary_invariants_and_operation_boundary() -> None:
    metadata = load_contract()["x-hol-contract"]
    assert isinstance(metadata, Mapping)
    assert metadata["implementationPhase"] == "runtime-backed"
    glossary = _string_keyed_mapping(metadata["glossary"], "glossary")
    assert set(glossary) == {
        "localRequest",
        "reviewRequest",
        "decision",
        "deliveryCommand",
        "localApplication",
        "agentContinuation",
    }
    invariants = _mapping_items(metadata["invariants"], "invariants")
    assert {item["id"] for item in invariants} == {
        "decision-not-application",
        "application-not-continuation",
        "allow-once-exact-request",
        "immutable-block-not-remotely-approvable",
        "policy-memory-separate-operation",
    }
    operations = metadata["operations"]
    assert isinstance(operations, Mapping)
    exact = operations["guard.review.resolveExact"]
    memory = operations["guard.review.syncPolicyMemory"]
    assert isinstance(exact, Mapping)
    assert isinstance(memory, Mapping)
    assert exact["outcomes"] == ["allow_once", "block"]
    assert exact["oneTime"] is True
    assert exact["createsReusablePolicy"] is False
    assert exact["createsDecisionMemory"] is False
    assert exact["requiresSeparateAuthorization"] is False
    assert memory["createsReusablePolicy"] is True
    assert memory["createsDecisionMemory"] is True
    assert memory["requiresSeparateAuthorization"] is True


def test_valid_result_fixtures_cover_recorded_applied_and_continuation_outcomes() -> None:
    cases = _result_cases("validResults")
    assert {case["name"] for case in cases} == {
        "pending-without-decision-or-delivery",
        "decision-recorded-awaiting-local-application",
        "allow-once-applied-and-resumed",
        "allow-once-applied-manual-retry",
        "block-applied-without-continuation",
        "block-recorded-awaiting-local-application",
        "allow-once-applied-and-already-resumed",
        "continuation-failed-after-terminal-local-application",
        "continuation-not-applicable-without-local-application",
    }
    for case in cases:
        validate_review_result(_string_keyed_mapping(case.get("result"), "result"))


def test_valid_results_attach_one_correlation_to_every_required_review_stage() -> None:
    for case in _result_cases("validResults"):
        result = case.get("result")
        assert isinstance(result, Mapping)
        correlation_id = result["correlationId"]
        for name in ("request", "decision", "delivery", "application", "continuation"):
            record = result[name]
            assert isinstance(record, Mapping)
            assert record["correlationId"] == correlation_id


def test_invalid_result_fixtures_fail_closed() -> None:
    for case in _result_cases("invalidResults"):
        candidate = copy.deepcopy(dict(_result_by_name(case.get("source"))))
        mutations = _mapping_items(case.get("mutations"), "mutations")
        for mutation in mutations:
            path = mutation.get("path")
            if not isinstance(path, list):
                raise AssertionError("fixture mutation path must be a list")
            mutation_path = cast(list[object], path)
            if mutation.get("delete") is True:
                _delete_path(candidate, mutation_path)
            else:
                _set_path(candidate, mutation_path, mutation.get("value"))
        with pytest.raises(ValueError, match=str(case["error"])):
            validate_review_result(candidate)


def test_portable_rfc3339_validation_does_not_depend_on_jsonschema_format_checker() -> None:
    candidate = copy.deepcopy(dict(_result_by_name("pending-without-decision-or-delivery")))
    candidate["observedAt"] = "2026-08-23 17:59:00"
    _schema_validate(load_contract(), candidate)
    with pytest.raises(ValueError, match="RFC3339 date-time"):
        validate_review_result(candidate)
    for timestamp in ("2026-08-23T17:59:00.1234567Z", "2026-08-23T17:59:00.123456789+05:30"):
        candidate["observedAt"] = timestamp
        validate_review_result(candidate)


def test_reviewability_fixtures_preserve_the_immutable_block_boundary() -> None:
    for case in _result_cases("reviewabilityCases"):
        validate_reviewability_case(case)


def test_statuses_have_one_contract_owned_source_of_truth(monkeypatch: pytest.MonkeyPatch) -> None:
    assert status_values("requestStatus") == (
        "pending",
        "resolved_allow",
        "resolved_block",
        "expired",
        "cancelled",
        "superseded",
    )
    assert status_values("continuationCapability") == (
        "suspended-response",
        "session-resume",
        "retry-only",
        "unsupported",
    )
    assert "sent" not in status_values("applicationStatus")
    with pytest.raises(ValueError, match="unknown Guard Cloud Review vocabulary"):
        _ = status_values("legacyDaemonAckStatus")
    escaped_contract: dict[str, object] = {
        "$defs": {"stage/status~values": [{"enum": ["queued", "applied"]}]},
        "x-hol-contract": {"vocabularyPaths": {"escapedStatus": "#/$defs/stage~1status~0values/0"}},
    }
    monkeypatch.setattr(contract_adapter, "load_contract", lambda: escaped_contract)
    assert status_values("escapedStatus") == ("queued", "applied")
    assert resolve_json_pointer({"stages": [{"a/b~c": "ready"}]}, "/stages/0/a~1b~0c") == "ready"
    assert resolve_json_pointer({"space key": "ready"}, "#/space%20key") == "ready"
    assert resolve_json_pointer({"/": "ready"}, "#/%7E1") == "ready"
    with pytest.raises(ValueError, match="invalid escape"):
        _ = resolve_json_pointer({}, "/invalid~2escape")
    with pytest.raises(ValueError, match="invalid percent escape"):
        _ = resolve_json_pointer({}, "#/invalid%2")
    with pytest.raises(ValueError, match="not valid UTF-8"):
        _ = resolve_json_pointer({}, "#/%FF")
    with pytest.raises(ValueError, match="invalid array index"):
        _ = resolve_json_pointer(["ready"], "/01")


def test_semantic_rules_are_portable_contract_data() -> None:
    metadata = load_contract()["x-hol-contract"]
    assert isinstance(metadata, Mapping)
    rules = _mapping_items(metadata["semanticRules"], "semanticRules")
    assert {rule["id"] for rule in rules} >= {
        "rfc3339-date-times",
        "correlation-equality",
        "exact-result-reviewable-pause",
        "recorded-decision-has-delivery",
        "completed-application-requires-applied-delivery",
        "resolved-allow-requires-recorded-decision",
        "resolved-block-requires-recorded-decision",
        "resolved-block-requires-blocked-continuation",
        "resolved-request-requires-applied-application",
        "recorded-block-requires-blocked-continuation",
        "applied-block-requires-blocked-continuation",
        "resumed-continuation-requires-recorded-decision",
        "resumed-continuation-requires-allow-once-decision",
        "not-applicable-continuation-requires-not-applicable-application",
        "not-applicable-delivery-requires-not-applicable-application",
        "failed-continuation-requires-compatible-application",
        "not-applicable-application-requires-not-applicable-delivery",
    }
    assert {rule["operator"] for rule in rules} >= {
        "all_equal",
        "equals",
        "if_equals_then_equals",
        "rfc3339_date_time",
    }


def test_public_documentation_is_generated_from_contract_source() -> None:
    assert PUBLIC_DOCUMENTATION_PATH.read_text(encoding="utf-8") == render_public_documentation()


def test_generated_artifacts_match_non_self_referential_contract_digests(tmp_path: Path) -> None:
    metadata = load_contract()["x-hol-contract"]
    assert isinstance(metadata, Mapping)
    generation = metadata["generation"]
    assert isinstance(generation, Mapping)
    assert generation["excludes"] == ["contract.json"]
    expected = expected_artifact_digests()
    assert set(expected) == {"commandResult", "fixtures", "publicDocumentation"}
    assert validate_generated_artifacts() == expected
    wheel_directory = tmp_path / "wheel"
    wheel_directory.mkdir()
    _ = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_directory)],
        check=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    wheel_paths = tuple(wheel_directory.glob("*.whl"))
    assert len(wheel_paths) == 1
    wheel_path = wheel_paths[0]
    resource_names = {
        "codex_plugin_scanner/guard/contracts/data/guard-cloud-review/v2/contract.json",
        "codex_plugin_scanner/guard/contracts/data/guard-cloud-review/v2/command-result.json",
        "codex_plugin_scanner/guard/contracts/data/guard-cloud-review/v2/fixtures.json",
        "codex_plugin_scanner/guard/contracts/data/guard-cloud-review/guard-cloud-review.md",
    }
    with zipfile.ZipFile(wheel_path) as archive:
        assert resource_names <= set(archive.namelist())
        archive.extractall(tmp_path / "unpacked-wheel")
    probe = "\n".join(
        (
            "from pathlib import Path",
            "import sys",
            "unpacked, repository = (Path(value).resolve() for value in sys.argv[1:])",
            "checkout_import_roots = {repository, repository / 'src'}",
            "def is_checkout_import_path(entry: str) -> bool:",
            "    return Path(entry or '.').resolve() in checkout_import_roots",
            "sys.path[:] = [str(unpacked), *(entry for entry in sys.path if not is_checkout_import_path(entry))]",
            "from codex_plugin_scanner.guard.contracts import guard_cloud_review as contract",
            (
                "resources = (contract.CONTRACT_PATH, contract.COMMAND_RESULT_CONTRACT_PATH, "
                "contract.FIXTURES_PATH, contract.PUBLIC_DOCUMENTATION_PATH)"
            ),
            "assert all(path.is_relative_to(unpacked) for path in resources)",
            "assert contract.load_contract()['x-hol-contract']['contractVersion'] == contract.CONTRACT_VERSION",
            (
                "assert contract.load_exact_command_result_contract()['x-hol-contract']['contractVersion'] "
                "== contract.COMMAND_RESULT_CONTRACT_VERSION"
            ),
            "assert contract.validate_generated_artifacts() == contract.expected_artifact_digests()",
        )
    )
    _ = subprocess.run(
        [sys.executable, "-c", probe, str(tmp_path / "unpacked-wheel"), str(Path(__file__).resolve().parents[1])],
        check=True,
        cwd=tmp_path,
    )

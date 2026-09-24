from __future__ import annotations

import copy
import io
import os
import stat
import traceback
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard import evaluation_contracts as contracts_module
from codex_plugin_scanner.guard import evaluation_evidence_package as evidence_package_module
from codex_plugin_scanner.guard.evaluation_contracts import (
    EVALUATION_PROFILE_SCHEMA_VERSION,
    EVALUATION_RESULT_SCHEMA_VERSION,
    EvaluationContractError,
    EvaluationProfile,
    EvaluationResult,
    evaluation_profile_schema,
    evaluation_result_schema,
    validate_evaluation_profile,
    validate_evaluation_result,
)
from codex_plugin_scanner.guard.evaluation_evidence_package import (
    build_evaluation_evidence_package,
    verify_evaluation_evidence_package,
    write_evaluation_evidence_package,
)


def _profile(tmp_path: Path) -> dict[str, object]:
    root = tmp_path / "evaluation-root"
    endpoint = "http://127.0.0.1:8765/receiver"
    artifact_digest = "sha256:" + "b" * 64
    return {
        "schemaVersion": EVALUATION_PROFILE_SCHEMA_VERSION,
        "profileId": "synthetic-local-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.4.2",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": {
            "product": "synthetic-agent",
            "version": "0.1.0",
            "os": "linux",
            "architecture": "x86_64",
            "runtimeLocation": "local",
            "requiredPrivilege": "standard_user",
        },
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.4.2",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "d" * 64,
        },
        "targetScope": {
            "rootPath": str(root),
            "allowedPaths": [str(root / "workspace")],
            "allowedEndpoints": [endpoint],
        },
        "resourceLimits": {
            "maxDurationSeconds": 60,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryBytes": 128 * 1024 * 1024,
            "maxConcurrency": 2,
        },
        "expectedCapabilities": [
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _result(profile: dict[str, object]) -> dict[str, object]:
    root = Path(profile["targetScope"]["rootPath"])  # type: ignore[index]
    endpoint = profile["targetScope"]["allowedEndpoints"][0]  # type: ignore[index]
    artifact = profile["installedArtifacts"][0]  # type: ignore[index]
    return {
        "schemaVersion": EVALUATION_RESULT_SCHEMA_VERSION,
        "resultId": "result-1",
        "profileId": profile["profileId"],
        "buildIdentity": copy.deepcopy(profile["buildIdentity"]),
        "artifactIdentity": copy.deepcopy(artifact),
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "proofRunId": "run-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],  # type: ignore[index]
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [
            {
                "caseId": "synthetic.read",
                "status": "passed",
                "expectedAction": "allow",
                "observedAction": "allow",
                "proofType": "unit_test",
                "witness": {
                    "kind": "loopback_receiver",
                    "path": str(root / "workspace" / "sentinel"),
                    "endpoint": endpoint,
                    "digest": "sha256:" + "e" * 64,
                    "note": "synthetic local witness",
                },
            }
        ],
    }


def test_evaluation_schemas_are_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(evaluation_profile_schema())
    Draft202012Validator.check_schema(evaluation_result_schema())


def test_profile_and_result_roundtrip_with_exact_identities(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile = EvaluationProfile.from_dict(profile_payload)
    result_payload = _result(profile_payload)
    result = EvaluationResult.from_dict(result_payload, profile=profile)

    assert profile.to_dict() == profile_payload
    assert result.to_dict() == result_payload


@pytest.mark.parametrize(
    ("field", "value"),
    [("artifactId", "other-artifact"), ("kind", "adapter"), ("version", "9.9.9")],
)
def test_result_requires_the_complete_installed_artifact_identity(tmp_path: Path, field: str, value: str) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    result["artifactIdentity"][field] = value  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="not installed"):
        EvaluationResult.from_dict(result, profile=profile)


@pytest.mark.parametrize(
    ("started", "finished", "error"),
    [
        ("not-a-time", "2026-09-23T12:00:01Z", "RFC3339"),
        ("2026-09-23T12:00:00", "2026-09-23T12:00:01Z", "RFC3339"),
        ("2026-09-23T12:00:02Z", "2026-09-23T12:00:01Z", "precede"),
        ("2026-09-23T12:00:00Z", "2026-09-23T12:01:01Z", "maxDurationSeconds"),
    ],
)
def test_result_timestamps_are_zoned_ordered_and_bounded(
    tmp_path: Path, started: str, finished: str, error: str
) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    result["startedAt"] = started
    result["finishedAt"] = finished
    with pytest.raises(EvaluationContractError, match=error):
        EvaluationResult.from_dict(result, profile=profile)


@pytest.mark.parametrize("fraction", ["1", "123456789"])
def test_result_accepts_rfc3339_fractional_seconds(tmp_path: Path, fraction: str) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    result["startedAt"] = f"2026-09-23T12:00:00.{fraction}Z"
    result["finishedAt"] = "2026-09-23T12:00:01Z"
    EvaluationResult.from_dict(result, profile=profile)


def test_result_cannot_omit_a_profile_capability(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile_payload["expectedCapabilities"].append({"capabilityId": "synthetic.shell", "expectedAction": "block"})
    with pytest.raises(EvaluationContractError, match="cover exactly"):
        EvaluationResult.from_dict(_result(profile_payload), profile=EvaluationProfile.from_dict(profile_payload))


def test_evaluation_validation_errors_do_not_echo_caller_values(tmp_path: Path) -> None:
    marker = "synthetic-secret-marker"
    profile = _profile(tmp_path)

    invalid_schema = _result(profile)
    invalid_schema["status"] = marker
    with pytest.raises(EvaluationContractError) as schema_error:
        EvaluationResult.from_dict(invalid_schema, profile=profile)
    assert marker not in "".join(traceback.format_exception(schema_error.value))

    duplicate_case = _result(profile)
    duplicate_case["cases"][0]["caseId"] = marker  # type: ignore[index]
    duplicate_case["cases"].append(copy.deepcopy(duplicate_case["cases"][0]))  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="duplicate result caseId") as duplicate_error:
        EvaluationResult.from_dict(duplicate_case, profile=profile)
    assert marker not in "".join(traceback.format_exception(duplicate_error.value))

    invalid_pass = _result(profile)
    invalid_pass["cases"][0]["caseId"] = marker  # type: ignore[index]
    invalid_pass["cases"][0]["expectedAction"] = "unsupported"  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="requires executed proof") as passed_error:
        EvaluationResult.from_dict(invalid_pass, profile=profile)
    assert marker not in "".join(traceback.format_exception(passed_error.value))


def test_evidence_package_is_reproducible_and_keeps_caller_proof_unverified(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    first = build_evaluation_evidence_package(profile, result)
    second = build_evaluation_evidence_package(profile, result)

    assert first == second
    manifest = verify_evaluation_evidence_package(first)
    assert manifest["profileId"] == profile["profileId"]
    assert manifest["resultId"] == result["resultId"]
    assert manifest["proofBoundary"] == "caller_supplied_unverified"


def test_evidence_package_verification_accepts_another_hosts_absolute_paths(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    root = r"C:\Users\Evaluator\AppData\Local\Temp\hol-guard-eval"
    profile["targetScope"]["rootPath"] = root  # type: ignore[index]
    profile["targetScope"]["allowedPaths"] = [root + r"\workspace"]  # type: ignore[index]
    result["cases"][0]["witness"]["path"] = root + r"\workspace\sentinel"  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="temporary"):
        validate_evaluation_profile(profile)
    validate_evaluation_profile(profile, portable=True)
    validate_evaluation_result(result, profile, portable=True)

    packaged = evidence_package_module._package_bytes(profile, result)
    assert verify_evaluation_evidence_package(packaged)["profileId"] == profile["profileId"]


def test_windows_temporary_path_check_rejects_a_junction_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolved(path: str) -> str:
        return r"D:\outside\sentinel" if path.startswith(r"C:\Temp\junction") else path

    monkeypatch.setattr(contracts_module, "os", SimpleNamespace(name="nt", path=SimpleNamespace(realpath=resolved)))
    monkeypatch.setattr(contracts_module.tempfile, "gettempdir", lambda: r"C:\Temp")
    assert contracts_module._is_windows_temp_path(r"C:\Temp\private")
    assert not contracts_module._is_windows_temp_path(r"C:\Temp\junction\sentinel")


def test_evidence_package_rejects_tampering_and_output_limit(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    packaged = build_evaluation_evidence_package(profile, result)
    corrupted = bytearray(packaged)
    index = corrupted.index(b"synthetic-local-v1")
    corrupted[index] = ord("x")
    with pytest.raises(EvaluationContractError, match=r"could not be read|manifest does not match"):
        verify_evaluation_evidence_package(bytes(corrupted))

    encrypted = bytearray(packaged)
    local_header = encrypted.find(b"PK\x03\x04")
    central_header = encrypted.find(b"PK\x01\x02")
    assert local_header >= 0 and central_header >= 0
    encrypted[local_header + 6] |= 1
    encrypted[central_header + 8] |= 1
    with pytest.raises(EvaluationContractError, match="could not be read"):
        verify_evaluation_evidence_package(bytes(encrypted))

    limits = profile["resourceLimits"]
    assert isinstance(limits, dict)
    limits["maxOutputBytes"] = 32
    with pytest.raises(EvaluationContractError, match="exceeds the declared output limit"):
        build_evaluation_evidence_package(profile, result)


def test_evidence_package_rejects_deeply_nested_json_with_contract_error() -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("profile.json", b"[" * 2000)
        archive.writestr("result.json", b"{}")
        archive.writestr("manifest.json", b"{}")

    with pytest.raises(EvaluationContractError, match="could not be read"):
        verify_evaluation_evidence_package(output.getvalue())


def test_evidence_package_write_is_private_and_never_overwrites(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    root = Path(profile["targetScope"]["rootPath"])  # type: ignore[index]
    root.mkdir(mode=0o700)
    unrelated = root / "user-config.json"
    unrelated.write_bytes(b"preserve")

    saved = write_evaluation_evidence_package(profile, result, output_dir=root)
    assert saved.path.is_file()
    assert saved.path.read_bytes() == build_evaluation_evidence_package(profile, result)
    assert saved.digest.startswith("sha256:")
    if os.name != "nt":
        assert stat.S_IMODE(saved.path.stat().st_mode) == 0o600
    with pytest.raises(EvaluationContractError, match="without overwriting"):
        write_evaluation_evidence_package(profile, result, output_dir=root)
    assert unrelated.read_bytes() == b"preserve"

    other = tmp_path / "different-private-root"
    other.mkdir(mode=0o700)
    with pytest.raises(EvaluationContractError, match="profile's private temporary root"):
        write_evaluation_evidence_package(profile, result, output_dir=other)
    assert unrelated.read_bytes() == b"preserve"


def test_evidence_package_failed_write_removes_only_its_incomplete_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    root = Path(profile["targetScope"]["rootPath"])  # type: ignore[index]
    root.mkdir(mode=0o700)
    unrelated = root / "user-config.json"
    unrelated.write_bytes(b"preserve")

    def fail_sync(_descriptor: int) -> None:
        raise OSError("synthetic sync failure")

    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_evidence_package.os.fsync", fail_sync)
    with pytest.raises(EvaluationContractError, match="unable to write"):
        write_evaluation_evidence_package(profile, result, output_dir=root)
    assert list(root.glob("hol-guard-eval-evidence-*.zip")) == []
    assert unrelated.read_bytes() == b"preserve"


@pytest.mark.skipif(os.name == "nt", reason="directory descriptor writes require POSIX")
def test_evidence_package_rejects_a_root_swapped_to_a_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    profile = _profile(tmp_path)
    result = _result(profile)
    root = Path(profile["targetScope"]["rootPath"])  # type: ignore[index]
    root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    backup = tmp_path / "original-root"
    original_open = os.open

    def swap_before_open(
        path: str | os.PathLike[str], flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if Path(path) == root:
            root.rename(backup)
            root.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_evidence_package.os.open", swap_before_open)
    with pytest.raises(EvaluationContractError, match="unable to write"):
        write_evaluation_evidence_package(profile, result, output_dir=root)
    assert list(outside.iterdir()) == []
    assert backup.is_dir()


def test_passed_result_requires_a_profile_for_coverage(tmp_path: Path) -> None:
    with pytest.raises(EvaluationContractError, match="requires the evaluation profile"):
        EvaluationResult.from_dict(_result(_profile(tmp_path)))


def test_passed_enforcement_requires_live_host_witness(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile_payload["expectedCapabilities"][0]["expectedAction"] = "block"
    result_payload = _result(profile_payload)
    result_payload["cases"][0]["expectedAction"] = "block"
    result_payload["cases"][0]["observedAction"] = "block"
    result_payload["cases"][0]["witness"] = {"kind": "none"}
    profile = EvaluationProfile.from_dict(profile_payload)
    with pytest.raises(EvaluationContractError, match="live installed host"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["evidenceIdentity"]["evidenceType"] = "live_installed_host_test"
    result_payload["cases"][0]["proofType"] = "live_installed_host_test"
    with pytest.raises(EvaluationContractError, match="distinct denied and allowed witnesses"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    root = Path(profile_payload["targetScope"]["rootPath"])  # type: ignore[index]
    result_payload["cases"][0]["witness"] = {  # type: ignore[index]
        "kind": "local_file",
        "path": str(root / "workspace" / "denied"),
    }
    with pytest.raises(EvaluationContractError, match="distinct denied and allowed witnesses"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["cases"][0]["witness"]["allowedPath"] = str(root / "workspace" / "denied")  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="distinct denied and allowed witnesses"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["cases"][0]["witness"]["allowedPath"] = str(root / "workspace") + "/./denied"  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="distinct denied and allowed witnesses"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["cases"][0]["witness"]["allowedPath"] = str(root / "workspace" / "allowed")  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="ready receiver"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["cases"][0]["witness"].update(  # type: ignore[index]
        {"receiverReady": True, "deniedReached": False, "allowedReached": True}
    )
    EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["cases"][0]["witness"]["allowedPath"] = str(root / "outside" / "allowed")  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="outside the profile target scope"):
        EvaluationResult.from_dict(result_payload, profile=profile)


@pytest.mark.parametrize(
    "field,value",
    [
        ("receiverReady", False),
        ("deniedReached", True),
        ("allowedReached", False),
    ],
)
def test_passed_enforcement_rejects_failed_receiver_observation(tmp_path: Path, field: str, value: bool) -> None:
    profile_payload = _profile(tmp_path)
    profile_payload["expectedCapabilities"][0]["expectedAction"] = "block"  # type: ignore[index]
    result_payload = _result(profile_payload)
    result_payload["evidenceIdentity"]["evidenceType"] = "live_installed_host_test"  # type: ignore[index]
    root = Path(profile_payload["targetScope"]["rootPath"])  # type: ignore[index]
    result_payload["cases"][0].update(  # type: ignore[index]
        {
            "expectedAction": "block",
            "observedAction": "block",
            "proofType": "live_installed_host_test",
            "witness": {
                "kind": "local_file",
                "path": str(root / "workspace" / "denied"),
                "allowedPath": str(root / "workspace" / "allowed"),
                "receiverReady": True,
                "deniedReached": False,
                "allowedReached": True,
            },
        }
    )
    result_payload["cases"][0]["witness"][field] = value  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="ready receiver"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_passed_enforcement_rejects_equivalent_loopback_urls(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    profile_payload["expectedCapabilities"][0]["expectedAction"] = "block"
    result_payload = _result(profile_payload)
    result_payload["evidenceIdentity"]["evidenceType"] = "live_installed_host_test"
    case = result_payload["cases"][0]
    case.update(
        {
            "expectedAction": "block",
            "observedAction": "block",
            "proofType": "live_installed_host_test",
            "witness": {
                "kind": "loopback_receiver",
                "endpoint": "http://127.0.0.1:8765/receiver",
                "allowedEndpoint": "http://127.0.0.1:8765/receiver/",
            },
        }
    )
    with pytest.raises(EvaluationContractError, match="distinct denied and allowed witnesses"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_result_summary_counts_must_match_cases(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["summary"] = {
        "passed": 2,
        "failed": 0,
        "unsupported": 0,
        "blockedEnvironment": 0,
        "notRun": 0,
    }
    profile = EvaluationProfile.from_dict(profile_payload)
    with pytest.raises(EvaluationContractError, match="summary does not match"):
        EvaluationResult.from_dict(result_payload, profile=profile)
    result_payload["summary"]["passed"] = 1
    EvaluationResult.from_dict(result_payload, profile=profile)


def test_unknown_profile_fields_are_rejected(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    payload["unexpected"] = "must not be accepted"

    with pytest.raises(ValidationError):
        Draft202012Validator(evaluation_profile_schema()).validate(payload)
    with pytest.raises(EvaluationContractError, match="evaluation profile is invalid"):
        validate_evaluation_profile(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        (
            "targetScope",
            {
                "rootPath": "/Users/not-a-temp-root",
                "allowedPaths": ["/Users/not-a-temp-root"],
                "allowedEndpoints": ["http://127.0.0.1:8765"],
            },
        ),
        ("network", {"mode": "local_only", "allowedEndpoints": ["https://example.invalid/receiver"], "proxyUrl": None}),
    ],
)
def test_unsafe_scope_is_rejected_by_schema_and_runtime(
    tmp_path: Path,
    field: str,
    value: dict[str, object],
) -> None:
    payload = _profile(tmp_path)
    payload[field] = value

    with pytest.raises(ValidationError):
        Draft202012Validator(evaluation_profile_schema()).validate(payload)
    with pytest.raises(EvaluationContractError):
        validate_evaluation_profile(payload)


def test_absolute_path_escape_is_rejected_even_inside_tmp_prefix(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    root = Path(payload["targetScope"]["rootPath"])  # type: ignore[index]
    payload["targetScope"]["allowedPaths"] = [str(root / ".." / "outside")]  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="remain under"):
        validate_evaluation_profile(payload)


def test_temp_parent_itself_cannot_be_the_disposable_scope(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    payload["targetScope"]["rootPath"] = "/tmp"  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="temporary test root"):
        validate_evaluation_profile(payload)


def test_foreign_windows_temp_path_is_rejected_on_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX validation boundary")
    payload = _profile(tmp_path)
    scope = payload["targetScope"]  # type: ignore[assignment]
    scope["rootPath"] = r"C:\Users\tester\AppData\Local\Temp\evaluation"
    scope["allowedPaths"] = [r"C:\Users\tester\AppData\Local\Temp\evaluation\workspace"]

    with pytest.raises(EvaluationContractError, match="temporary test root"):
        validate_evaluation_profile(payload)


def test_hostname_endpoint_cannot_rebind_outside_loopback(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    payload["network"]["allowedEndpoints"] = ["http://localhost:8765/receiver"]  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="evaluation profile is invalid"):
        validate_evaluation_profile(payload)


def test_explicit_proxy_must_be_within_declared_target_scope(tmp_path: Path) -> None:
    payload = _profile(tmp_path)
    network = payload["network"]
    assert isinstance(network, dict)
    network["mode"] = "explicit"
    network["proxyUrl"] = "http://127.0.0.1:8766/proxy"
    with pytest.raises(EvaluationContractError, match="proxyUrl must be within"):
        validate_evaluation_profile(payload)
    scope = payload["targetScope"]
    assert isinstance(scope, dict)
    scope["allowedEndpoints"].append(network["proxyUrl"])
    validate_evaluation_profile(payload)


def test_result_witness_must_stay_in_profile_scope(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["cases"][0]["witness"]["endpoint"] = "http://127.0.0.1:8766/other"  # type: ignore[index]

    with pytest.raises(EvaluationContractError, match="outside the profile target scope"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_result_witness_must_be_in_an_allowed_path(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    root = Path(profile_payload["targetScope"]["rootPath"])  # type: ignore[index]
    result_payload["cases"][0]["witness"]["path"] = str(root / "other" / "sentinel")  # type: ignore[index]
    with pytest.raises(EvaluationContractError, match="outside the profile target scope"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_result_status_vocabulary_is_closed(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["status"] = "green"

    with pytest.raises(EvaluationContractError, match="evaluation result is invalid"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


@pytest.mark.parametrize(
    "case_change",
    [
        {"proofType": "not_run"},
        {"observedAction": "block"},
        {"observedAction": None},
        {"expectedAction": "unsupported", "observedAction": "unsupported"},
    ],
)
def test_passed_case_cannot_hide_missing_or_mismatched_proof(tmp_path: Path, case_change: dict[str, object]) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["cases"][0].update(case_change)  # type: ignore[index]
    with pytest.raises(EvaluationContractError):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))


def test_passed_result_cannot_hide_unrun_case(tmp_path: Path) -> None:
    profile_payload = _profile(tmp_path)
    result_payload = _result(profile_payload)
    result_payload["cases"][0].update(  # type: ignore[index]
        {"status": "not_run", "proofType": "not_run", "observedAction": None}
    )
    with pytest.raises(EvaluationContractError, match="unpassed case"):
        EvaluationResult.from_dict(result_payload, profile=EvaluationProfile.from_dict(profile_payload))

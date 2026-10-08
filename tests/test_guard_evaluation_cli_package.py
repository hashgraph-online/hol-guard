from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.evaluation_cli import main
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationContractError
from codex_plugin_scanner.guard.evaluation_evidence_package import (
    EvaluationEvidencePackageError,
    build_evaluation_evidence_package,
    verify_evaluation_evidence_package,
)

from .evaluation_cli_fixtures import _payload, _result, _write_profile


def test_verify_evidence_reports_canonical_manifest(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result = _result(profile)
    package_path = tmp_path / "evidence.zip"
    package_path.write_bytes(build_evaluation_evidence_package(profile, result))

    status = main(["verify-evidence", str(package_path)])

    payload = _payload(capsys)
    assert status == 0
    assert payload["status"] == "passed"
    assert payload["manifest"]["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]
    assert payload["manifest"]["profileId"] == profile["profileId"]  # type: ignore[index]
    assert profile_path.is_file()


@pytest.mark.parametrize("entry_name", ["profile.json", "result.json", "manifest.json"])
def test_verify_evidence_rejects_duplicate_json_keys_early(tmp_path: Path, entry_name: str) -> None:
    _, _, profile = _write_profile(tmp_path)
    packaged = build_evaluation_evidence_package(profile, _result(profile))
    with zipfile.ZipFile(io.BytesIO(packaged)) as original:
        entries = {name: original.read(name) for name in original.namelist()}
    entries[entry_name] = entries[entry_name].replace(b"{", b'{"duplicate":0,"duplicate":1,', 1)

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name in ("profile.json", "result.json", "manifest.json"):
            archive.writestr(name, entries[name])

    with pytest.raises(EvaluationContractError, match="could not be read"):
        verify_evaluation_evidence_package(output.getvalue())


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_writes_a_private_package_that_verify_can_read(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 0
    assert payload["command"] == "package-evidence"
    assert payload["status"] == "passed"
    package = payload["package"]
    package_path = Path(package["path"])  # type: ignore[index]
    assert package_path.parent == tmp_path
    assert package["digest"].startswith("sha256:")  # type: ignore[index]
    assert package["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]
    assert package_path.is_file()

    verify_status = main(["verify-evidence", str(package_path)])
    verify_payload = _payload(capsys)
    assert verify_status == 0
    assert verify_payload["status"] == "passed"
    assert verify_payload["manifest"]["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]


def test_package_evidence_rejects_mismatched_result_without_echoing_values(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    secret_marker = "private-result-marker"
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile, profile_id=secret_marker)), encoding="utf-8")

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "not_run"
    assert payload["error"] == {"code": "result_invalid", "message": "evaluation result is invalid"}
    assert secret_marker not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


def test_package_evidence_bounds_result_json_before_parsing(tmp_path: Path, capsys) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    secret_marker = b"private-oversized-result-marker"
    result_path = tmp_path / "result.json"
    result_path.write_bytes(b'{"marker":"' + secret_marker + b'","padding":"' + b"x" * (1024 * 1024) + b'"}')

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"] == {
        "code": "result_too_large",
        "message": "evaluation result exceeds the configured input limit",
    }
    assert secret_marker.decode() not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.parametrize(
    ("record", "raw", "expected_code"),
    [
        ("profile", '{"profileId":"one","profileId":"two"}', "profile_json_invalid"),
        ("profile", '{"profileId":NaN}', "profile_json_invalid"),
        ("result", '{"resultId":"one","resultId":"two"}', "result_json_invalid"),
        ("result", '{"resultId":Infinity}', "result_json_invalid"),
    ],
)
def test_package_evidence_rejects_ambiguous_json_records(
    tmp_path: Path, capsys, record: str, raw: str, expected_code: str
) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    if record == "profile":
        profile_path.write_text(raw, encoding="utf-8")
        result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")
    else:
        result_path.write_text(raw, encoding="utf-8")

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["error"]["code"] == expected_code  # type: ignore[index]
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_rejects_overwrite_and_out_of_scope_output(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")
    arguments = [
        "package-evidence",
        "--profile",
        str(profile_path),
        "--result",
        str(result_path),
        "--output-dir",
        str(tmp_path),
    ]

    assert main(arguments) == 0
    first_payload = _payload(capsys)
    package_path = Path(first_payload["package"]["path"])  # type: ignore[index]

    assert main(arguments) == 2
    overwrite_payload = _payload(capsys)
    assert overwrite_payload["status"] == "blocked_environment"
    assert overwrite_payload["error"] == {
        "code": "output_exists",
        "message": "evaluation evidence package already exists",
    }
    assert package_path.is_file()

    outside = tmp_path / "different-private-root"
    outside.mkdir(mode=0o700)
    outside_arguments = [*arguments[:-1], str(outside)]
    assert main(outside_arguments) == 2
    scope_payload = _payload(capsys)
    assert scope_payload["status"] == "blocked_environment"
    assert scope_payload["error"] == {
        "code": "output_scope_invalid",
        "message": "evaluation evidence output is outside the profile private temporary scope",
    }
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_reports_generic_write_failure_without_calling_it_an_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    def fail_sync(_descriptor: int) -> None:
        raise OSError("synthetic permission failure")

    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_evidence_package.os.fsync", fail_sync)
    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"] == {
        "code": "evidence_package_write_failed",
        "message": "evaluation evidence package could not be written safely",
    }
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


def test_package_evidence_uses_typed_failure_code_when_message_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise EvaluationEvidencePackageError("output_exists", "changed diagnostic text")

    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_cli.write_evaluation_evidence_package", fail_write)
    status = main(["package-evidence", str(profile_path), str(result_path), str(tmp_path)])

    payload = _payload(capsys)
    assert status == 2
    assert payload["error"] == {
        "code": "output_exists",
        "message": "evaluation evidence package already exists",
    }
    assert "changed diagnostic text" not in json.dumps(payload)


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_rejects_nonportable_root_before_writing(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    (tmp_path / "nested").mkdir(mode=0o700)
    declared_root = str(tmp_path / "nested" / "..")
    profile["targetScope"]["rootPath"] = declared_root  # type: ignore[index]
    profile["targetScope"]["allowedPaths"] = [str(tmp_path / "workspace")]  # type: ignore[index]
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    status = main(["package-evidence", str(profile_path), str(result_path), str(tmp_path)])

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "failed"
    assert payload["error"] == {
        "code": "evidence_package_invalid",
        "message": "evaluation evidence package is invalid",
    }
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_reports_unpaired_surrogate_without_traceback(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    profile["hostIdentity"]["product"] = "\ud800"  # type: ignore[index]
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    status = main(["package-evidence", str(profile_path), str(result_path), str(tmp_path)])

    payload = _payload(capsys)
    assert status == 2
    assert payload["error"]["code"] == "evidence_package_invalid"  # type: ignore[index]
    assert "\ud800" not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))

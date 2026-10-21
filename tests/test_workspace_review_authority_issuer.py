from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.approval.issue_workspace_review_authority import (
    ENROLLMENT_DOMAIN,
    ROOT_FINGERPRINT_ENV,
    ROOT_PUBLIC_ENV,
    ROOT_SEED_ENV,
    AuthorityIssuerError,
    canonical_json_bytes,
    main,
    sign_request,
    validate_request,
)

ROOT_SEED = bytes([42]) * 32
WORKSPACE_SEED = bytes([9]) * 32
FIXTURE_NOW_MS = 2_000


def _public_key_hex(seed: bytes) -> str:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _environment(seed: bytes = ROOT_SEED) -> dict[str, str]:
    public = bytes.fromhex(_public_key_hex(seed))
    return {
        ROOT_SEED_ENV: seed.hex(),
        ROOT_PUBLIC_ENV: public.hex(),
        ROOT_FINGERPRINT_ENV: hashlib.sha256(public).hexdigest(),
    }


def _request(*, now_ms: int = FIXTURE_NOW_MS) -> dict[str, object]:
    public_key = bytes.fromhex(_public_key_hex(WORKSPACE_SEED))
    return {
        "schema": "guard-native-workspace-review-authority.v1",
        "version": 1,
        "purpose": "cloud_review_team_delegation",
        "key_algorithm": "ed25519",
        "key_id": hashlib.sha256(public_key).hexdigest(),
        "public_key": public_key.hex(),
        "workspace_binding": "1" * 64,
        "device_binding": "2" * 64,
        "installation_binding": "3" * 64,
        "enrollment_generation": 1,
        "previous_key_id": None,
        "scope_contract_version": "guard-native-workspace-review-scope.v1",
        "scope_binding": "4" * 64,
        "issued_at_ms": now_ms - 1_000,
        "expires_at_ms": now_ms + 59_000,
        "status": "active",
    }


def _write_request(path: Path, request: dict[str, object]) -> None:
    _ = path.write_bytes(json.dumps(request).encode("utf-8"))


def _request_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_signature_matches_rust_canonical_fixture() -> None:
    request = _request()
    signed = sign_request(request, now_ms=FIXTURE_NOW_MS, environment=_environment())
    unsigned = validate_request(request, now_ms=FIXTURE_NOW_MS)
    signing_bytes = canonical_json_bytes(unsigned)
    assert hashlib.sha256(signing_bytes).hexdigest() == (
        "df5f21e909cbe2d7f4083b8292cf4fb3b6a29743825c7d74bc871fee1c3bbbf7"
    )
    assert signed["enrollment_signature"] == (
        "aecd796bba8372b95c3b4caef42b1d95885582fc218f037c789dbce58259df31272822ade2ae94f9f6a488b06c5d865b28d4a61fe272e584c01edb9c6633a309"
    )
    root_public = Ed25519PrivateKey.from_private_bytes(ROOT_SEED).public_key()
    root_public.verify(
        bytes.fromhex(str(signed["enrollment_signature"])),
        ENROLLMENT_DOMAIN + signing_bytes,
    )


def test_duplicate_and_unknown_fields_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    _ = duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
    assert main(["--request", str(duplicate), "--validate-only"]) == 1

    unknown = _request()
    unknown["unexpected"] = True
    with pytest.raises(AuthorityIssuerError):
        _ = validate_request(unknown, now_ms=FIXTURE_NOW_MS)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("workspace_binding", "not-a-digest"),
        ("device_binding", "3" * 64),
        ("scope_binding", "A" * 64),
        ("issued_at_ms", 0),
        ("expires_at_ms", FIXTURE_NOW_MS - 1),
        ("issued_at_ms", FIXTURE_NOW_MS + 1),
        ("enrollment_generation", 0),
        ("version", True),
        ("issued_at_ms", 1 << 53),
    ],
)
def test_invalid_bindings_times_and_generation_are_rejected(name: str, value: object) -> None:
    request = _request()
    request[name] = value
    with pytest.raises(AuthorityIssuerError):
        _ = validate_request(request, now_ms=FIXTURE_NOW_MS)


def test_rotation_and_revocation_shape_matches_runtime_rules() -> None:
    request = _request()
    request["enrollment_generation"] = 2
    with pytest.raises(AuthorityIssuerError):
        _ = validate_request(request, now_ms=FIXTURE_NOW_MS)

    request["previous_key_id"] = "5" * 64
    _ = validate_request(request, now_ms=FIXTURE_NOW_MS)

    request["status"] = "revoked"
    request["previous_key_id"] = None
    _ = validate_request(request, now_ms=FIXTURE_NOW_MS)

    request["previous_key_id"] = "5" * 64
    with pytest.raises(AuthorityIssuerError):
        _ = validate_request(request, now_ms=FIXTURE_NOW_MS)


def test_root_public_pin_and_fingerprint_are_both_required() -> None:
    request = _request()
    environment = _environment()
    environment[ROOT_PUBLIC_ENV] = _public_key_hex(bytes([7]) * 32)
    with pytest.raises(AuthorityIssuerError):
        _ = sign_request(request, now_ms=FIXTURE_NOW_MS, environment=environment)

    environment = _environment()
    environment[ROOT_FINGERPRINT_ENV] = "0" * 64
    with pytest.raises(AuthorityIssuerError):
        _ = sign_request(request, now_ms=FIXTURE_NOW_MS, environment=environment)


def test_validate_only_needs_no_root_environment_and_does_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now_ms = int(time.time() * 1000)
    request = _request(now_ms=now_ms)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, request)
    for name in (ROOT_SEED_ENV, ROOT_PUBLIC_ENV, ROOT_FINGERPRINT_ENV):
        monkeypatch.delenv(name, raising=False)
    assert main(["--request", str(request_path), "--validate-only"]) == 0
    assert not output_path.exists()


def test_signing_requires_lowercase_expected_request_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, _request(now_ms=int(time.time() * 1000)))
    expected = _request_digest(request_path)

    with pytest.raises(SystemExit) as missing_digest:
        _ = main(["--request", str(request_path), "--output", str(output_path)])
    assert missing_digest.value.code == 2
    assert not output_path.exists()

    assert (
        main(
            [
                "--request",
                str(request_path),
                "--output",
                str(output_path),
                "--expected-request-sha256",
                expected.upper(),
            ]
        )
        == 1
    )
    assert not output_path.exists()
    assert (
        main(
            [
                "--request",
                str(request_path),
                "--output",
                str(output_path),
                "--expected-request-sha256",
                expected,
            ]
        )
        == 0
    )


@pytest.mark.parametrize("failed_stage", ["request validation", "root signing", "output publication"])
def test_failure_reports_only_static_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], failed_stage: str
) -> None:
    from scripts.approval import issue_workspace_review_authority as issuer

    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, _request(now_ms=int(time.time() * 1000)))
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    function = {
        "request validation": "_read_request",
        "root signing": "sign_request",
        "output publication": "_write_new_private",
    }[failed_stage]

    def sensitive_failure(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(ROOT_SEED.hex())

    monkeypatch.setattr(issuer, function, sensitive_failure)
    assert (
        main(
            [
                "--request",
                str(request_path),
                "--output",
                str(output_path),
                "--expected-request-sha256",
                _request_digest(request_path),
            ]
        )
        == 1
    )
    assert capsys.readouterr().err == f"workspace review authority operation rejected during {failed_stage}\n"
    assert not output_path.exists()


@pytest.mark.parametrize(
    ("failure_point", "expected_stage"),
    [
        ("_root_signing_key", "root signing"),
        ("canonical_json_bytes", "root signing"),
        ("_unsigned_signing_bytes", "root signing"),
        ("signature_verification", "root signing"),
    ],
)
def test_sensitive_signing_failures_report_only_static_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure_point: str,
    expected_stage: str,
) -> None:
    from scripts.approval import issue_workspace_review_authority as issuer

    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, _request(now_ms=int(time.time() * 1000)))
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)

    def sensitive_failure(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(ROOT_SEED.hex())

    if failure_point == "signature_verification":

        class FailingVerifier:
            def verify(self, *_args: object, **_kwargs: object) -> None:
                raise RuntimeError(ROOT_SEED.hex())

        class FailingPublicKey:
            @staticmethod
            def from_public_bytes(_value: bytes) -> FailingVerifier:
                return FailingVerifier()

        monkeypatch.setattr(issuer, "Ed25519PublicKey", FailingPublicKey)
    else:
        monkeypatch.setattr(issuer, failure_point, sensitive_failure)

    assert (
        main(
            [
                "--request",
                str(request_path),
                "--output",
                str(output_path),
                "--expected-request-sha256",
                _request_digest(request_path),
            ]
        )
        == 1
    )
    error = capsys.readouterr().err
    assert error == f"workspace review authority operation rejected during {expected_stage}\n"
    assert ROOT_SEED.hex() not in error
    assert not output_path.exists()


def test_same_size_request_substitution_fails_expected_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    original = _request(now_ms=int(time.time() * 1000))
    _write_request(request_path, original)
    expected = _request_digest(request_path)
    original_size = request_path.stat().st_size
    original["workspace_binding"] = "9" * 64
    _write_request(request_path, original)
    assert request_path.stat().st_size == original_size
    args = ["--request", str(request_path), "--output", str(output_path), "--expected-request-sha256"]
    assert main([*args, expected]) == 1
    assert not output_path.exists()
    assert main([*args, _request_digest(request_path)]) == 0


def test_output_is_new_private_file_and_existing_file_is_never_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    now_ms = int(time.time() * 1000)
    request = _request(now_ms=now_ms)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, request)
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    expected = _request_digest(request_path)
    sign_args = [
        "--request",
        str(request_path),
        "--output",
        str(output_path),
        "--expected-request-sha256",
        expected,
    ]
    assert main(sign_args) == 0
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600
    public_bytes = output_path.read_bytes()
    assert ROOT_SEED.hex().encode() not in public_bytes
    decoded: object = cast(object, json.loads(public_bytes))
    assert isinstance(decoded, dict)
    decoded_mapping = cast(dict[object, object], decoded)
    assert decoded_mapping.get("enrollment_signature")

    _ = output_path.write_bytes(b"sentinel")
    assert main(sign_args) == 1
    assert output_path.read_bytes() == b"sentinel"
    assert ROOT_SEED.hex() not in capsys.readouterr().err


def test_fsync_failure_leaves_no_final_and_retry_works(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now_ms = int(time.time() * 1000)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, _request(now_ms=now_ms))
    expected = _request_digest(request_path)
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    sign_args = [
        "--request",
        str(request_path),
        "--output",
        str(output_path),
        "--expected-request-sha256",
        expected,
    ]

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("injected fsync failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_fsync)
        assert main(sign_args) == 1
    assert not output_path.exists()
    assert not list(tmp_path.glob(f".{output_path.name}.*.tmp"))
    assert main(sign_args) == 0


@pytest.mark.skipif(os.name == "nt", reason="symlink permissions vary on Windows")
def test_temp_symlink_substitution_during_link_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now_ms = int(time.time() * 1000)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    attacker_target = tmp_path / "attacker-target"
    _write_request(request_path, _request(now_ms=now_ms))
    _ = attacker_target.write_bytes(b"attacker-target")
    expected = _request_digest(request_path)
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    original_link = os.link
    replaced: list[Path] = []

    def replace_temp_with_symlink(source: Path, destination: Path, *, follow_symlinks: bool = True) -> None:
        source_path = Path(source)
        replaced.append(source_path)
        source_path.unlink()
        source_path.symlink_to(attacker_target)
        original_link(source_path, destination, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "link", replace_temp_with_symlink)
    result = main(
        [
            "--request",
            str(request_path),
            "--output",
            str(output_path),
            "--expected-request-sha256",
            expected,
        ]
    )
    assert result == 1
    assert not output_path.exists()
    assert attacker_target.read_bytes() == b"attacker-target"
    assert replaced and replaced[0].is_symlink()


def test_temp_regular_file_substitution_during_link_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now_ms = int(time.time() * 1000)
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "authority.json"
    _write_request(request_path, _request(now_ms=now_ms))
    expected = _request_digest(request_path)
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    original_link = os.link
    replaced: list[Path] = []
    attacker_bytes = b"attacker-regular-file"

    def replace_temp_with_regular_file(source: Path, destination: Path, *, follow_symlinks: bool = True) -> None:
        source_path = Path(source)
        replaced.append(source_path)
        source_path.unlink()
        _ = source_path.write_bytes(attacker_bytes)
        original_link(source_path, destination, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "link", replace_temp_with_regular_file)
    result = main(
        [
            "--request",
            str(request_path),
            "--output",
            str(output_path),
            "--expected-request-sha256",
            expected,
        ]
    )
    assert result == 1
    assert not output_path.exists()
    assert replaced and replaced[0].read_bytes() == attacker_bytes


@pytest.mark.skipif(os.name == "nt", reason="symlink permissions vary on Windows")
def test_input_and_output_symlinks_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    now_ms = int(time.time() * 1000)
    request = _request(now_ms=now_ms)
    source = tmp_path / "request.json"
    _write_request(source, request)
    input_link = tmp_path / "request-link.json"
    input_link.symlink_to(source)
    assert main(["--request", str(input_link), "--validate-only"]) == 1

    request_path = tmp_path / "request-valid.json"
    _write_request(request_path, request)
    for name, value in _environment().items():
        monkeypatch.setenv(name, value)
    output_target = tmp_path / "authority-target.json"
    _ = output_target.write_bytes(b"keep")
    output_link = tmp_path / "authority-link.json"
    output_link.symlink_to(output_target)
    assert (
        main(
            [
                "--request",
                str(request_path),
                "--output",
                str(output_link),
                "--expected-request-sha256",
                _request_digest(request_path),
            ]
        )
        == 1
    )
    assert output_target.read_bytes() == b"keep"

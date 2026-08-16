from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import utils

from codex_plugin_scanner.guard.mdm import device_key_native
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _canonical_claims(**changes: object) -> bytes:
    claims: dict[str, object] = {
        "schemaVersion": "hol-guard-health-lease.v1",
        "workspaceId": "workspace-1",
        "deviceId": "device-1",
        "machineInstallationId": "a" * 32,
        "installationGeneration": "b" * 32,
        "sequence": 1,
        "issuedAt": "2026-07-18T12:00:00Z",
        "leaseExpiresAt": "2026-07-18T12:05:00Z",
        "snapshotSchemaVersion": "local-integrity-snapshot.v1",
        "snapshotDigest": "c" * 64,
        "previousLeaseDigest": None,
        "previousLeaseKeyId": None,
        "signingKeyId": "A" * 43,
    }
    claims.update(changes)
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()


def _successful_result(signature: bytes) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["helper"],
        0,
        json.dumps(
            {
                "ok": True,
                "signature": base64.b64encode(signature).decode(),
                "signatureAlgorithm": "ecdsa-p256-sha256",
                "signatureEncoding": "asn1-der",
            }
        ),
        "",
    )


def _canonical_protection_lease(**changes: object) -> bytes:
    claims: dict[str, object] = {
        "workspaceId": "workspace-1",
        "deviceId": "device-1",
        "machineInstallationId": "a" * 32,
        "installationGeneration": "b" * 32,
        "sequence": 1,
        "issuedAt": "2026-07-18T12:00:00Z",
        "validForSeconds": 900,
        "snapshotSchemaVersion": "local-integrity-snapshot.v1",
        "snapshotDigest": "c" * 64,
        "previousLeaseDigest": None,
        "signingKeyId": "A" * 43,
        "challenge": None,
    }
    claims.update(changes)
    return json.dumps(
        {"claims": claims, "schemaVersion": "protection-lease.v1"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def test_protection_lease_signing_uses_distinct_purpose_bound_native_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signature = utils.encode_dss_signature(1, 2)
    run = Mock(return_value=_successful_result(signature))
    monkeypatch.setattr(device_key_native.subprocess, "run", run)
    lease = _canonical_protection_lease()

    result = device_key_native.sign_protection_lease(_paths(tmp_path), "d" * 32, lease, system_name="Darwin")

    assert result.signature == signature
    assert run.call_args.args[0] == [
        str(tmp_path / "runtime" / "hol-guard-device-key"),
        "sign-protection-lease",
        "d" * 32,
    ]
    assert run.call_args.kwargs["input"] == lease.decode()


def test_health_key_registration_signing_uses_distinct_purpose_bound_native_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signature = utils.encode_dss_signature(1, 2)
    run = Mock(return_value=_successful_result(signature))
    monkeypatch.setattr(device_key_native.subprocess, "run", run)
    registration = json.dumps(
        {
            "algorithm": "ecdsa-p256-sha256",
            "deviceId": "device-1",
            "installationGeneration": "b" * 32,
            "keyId": "A" * 43,
            "machineInstallationId": "a" * 32,
            "previousInstallationGeneration": None,
            "publicKeySpki": base64.b64encode(b"public-key").decode(),
            "registeredAt": "2026-07-18T12:00:00Z",
            "schemaVersion": "hol-guard-health-key-registration.v1",
            "workspaceId": "workspace-1",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    result = device_key_native.sign_health_key_registration(
        _paths(tmp_path), "d" * 32, registration, system_name="Darwin"
    )

    assert result.signature == signature
    assert run.call_args.args[0] == [
        str(tmp_path / "runtime" / "hol-guard-device-key"),
        "sign-health-key-registration",
        "d" * 32,
    ]


def test_health_lease_signing_uses_only_purpose_bound_native_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signature = utils.encode_dss_signature(1, 2)
    run = Mock(return_value=_successful_result(signature))
    monkeypatch.setattr(device_key_native.subprocess, "run", run)
    claims = _canonical_claims()

    result = device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, claims, system_name="Darwin")

    assert result.signature == signature
    assert result.algorithm == "ecdsa-p256-sha256"
    assert result.encoding == "asn1-der"
    assert run.call_args.args[0] == [
        str(tmp_path / "runtime" / "hol-guard-device-key"),
        "sign-health-lease",
        "d" * 32,
    ]
    assert run.call_args.kwargs["input"] == claims.decode()
    with pytest.raises(ValueError, match="device_key_request_invalid"):
        device_key_native.run_helper(_paths(tmp_path), "sign", "d" * 32, system_name="Darwin")


def test_health_lease_signing_accepts_uint64_sequence_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    signature = utils.encode_dss_signature(1, 2)
    monkeypatch.setattr(device_key_native.subprocess, "run", Mock(return_value=_successful_result(signature)))
    claims = _canonical_claims(
        sequence=(1 << 64) - 1,
        previousLeaseDigest="e" * 64,
        previousLeaseKeyId="B" * 43,
    )

    result = device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, claims, system_name="Darwin")

    assert result.signature == signature


@pytest.mark.parametrize(
    "claims",
    [
        b"x" * 4097,
        _canonical_claims(unexpected=True),
        b'{"schemaVersion":"hol-guard-health-lease.v1"}',
        _canonical_claims() + b"\n",
    ],
)
def test_health_lease_signing_rejects_oversized_unknown_or_noncanonical_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claims: bytes
) -> None:
    run = Mock()
    monkeypatch.setattr(device_key_native.subprocess, "run", run)

    with pytest.raises(ValueError, match="health_lease_claims_invalid"):
        device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, claims, system_name="Darwin")

    run.assert_not_called()


@pytest.mark.parametrize(
    "claims",
    [
        _canonical_claims(workspaceId=""),
        _canonical_claims(deviceId="contains a space"),
        _canonical_claims(sequence=0),
        _canonical_claims(sequence=True),
        _canonical_claims(issuedAt="2026-02-30T12:00:00Z"),
        _canonical_claims(leaseExpiresAt="2026-07-18T13:00:01Z"),
        _canonical_claims(snapshotSchemaVersion="hol-guard-local-integrity.v1"),
        _canonical_claims(signingKeyId="short"),
    ],
)
def test_health_lease_signing_revalidates_claim_values_before_native_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claims: bytes
) -> None:
    run = Mock()
    monkeypatch.setattr(device_key_native.subprocess, "run", run)

    with pytest.raises(ValueError, match="health_lease_claims_invalid"):
        device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, claims, system_name="Darwin")

    run.assert_not_called()


@pytest.mark.parametrize(
    "response_mutation",
    [
        {"extra": True},
        {"signatureAlgorithm": "ecdsa-p256"},
        {"signatureEncoding": "p1363"},
        {"signature": "not-base64"},
    ],
)
def test_health_lease_signing_rejects_noncontractual_helper_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response_mutation: dict[str, object]
) -> None:
    payload: dict[str, object] = {
        "ok": True,
        "signature": base64.b64encode(utils.encode_dss_signature(1, 2)).decode(),
        "signatureAlgorithm": "ecdsa-p256-sha256",
        "signatureEncoding": "asn1-der",
    }
    payload.update(response_mutation)
    monkeypatch.setattr(
        device_key_native.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess(["helper"], 0, json.dumps(payload), "")),
    )

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, _canonical_claims(), system_name="Darwin")


def test_health_lease_signing_rejects_oversized_helper_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        device_key_native.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess(["helper"], 0, "x" * (16 * 1024 + 1), "")),
    )

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, _canonical_claims(), system_name="Darwin")


@pytest.mark.parametrize(
    "signature",
    [
        b"\x30\x06\x02\x01\x01\x02\x01\x02\x00",
        b"\x30\x07\x02\x02\x00\x01\x02\x01\x02",
        utils.encode_dss_signature(0, 2),
    ],
)
def test_health_lease_signing_rejects_noncanonical_or_out_of_range_der(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signature: bytes
) -> None:
    monkeypatch.setattr(device_key_native.subprocess, "run", Mock(return_value=_successful_result(signature)))

    with pytest.raises(OSError, match="device_key_probe_failed"):
        device_key_native.sign_health_lease(_paths(tmp_path), "d" * 32, _canonical_claims(), system_name="Darwin")


def test_native_helpers_bind_health_lease_domain_and_exact_claim_contract() -> None:
    macos = Path("scripts/mdm/macos/device-key-helper.swift").read_text(encoding="utf-8")
    windows = Path("scripts/mdm/windows/device-key-helper.ps1").read_text(encoding="utf-8")

    for source in (macos, windows):
        assert "HOL-GUARD-HEALTH-LEASE-V1" in source
        assert "hol-guard-health-lease.v1" in source
        assert "local-integrity-snapshot.v1" in source
        assert "sign-health-lease" in source
        assert "sign-message" not in source
        assert "sign-digest" not in source
    assert "ecdsaSignatureMessageX962SHA256" in macos
    assert "SHA256.hash(data: spkiPrefix + publicKeyX963)" in macos
    assert "claimedSigningKeyId == expectedSigningKeyId" in macos
    assert "Convert-P1363ToDer" in windows
    assert "Get-SigningKeyId $PublicKey" in windows
    assert "$Claims.signingKeyId -ne $ExpectedSigningKeyId" in windows


@pytest.mark.skipif(os.name != "nt", reason="PowerShell helper conversion requires Windows")
@pytest.mark.parametrize(
    ("r", "s"),
    [
        (1, 1),
        (0x7F, 0x80 << 248),
        (0x80, (1 << 256) - 1),
    ],
)
def test_windows_p1363_to_der_conversion_vectors(r: int, s: int) -> None:
    powershell = Path(os.environ["SYSTEMROOT"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    helper = Path("scripts/mdm/windows/device-key-helper.ps1").resolve()
    p1363 = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    program = (
        "$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors);"
        "$fn=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Convert-P1363ToDer'},$true);"
        "Invoke-Expression $fn.Extent.Text;"
        "$raw=[Convert]::FromBase64String($args[1]);"
        "[Convert]::ToBase64String((Convert-P1363ToDer $raw))"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            program,
            str(helper),
            base64.b64encode(p1363).decode(),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert base64.b64decode(result.stdout.strip(), validate=True) == utils.encode_dss_signature(r, s)

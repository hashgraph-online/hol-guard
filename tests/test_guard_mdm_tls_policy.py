from __future__ import annotations

import ast
import hashlib
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from codex_plugin_scanner.guard.mdm import network_trust as trust_module
from codex_plugin_scanner.guard.mdm.contracts import ManagedNetworkPolicy
from codex_plugin_scanner.guard.mdm.network import managed_ssl_context

ROOT = Path(__file__).parents[1]
GUARD_SOURCE = ROOT / "src" / "codex_plugin_scanner" / "guard"


def _test_ca() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HOL Guard synthetic unmanaged CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        certificate.public_bytes(serialization.Encoding.DER),
    )


def _trusted_fingerprints(context: ssl.SSLContext) -> set[str]:
    certificates = context.get_ca_certs(binary_form=True)
    return {hashlib.sha256(certificate).hexdigest() for certificate in certificates}


def test_shell_ca_overrides_are_ignored_but_managed_ca_is_additive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pem, der = _test_ca()
    ambient_bundle = tmp_path / "ambient-ca.pem"
    ambient_bundle.write_bytes(pem)
    ambient_bundle.chmod(0o600)
    monkeypatch.setattr(trust_module, "machine_controlled_file_is_trusted", lambda path: path == ambient_bundle)
    monkeypatch.setenv("SSL_CERT_FILE", str(ambient_bundle))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "ambient-ca-dir"))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ambient_bundle))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(ambient_bundle))
    fingerprint = hashlib.sha256(der).hexdigest()

    unmanaged_context = managed_ssl_context(ManagedNetworkPolicy(proxy_mode="none"))
    assert fingerprint not in _trusted_fingerprints(unmanaged_context)

    approved_context = managed_ssl_context(ManagedNetworkPolicy(proxy_mode="none", ca_bundle_path=str(ambient_bundle)))
    assert fingerprint in _trusted_fingerprints(approved_context)
    assert approved_context.check_hostname is True


def test_guard_runtime_contains_no_tls_verification_bypass() -> None:
    violations: list[str] = []
    for path in sorted(GUARD_SOURCE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                function = node.func
                if isinstance(function, ast.Attribute) and function.attr == "_create_unverified_context":
                    violations.append(f"{path}: unverified SSL context")
                for keyword in node.keywords:
                    if (
                        keyword.arg == "verify"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False
                    ):
                        violations.append(f"{path}: verify=False")
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    if not isinstance(target, ast.Attribute):
                        continue
                    if target.attr == "check_hostname" and isinstance(value, ast.Constant) and value.value is False:
                        violations.append(f"{path}: check_hostname=False")
                    if target.attr == "verify" and isinstance(value, ast.Constant) and value.value is False:
                        violations.append(f"{path}: verify=False")
                    if target.attr == "verify_mode" and isinstance(value, ast.Attribute) and value.attr == "CERT_NONE":
                        violations.append(f"{path}: CERT_NONE")
    assert violations == []

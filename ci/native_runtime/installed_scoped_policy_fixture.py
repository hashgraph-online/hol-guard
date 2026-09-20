"""Synthetic signed delivery over verified loopback TLS for installed probes.

Enrollment and the signing trust anchor are fixture inputs. Policy rows,
publication, acknowledgements, runtime capabilities and receipts are not seeded.
This fixture does not establish an ordinary OAuth authorization ceremony.
"""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import secrets
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import pairwise
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.exact_command import exact_command_sha256
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import policy_bundle_verification_key_from_public_key
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CANONICALIZATION,
    POLICY_BUNDLE_V2_CONTRACT,
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
)
from codex_plugin_scanner.guard.store import GuardStore

WORKSPACE = "scoped-installed-synthetic-workspace"
# The review row must raise the current action to prove selected provenance.
# A printf review would merely equal the configured review and select no row.
COMMANDS = {"allow": "printf 'scoped allow'", "block": "printf 'scoped block'", "review": "pwd"}


def _pem(key: rsa.RSAPrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )


class SignedPolicyFixture:
    """Use actual credential and trust storage, with no applied authority."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.workspace = root / "work"
        self.workspace.mkdir(mode=0o700)
        self.store = GuardStore(root / "guard")
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.verification = policy_bundle_verification_key_from_public_key(
            key_id="synthetic-installed-policy", public_key_pem=_pem(self.key), workspace_id=WORKSPACE
        )
        now = datetime.now(timezone.utc).isoformat()
        self.store.set_sync_payload("policy_bundle_keyring", {"keys": [self.verification.to_dict()]}, now)
        dpop = generate_dpop_key_pair()
        (self.store.guard_home / "config.toml").write_text(
            'mode="enforce"\ndefault_action="review"\n[harnesses]\ncodex="review"\n', encoding="utf-8"
        )
        self.bundle: dict[str, object] | None = None
        self.requests = 0
        self.token = secrets.token_urlsafe(32)
        self.ca_file, key_file = self._certificate()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

            def do_POST(self) -> None:
                if not secrets.compare_digest(self.headers.get("Authorization", ""), f"Bearer {fixture.token}"):
                    self.send_error(401)
                    return
                length = self.headers.get("Content-Length", "")
                if not length.isdecimal() or not 0 < int(length) <= 1024 * 1024:
                    self.send_error(400)
                    return
                try:
                    request = json.loads(self.rfile.read(int(length)))
                except (ValueError, UnicodeError):
                    self.send_error(400)
                    return
                if not isinstance(request, dict):
                    self.send_error(400)
                    return
                response = fixture.response_for_request(self.path, request)
                encoded = json.dumps(response, separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.ca_file, key_file)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.store.set_oauth_local_credentials(
            issuer=f"https://127.0.0.1:{self.server.server_port}",
            client_id="guard-local-daemon-local",
            refresh_token=secrets.token_urlsafe(32),
            dpop_private_key_pem=dpop.private_key_pem,
            dpop_public_jwk=dpop.public_jwk,
            dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
            device_id=dpop.public_jwk_thumbprint,
            grant_id="synthetic-installed-grant",
            machine_id="synthetic-installed-machine",
            workspace_id=WORKSPACE,
            now=now,
            access_token=self.token,
            access_token_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def response_for_request(self, path: str, request: dict[str, object]) -> dict[str, object]:
        """Return the bounded synthetic issuer response after authenticated TLS."""
        if path == "/api/guard/review/v2/events:batch":
            # Model only the transport acknowledgement used by the real daemon
            # worker. This fixture does not prove remote event verification.
            events = request.get("events")
            if not isinstance(events, list):
                events = []
            sequences = [event.get("localStreamSequence") if isinstance(event, dict) else None for event in events]
            valid_sequences = [sequence for sequence in sequences if type(sequence) is int and sequence > 0]
            valid = (
                type(request.get("protocolVersion")) is int
                and request["protocolVersion"] == 2
                and bool(events)
                and all(
                    isinstance(event, dict) and isinstance(event.get("eventId"), str) and event["eventId"]
                    for event in events
                )
                and len(valid_sequences) == len(events)
                and all(left < right for left, right in pairwise(valid_sequences))
                and type(request.get("firstSequence")) is int
                and type(request.get("lastSequence")) is int
                and request.get("firstSequence") == valid_sequences[0]
                and request.get("lastSequence") == valid_sequences[-1]
            )
            return {
                "protocolVersion": 2,
                "accepted": len(events) if valid else 0,
                "rejected": 0 if valid else len(events),
                "acknowledgedThrough": sequences[-1] if valid else 0,
                "results": [
                    {
                        "eventId": event.get("eventId") if isinstance(event, dict) else None,
                        "status": "accepted" if valid else "rejected",
                        **({} if valid else {"code": "synthetic_fixture_event_shape_invalid"}),
                    }
                    for event in events
                ],
            }
        if path == "/api/guard/receipts/sync":
            self.requests += 1
            return {
                "syncedAt": datetime.now(timezone.utc).isoformat(),
                "receiptsStored": 0,
                **({"policyBundle": copy.deepcopy(self.bundle)} if self.bundle is not None else {}),
            }
        return {"accepted": 0, "rejected": 0, "statuses": []}

    def _certificate(self) -> tuple[Path, Path]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic installed fixture")])
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False
            )
            .sign(key, hashes.SHA256())
        )
        certificate_file, key_file = self.root / "fixture-ca.pem", self.root / "fixture-key.pem"
        certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        key_file.chmod(0o600)
        return certificate_file, key_file

    def signed_bundle(
        self, version: int, *, workspace: str = WORKSPACE, lifetime: str = "permanent"
    ) -> dict[str, object]:
        now = datetime.now(timezone.utc)
        rules = [
            {
                "id": f"synthetic.{action}",
                "enabled": True,
                "effect": action,
                "match": {
                    "harnesses": ["codex"],
                    "artifacts": ["codex:project:Bash"],
                    "exactCommand": {
                        "contractVersion": "guard.exact-command.v1",
                        "sha256": exact_command_sha256(command),
                    },
                },
                "lifetime": {"mode": lifetime, "expiresAt": None},
                "provenance": {"source": "cloud", "createdAt": now.isoformat().replace("+00:00", "Z")},
            }
            for action, command in COMMANDS.items()
        ]
        result: dict[str, object] = {
            "envelopeVersion": 2,
            "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
            "bundleVersion": version,
            "bundleHash": "",
            "payloadHash": "",
            "issuedAt": now.isoformat().replace("+00:00", "Z"),
            "expiresAt": (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
            "workspaceId": workspace,
            "canonicalization": POLICY_BUNDLE_V2_CANONICALIZATION,
            "verifier": {
                "algorithm": "rsa-pss-sha256",
                "keyId": self.verification.key_id,
                "keyFingerprint": self.verification.fingerprint_sha256,
                "publicKeyPem": self.verification.public_key_pem,
                "signature": "",
            },
            "payload": {
                "apiVersion": "guard.hashgraphonline.com/v1alpha1",
                "kind": "GuardPolicy",
                "metadata": {"id": "synthetic.installed-policy", "name": "Synthetic", "revision": version},
                "spec": {
                    "defaults": {"mode": "enforce", "defaultAction": "warn"},
                    "rolloutState": "enforcing",
                    "rules": rules,
                },
            },
            "rollback": None,
        }
        return self.sign(result)

    def sign(self, result: dict[str, object]) -> dict[str, object]:
        result["payloadHash"] = payload_hash_for_policy_bundle_v2(result)
        result["bundleHash"] = computed_policy_bundle_v2_hash(result)
        verifier = result["verifier"]
        assert isinstance(verifier, dict)
        verifier["signature"] = base64.b64encode(
            self.key.sign(
                canonical_policy_bundle_v2_payload(result),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        ).decode("ascii")
        return result

    @property
    def sync_url(self) -> str:
        return f"https://127.0.0.1:{self.server.server_port}/api/guard/receipts/sync"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("scoped_fixture_cleanup_failed")

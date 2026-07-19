from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import utils

from codex_plugin_scanner.guard.mdm.contracts import MachinePaths
from codex_plugin_scanner.guard.mdm.health_key_registration import build_machine_health_key_registration
from codex_plugin_scanner.guard.mdm.health_lease_contract import HealthLeaseBinding


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(root / "runtime", root / "state", root / "policy", root / "logs", root / "manifest")


def test_machine_health_key_registration_is_canonical_and_proves_possession(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signature = utils.encode_dss_signature(1, 2)
    generation = SimpleNamespace(
        generation="3" * 32,
        key_id="A" * 43,
        public_key_spki=base64.b64encode(b"public-key").decode(),
    )
    signed_payloads: list[bytes] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.health_key_registration.verified_machine_device_key_by_id",
        lambda *_args, **_kwargs: generation,
    )

    def sign(_paths: object, _generation: str, payload: bytes, **_kwargs: object) -> SimpleNamespace:
        signed_payloads.append(payload)
        return SimpleNamespace(signature=signature)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.mdm.device_key_native.sign_health_key_registration",
        sign,
    )

    payload = build_machine_health_key_registration(
        _paths(tmp_path),
        HealthLeaseBinding("workspace-a", "device-a"),
        machine_installation_id="1" * 32,
        installation_generation="2" * 32,
        system_name="Darwin",
    )
    decoded = json.loads(payload)
    proof = decoded.pop("proof")

    assert payload == json.dumps({**decoded, "proof": proof}, sort_keys=True, separators=(",", ":")).encode()
    assert signed_payloads == [json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()]
    assert proof == {
        "algorithm": "ecdsa-p256-sha256",
        "encoding": "asn1-der",
        "value": base64.b64encode(signature).decode(),
    }
    assert decoded["workspaceId"] == "workspace-a"
    assert decoded["deviceId"] == "device-a"
    assert decoded["keyId"] == "A" * 43

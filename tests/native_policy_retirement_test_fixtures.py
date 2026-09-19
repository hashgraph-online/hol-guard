"""Authenticated control peer for tests that already inject native push ACKs.

This is a controlled protocol peer, not an installed resident. Source capture,
Store keys, counter reservation, SQL mutation and publisher invalidation remain
real; no policy/control production validator is replaced.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_control as control
from codex_plugin_scanner.guard import native_policy_snapshot_rotation as rotation
from codex_plugin_scanner.guard.native_policy_snapshot_codec import _canonical_json_bytes_v3 as canonical
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_storage import _read_v3_generation_state, _v3_generation_lock
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus
from codex_plugin_scanner.guard.native_runtime_capabilities import NativeRuntimeCapabilities
from codex_plugin_scanner.guard.store import GuardStore


def authenticated_retirement_peer(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    master, _ = store._policy_integrity_secret_material(create=False)
    assert type(master) is bytes and len(master) == 32
    key = derive_native_policy_verifier_key(master)
    current = _read_v3_generation_state(store.guard_home)
    assert current is not None
    floor, digest = current
    runtime = "a" * 64  # Same identity as the existing injected publisher status.
    status = NativeRuntimeStatus(
        "auto",
        True,
        True,
        "ready",
        NativeRuntimeIdentity(Path("/tmp/hol-guard-runtime"), 1, 1, runtime),
        NativeRuntimeCapabilities(1, "3.0.1", "test", "test", "test", ("policy-snapshot-control-v1",)),
    )
    monkeypatch.setattr(rotation, "_native_policy_control_runtime_status_owned", lambda **kwargs: status)
    operations: list[str] = []

    def client(**kwargs):
        outer = json.loads(kwargs["payload"])
        request, operation = outer["request"], outer["operation"]
        intent = request["intent"]
        observe = operation == "policy_snapshot_observe"
        assert operation in {"policy_snapshot_observe", "policy_snapshot_withdraw"}
        domain = control._OBSERVATION_DOMAIN if observe else control._WITHDRAWAL_DOMAIN
        assert hmac.compare_digest(
            request["mac"], hmac.new(key, domain + canonical(intent), hashlib.sha256).hexdigest()
        )
        assert intent["runtime_identity"] == runtime
        with _v3_generation_lock(store.guard_home, deadline_monotonic=kwargs["deadline_monotonic"]):
            pass
        operations.append(operation)
        common = {
            "runtime_identity": runtime,
            "scope_digest": intent["scope_digest"],
            "resident_generation": 3,
            "request_sha256": hashlib.sha256(canonical(request)).hexdigest(),
        }
        authority = {
            "fingerprint": "b" * 64,
            "generation_floor": floor,
            "policy_digest": digest,
            "usable_snapshot": True,
        }
        if observe:
            response = {
                **common,
                "schema": "guard-policy-snapshot-observation-response.v1",
                "nonce": intent["nonce"],
                "authority": authority,
            }
            response_domain = control._OBSERVATION_RESPONSE_DOMAIN
        else:
            assert intent["expected_authority"] == authority
            assert intent["retirement_generation"] > floor
            reserved = _read_v3_generation_state(store.guard_home)
            assert reserved == (intent["retirement_generation"], intent["retirement_policy_digest"])
            response = {
                **common,
                "schema": "guard-policy-snapshot-withdrawal-response.v1",
                "status": "withdrawn",
                "generation": intent["retirement_generation"],
                "policy_digest": intent["retirement_policy_digest"],
            }
            response_domain = control._WITHDRAWAL_RESPONSE_DOMAIN
        mac = hmac.new(key, response_domain + canonical(response), hashlib.sha256).hexdigest()
        return canonical({"response": response, "mac": mac})

    monkeypatch.setattr(rotation, "_native_policy_control_request_owned", client)
    return operations

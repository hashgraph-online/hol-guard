"""Publish and observe a real expired resident authority in a private fixture."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any, TypedDict

from scripts.native_slo_observation_failure import contextual_failure
from scripts.native_slo_publisher_failure import rejected_starting_snapshot


class _RenewalCommandInputs(TypedDict, total=False):
    command_extensions: Mapping[str, object]


def _renewal_command_inputs(publisher: Any, previous: Mapping[str, object]) -> _RenewalCommandInputs:
    """Preserve accepted controls without adding a schema to the pinned baseline."""
    if "command_extensions" not in previous:
        # Baseline 2e672d2 has no native command-control snapshot field or
        # matching generation-builder parameter. Its absent binding stays absent.
        return {}
    previous_binding = previous["command_extensions"]
    if not isinstance(previous_binding, Mapping):
        raise RuntimeError("expiry fixture acknowledged command binding invalid")
    current = publisher._compiled_command_extensions()
    if current != previous_binding:
        raise RuntimeError("expiry fixture command authority changed before renewal")
    return {"command_extensions": current}


def _authenticated_readback(store: Any) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Read compact binding and full MAC-verified Rust authority independently."""
    from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store
    from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        _RUST_SNAPSHOT_STATE_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
        POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
    )
    from codex_plugin_scanner.guard.native_policy_snapshot_storage import _read_v3_snapshot_file

    binding = acked_snapshot_binding_for_store(store)
    material = store._policy_integrity_secret_material(create=False)
    try:
        if not isinstance(material, tuple) or len(material) != 2 or not isinstance(material[0], bytes):
            raise RuntimeError("expiry fixture readback signing material unavailable")
        accepted = _read_v3_snapshot_file(
            store.guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / _RUST_SNAPSHOT_STATE_NAME,
            verifier_key=derive_native_policy_verifier_key(material[0]),
            maximum_bytes=POLICY_SNAPSHOT_AUTHORITY_MAX_BYTES,
        )
    finally:
        material = None
    return binding, accepted[0] if accepted is not None else None


def _readback_matches(
    binding: Mapping[str, object] | None,
    accepted: Mapping[str, object] | None,
    expected: Mapping[str, object],
) -> bool:
    return (
        binding is not None
        and accepted is not None
        and all(
            binding.get(key) == expected.get(key) for key in ("generation", "policy_digest", "runtime_identity", "mode")
        )
        and all(
            accepted.get(key) == expected.get(key)
            for key in (
                "generation",
                "policy_digest",
                "runtime_identity",
                "mode",
                "issued_at_ms",
                "expires_at_ms",
                "command_extensions",
            )
        )
        and ("command_extensions" in accepted) == ("command_extensions" in expected)
        and binding.get("command_extensions_bound", False) is ("command_extensions" in expected)
    )


def expire_acknowledged_authority(session: Any) -> dict[str, bool]:
    from codex_plugin_scanner.guard.native_hook_edge import _encode_hook_envelope
    from codex_plugin_scanner.guard.native_policy_snapshot_acked import acked_snapshot_binding_for_store
    from codex_plugin_scanner.guard.native_policy_snapshot_contract import _policy_snapshot_push_bytes_v3
    from codex_plugin_scanner.guard.native_policy_snapshot_generation import native_policy_snapshot_v3
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _ack_from_resident_output
    from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
    from codex_plugin_scanner.guard.native_runtime import _isolated_environment, native_runtime_status
    from scripts.native_benchmark_oracle import synthetic_payload

    worker = session.daemon._server.hook_worker
    publisher = worker.policy_snapshot_publisher
    previous = publisher.current_snapshot()
    if previous is None:
        error = RuntimeError("expiry fixture requires an acknowledged starting generation")
        raise contextual_failure(
            error, expiry_stage="starting_authority", publisher_state=rejected_starting_snapshot(publisher)
        ) from error
    starting_binding, starting_accepted = _authenticated_readback(session.store)
    if not _readback_matches(starting_binding, starting_accepted, previous):
        raise RuntimeError("expiry fixture starting authority readback mismatch")
    config = publisher._compiled_effective_policy()
    command_inputs = _renewal_command_inputs(publisher, previous)
    publisher.close()  # Suspend renewal; this alone is not evidence of expiry.
    if publisher._thread is not None and publisher._thread.is_alive():
        raise RuntimeError("expiry fixture could not suspend publication")
    status = native_runtime_status()
    if status.identity is None or status.capabilities is None:
        raise RuntimeError("expiry fixture runtime unavailable")
    material = session.store._policy_integrity_secret_material(create=False)
    if not isinstance(material, tuple) or not isinstance(material[0], bytes):
        raise RuntimeError("expiry fixture signing material unavailable")
    issued = int(time.time() * 1000)
    expires = issued + 3_000
    try:
        snapshot = native_policy_snapshot_v3(
            config=config,
            guard_home=session.guard_home,
            runtime_identity=status.identity.sha256,
            rule_digest=status.capabilities.rule_digest,
            policy_integrity_key=material[0],
            issued_at_ms=issued,
            expires_at_ms=expires,
            renew_after_generation=int(previous["generation"]),
            deadline_monotonic=time.monotonic() + 2.0,
            **command_inputs,
        )
    finally:
        material = None
    if snapshot.get("expires_at_ms") != expires or snapshot["generation"] <= previous["generation"]:
        raise RuntimeError("expiry fixture reused a long-lived generation")
    if any(
        snapshot.get(key) != previous.get(key)
        for key in ("policy_digest", "mode", "runtime_identity", "command_extensions")
    ):
        raise RuntimeError("expiry fixture renewal changed acknowledged authority")
    proof: dict[str, object] = {
        "expiry_stage": "publication",
        "short_lived_ttl_ms": 3_000,
        "policy_preserved": True,
        "control_binding_present": "command_extensions" in previous,
        "control_input_preserved": True,
        "control_binding_preserved": None,
        "starting_authority_authenticated": True,
    }
    try:
        output = native_resident_client_request(
            executable=status.identity.path,
            guard_home=session.guard_home,
            environment=_isolated_environment(),
            payload=_policy_snapshot_push_bytes_v3(snapshot),
            deadline_monotonic=time.monotonic() + 2.0,
        )
        proof["ack_bytes_received"] = bool(output)
        ack = _ack_from_resident_output(output)
        proof["ack_decoded"] = ack is not None
        proof["ack_accepted"] = ack is not None and ack.get("status") == "accepted"
        proof["ack_generation_matches"] = ack is not None and ack.get("generation") == snapshot["generation"]
        proof["ack_digest_matches"] = ack is not None and ack.get("policy_digest") == snapshot["policy_digest"]
        if not all(
            proof[key] for key in ("ack_decoded", "ack_accepted", "ack_generation_matches", "ack_digest_matches")
        ):
            raise RuntimeError("expiry fixture short-lived publication ACK invalid")
        proof["expiry_stage"] = "authenticated_readback"
        binding, accepted = _authenticated_readback(session.store)
        proof["authenticated_binding_present"] = binding is not None
        proof["authenticated_snapshot_present"] = accepted is not None
        proof["authenticated_binding_matches"] = _readback_matches(binding, accepted, snapshot)
        proof["authenticated_controls_match"] = (
            accepted is not None
            and ("command_extensions" in accepted) == ("command_extensions" in snapshot)
            and accepted.get("command_extensions") == snapshot.get("command_extensions")
        )
        proof["control_binding_preserved"] = (
            proof["authenticated_binding_matches"] and proof["authenticated_controls_match"]
        )
        proof["authority_unexpired_at_readback"] = int(time.time() * 1000) < expires
        if (
            binding is None
            or not proof["authenticated_binding_matches"]
            or not proof["authority_unexpired_at_readback"]
        ):
            raise RuntimeError("expiry fixture did not authenticate its short-lived publication")
    except Exception as error:
        # Preserve only fixed resident rejection codes, never arbitrary IPC text.
        if str(error) in {"native_command_control_binding_removed", "snapshot_expired"}:
            proof["native_error"] = str(error)
        raise contextual_failure(error, **proof) from error
    while int(time.time() * 1000) <= expires:
        time.sleep(0.01)
    if acked_snapshot_binding_for_store(session.store) is not None:
        raise RuntimeError("expired resident authority remained valid")
    encoded = _encode_hook_envelope(
        payload=synthetic_payload(0),
        harness="claude-code",
        event="PostToolUse",
        guard_home=session.guard_home,
        home_dir=session.root,
        cwd=session.workspace,
        source_ref_external_allowed=False,
        deadline_budget_ms=1000,
        snapshot=binding,
    )
    if encoded is None:
        raise RuntimeError("expiry probe envelope unavailable")
    rejected = native_resident_client_request(
        executable=status.identity.path,
        guard_home=session.guard_home,
        environment=_isolated_environment(),
        payload=encoded,
        raw_hook_envelope=True,
        deadline_monotonic=time.monotonic() + 1.0,
    )
    response = json.loads(rejected) if rejected else None
    if (
        not isinstance(response, dict)
        or response.get("error") != "snapshot_expired"
        or not set(response) <= {"error", "retryable"}
        or ("retryable" in response and not isinstance(response["retryable"], bool))
    ):
        raise RuntimeError("resident did not explicitly reject the expired authority")
    prepared = worker.prepare_workspace_policy(session.workspace, deadline=time.monotonic() + 0.4)
    return {
        "expired_resident_authority": True,
        "short_lived_acknowledged": True,
        "starting_authority_authenticated": True,
        "authenticated_readback": True,
        "policy_preserved": True,
        "control_binding_present": "command_extensions" in previous,
        "control_binding_preserved": True,
        "policy_prepare_rejected": prepared is None,
        "refresh_suspended": publisher.closed and (publisher._thread is None or not publisher._thread.is_alive()),
    }

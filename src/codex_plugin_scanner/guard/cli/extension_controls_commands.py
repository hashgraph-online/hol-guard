"""Deterministic CLI inspection and mutation for extension controls."""

from __future__ import annotations

import argparse
import contextlib
import json
import secrets
import sys
from pathlib import Path
from typing import TextIO, cast

from ..approval_gate import (
    ApprovalGateError,
    consume_extension_control_grant,
    require_extension_control,
)
from ..daemon.client import GuardDaemonRequestError, GuardSurfaceDaemonClient
from ..daemon.manager import load_guard_daemon_auth_token, load_guard_daemon_url
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_authority import ExtensionControlAuthorityError
from ..runtime.extension_control_proof import (
    ExtensionControlEnrollment,
    ExtensionControlProofError,
    issue_extension_control_enrollment_proof,
)
from ..store import GuardStore
from .approval_gate_prompt import prompt_for_approval_gate


def _client(guard_home: Path) -> GuardSurfaceDaemonClient:
    daemon_url = load_guard_daemon_url(guard_home)
    auth_token = load_guard_daemon_auth_token(guard_home)
    if daemon_url is None or auth_token is None:
        raise GuardDaemonRequestError("Guard daemon is not running")
    return GuardSurfaceDaemonClient(daemon_url, auth_token)


def _emit(payload: object, output_stream: TextIO | None) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=output_stream or sys.stdout)


def _mutation_payload(effective: dict[str, object], args: argparse.Namespace) -> dict[str, object]:
    revision = effective.get("revision")
    catalog_digest = effective.get("catalog_digest")
    raw_layers = effective.get("layers")
    if type(revision) is not int or not isinstance(catalog_digest, str) or not isinstance(raw_layers, list):
        raise ValueError("daemon returned invalid effective controls")
    layers = [
        dict(cast(dict[str, object], layer)) for layer in cast(list[object], raw_layers) if isinstance(layer, dict)
    ]
    local_candidate = next((layer for layer in layers if layer.get("kind") == "local-admin"), None)
    if local_candidate is None:
        local: dict[str, object] = {
            "schema_version": "1.0.0",
            "kind": "local-admin",
            "catalog_digest": catalog_digest,
            "global_lockdown": False,
            "controls": [],
        }
        layers.append(local)
    else:
        local = local_candidate
    command = str(args.controls_command)
    state = str(args.state)
    if command.startswith("global-"):
        local["global_lockdown"] = state == "enabled"
    else:
        target_kind = str(args.target_kind)
        target_id = str(args.target_id)
        controls = local.get("controls")
        if not isinstance(controls, list):
            raise ValueError("daemon returned invalid local controls")
        filtered = [
            item
            for item in controls
            if not (
                isinstance(item, dict) and item.get("target_kind") == target_kind and item.get("target_id") == target_id
            )
        ]
        filtered.append({"target_kind": target_kind, "target_id": target_id, "state": state})
        local["controls"] = filtered
    return {
        "previous_revision": revision,
        "catalog_digest": catalog_digest,
        "layers": layers,
        "actor_id": "local-admin",
        "idempotency_key": secrets.token_hex(16),
        "nonce": secrets.token_hex(16),
    }


def _enroll(guard_home: Path, actor: str, output_stream: TextIO | None) -> int:
    store = GuardStore(guard_home)
    enrollment = ExtensionControlEnrollment(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        actor_id=actor,
        nonce=secrets.token_hex(16),
    )
    gate_input = prompt_for_approval_gate(guard_home, use_cooldown=False)
    proof = issue_extension_control_enrollment_proof(
        guard_home,
        enrollment,
        approval_gate_input=gate_input,
        session_nonce=secrets.token_hex(16),
    )
    view = store.enroll_extension_control_authority(
        catalog_digest=enrollment.catalog_digest,
        actor_id=enrollment.actor_id,
        nonce=enrollment.nonce,
        proof=proof,
    )
    with contextlib.suppress(GuardDaemonRequestError):
        _ = _client(guard_home).refresh_extension_controls()
    _emit(
        {"catalog_digest": view.catalog_digest, "health": view.health.value, "revision": view.revision}, output_stream
    )
    return 0


def _recover_authority(
    guard_home: Path,
    *,
    command: str,
    output_stream: TextIO | None,
) -> int:
    store = GuardStore(guard_home)
    catalog_digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    current = store.read_extension_control_authority(catalog_digest=catalog_digest)
    session_nonce = secrets.token_hex(32)
    subject = f"{command}:{current.health.value}:{current.revision}:{catalog_digest}"
    gate_input = prompt_for_approval_gate(
        guard_home,
        use_cooldown=False,
        summary=f"Authenticate extension-control authority {command}.",
    )
    if command == "recover-authority":
        grant = require_extension_control(
            guard_home,
            approval_gate_input=gate_input,
            action=command,
            subject=subject,
            session_nonce=session_nonce,
        )
        consume_extension_control_grant(
            guard_home,
            grant,
            action=command,
            subject=subject,
            session_nonce=session_nonce,
        )
        view = store.recover_extension_control_authority(catalog_digest=catalog_digest)
        with contextlib.suppress(GuardDaemonRequestError):
            _ = _client(guard_home).refresh_extension_controls()
        response: dict[str, object] = {
            "health": view.health.value,
            "revision": view.revision,
            "catalog_digest": view.catalog_digest,
        }
    else:
        payload: dict[str, object] = {"session_nonce": session_nonce}
        if gate_input is not None:
            payload["approval_password"] = gate_input.password
            payload["approval_totp_code"] = gate_input.totp_code
        response = _client(guard_home).acknowledge_degraded_extension_controls(payload)
    _emit(response, output_stream)
    return 0


def run_extension_controls_command(
    args: argparse.Namespace,
    *,
    guard_home: Path,
    output_stream: TextIO | None,
) -> int:
    """Run one extension-control CLI command with stable exit semantics."""

    command = str(args.controls_command)
    try:
        if command == "enroll":
            return _enroll(guard_home, str(args.actor), output_stream)
        if command in {"recover-authority", "acknowledge-degraded"}:
            return _recover_authority(
                guard_home,
                command=command,
                output_stream=output_stream,
            )
        client = _client(guard_home)
        if command == "status":
            _emit(client.effective_extension_controls(), output_stream)
            return 0
        if command in {"list", "show"}:
            catalog = client.extension_control_catalog()
            if command == "list":
                _emit(catalog, output_stream)
                return 0
            target_id = str(args.target_id)
            extensions = catalog.get("extensions")
            if isinstance(extensions, list):
                for extension in extensions:
                    if isinstance(extension, dict) and extension.get("extension_id") == target_id:
                        _emit(extension, output_stream)
                        return 0
            raise ValueError(f"unknown extension target: {target_id}")
        effective = client.effective_extension_controls()
        payload = _mutation_payload(effective, args)
        if command in {"preview", "global-preview"}:
            _emit(client.preview_extension_controls(payload), output_stream)
            return 0
        gate_input = prompt_for_approval_gate(guard_home, use_cooldown=False)
        payload["session_nonce"] = secrets.token_hex(16)
        if gate_input is not None:
            payload["approval_password"] = gate_input.password
            payload["approval_totp_code"] = gate_input.totp_code
        preview = client.preview_extension_controls(payload)
        proof_id = preview.get("proof_id")
        if not isinstance(proof_id, str):
            raise ExtensionControlProofError("daemon did not issue a mutation proof")
        payload["proof_id"] = proof_id
        _emit(client.apply_extension_controls(payload), output_stream)
        return 0
    except (
        ApprovalGateError,
        ExtensionControlAuthorityError,
        ExtensionControlProofError,
        EOFError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 4
    except GuardDaemonRequestError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 4 if error.status in {401, 403, 423} else 2
    except (TypeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

"""Replay the language-neutral approval-gate vectors through the resident.

The vectors in ``tests/fixtures/approval_gate/parity_vectors.json`` record the
approval gate's decisions (eligibility, identity/context matching, claim and
consume ordering, lockout, cooldown, TOTP, fresh-policy revalidation). The Rust
unit tests replay the same file against the op directly; this module replays it
through the public Python functions so the transport, wire decoding and error
reconstruction are held to the same expectations. Python holds no oracle here.
"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.guard import approval_gate as ag
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_approval_gate import approval_gate_native
from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.totp import totp_code_at_counter

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "approval_gate" / "parity_vectors.json").read_text(encoding="utf-8")
)
assert VECTORS["schema"] == "guard-approval-gate-parity-vectors.v1"

_CONFIG_FIELDS = (
    "enabled",
    "configured",
    "cooldown_seconds",
    "cooldown_active",
    "cooldown_expires_at",
    "locked_until",
    "fail_closed",
    "strict_all_decisions",
    "totp_enabled",
    "totp_pending",
    "totp_recent_satisfied",
)
_GRANT_FIELDS = (
    "purpose",
    "issued_at",
    "expires_at",
    "action",
    "scope",
    "subject",
    "session_nonce",
    "used_cooldown",
    "cooldown_expires_at",
    "password_verified",
    "totp_verified",
    "strict",
)


def _config(value: ag.ApprovalGatePublicConfig) -> dict[str, object]:
    return {field: getattr(value, field) for field in _CONFIG_FIELDS}


def _grant(value: ag.ApprovalGateGrant | None) -> dict[str, object] | None:
    if value is None:
        return None
    payload: dict[str, object] = {field: getattr(value, field) for field in _GRANT_FIELDS}
    payload["grant_id"] = value.grant_id
    payload["factor_set"] = list(value.factor_set)
    return payload


def _input(spec: dict[str, object] | None, secrets: dict[str, str]) -> ag.ApprovalGateInput | None:
    if spec is None:
        return None
    fields: dict[str, object] = {}
    for key, value in spec.items():
        if isinstance(value, dict) and "$totp" in value:
            marker = value["$totp"]
            counter = int(datetime.fromisoformat(marker["at"]).timestamp() // 30) + marker["offset"]
            value = totp_code_at_counter(secret=secrets[marker["secret"]], counter=counter)
        fields[key] = value
    return ag.ApprovalGateInput(**fields)


def _apply_file(home: Path, spec: dict[str, object]) -> dict[str, object]:
    path = home / str(spec.get("write") or spec.get("delete") or "approval-gate.json")
    if "write" in spec:
        path.write_text(str(spec["content"]), encoding="utf-8")
    elif "delete" in spec:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    else:
        state = json.loads(path.read_text(encoding="utf-8"))
        state.update(spec["patch_state"])
        path.write_text(json.dumps(state), encoding="utf-8")
    return {"applied": True}


def _context(p: dict[str, object]) -> dict[str, object]:
    return {
        "action": p.get("action"),
        "scope": p.get("scope"),
        "subject": p.get("subject"),
        "session_nonce": p.get("session_nonce"),
    }


def _call(home: Path, call: dict[str, object], grants: dict[str, ag.ApprovalGateGrant], secrets: dict[str, str]):
    method = str(call["method"])
    raw = call.get("params")
    params = raw if isinstance(raw, dict) else {}
    now = str(call["now"])
    supplied = _input(call.get("input"), secrets)
    grant = grants.get(str(call["grant"])) if call.get("grant") else None
    ctx = _context(params)
    if method == "public_config":
        return _config(ag.public_config(home, now=now))
    if method == "recent_totp_satisfied":
        return {"satisfied": ag.recent_totp_satisfied(home, now=now)}
    if method == "update_settings":
        return _config(ag.update_settings(home, raw, approval_gate_grant=grant, now=now))
    if method == "validate_settings_update":
        ag.validate_settings_update(home, raw, approval_gate_grant=grant, now=now)
        return {"validated": True}
    if method == "revoke_cooldown":
        return _config(ag.revoke_cooldown(home, now=now))
    if method == "unlock_cooldown":
        return _config(
            ag.unlock_cooldown(home, duration_seconds=call["duration_seconds"], approval_gate_input=supplied, now=now)
        )
    if method == "begin_totp_enrollment":
        begun = ag.begin_totp_enrollment(
            home, approval_gate_input=supplied, device_label=str(call.get("device_label") or "local-device"), now=now
        )
        if call.get("secret_bind"):
            secrets[str(call["secret_bind"])] = parse_qs(urlparse(str(begun["otpauth_uri"])).query)["secret"][0]
        return {key: begun[key] for key in ("pending", "manual_key", "expires_at", "otpauth_uri")}
    if method == "confirm_totp_enrollment":
        return _config(ag.confirm_totp_enrollment(home, approval_gate_input=supplied, now=now))
    if method == "disable_totp":
        return _config(ag.disable_totp(home, approval_gate_input=supplied, now=now))
    if method == "require_approval_decision":
        issued = ag.require_approval_decision(
            home,
            action=params["action"],
            scope=params["scope"],
            approval_gate_input=supplied,
            approval_gate_grant=grant,
            subject=params.get("subject"),
            session_nonce=params.get("session_nonce"),
            now=now,
        )
    elif method == "require_high_risk":
        issued = ag.require_high_risk(
            home,
            purpose=call["purpose"],
            approval_gate_input=supplied,
            approval_gate_grant=grant,
            now=now,
            **ctx,
        )
    elif method in {"require_extension_control", "require_local_cli_trust"}:
        issued = getattr(ag, method)(
            home,
            approval_gate_input=supplied,
            action=params["action"],
            subject=params["subject"],
            session_nonce=params["session_nonce"],
            now=now,
        )
    else:
        issued = None
    if method in {
        "require_approval_decision",
        "require_high_risk",
        "require_extension_control",
        "require_local_cli_trust",
    }:
        if issued is not None and call.get("bind"):
            grants[str(call["bind"])] = issued
        return {"grant": _grant(issued)}
    if method in {"consume_extension_control_grant", "consume_local_cli_trust_grant"}:
        getattr(ag, method)(
            home,
            grant,
            action=params["action"],
            subject=params["subject"],
            session_nonce=params["session_nonce"],
            now=now,
        )
        return {"consumed": True}
    if method == "require_policy_write":
        decision = PolicyDecision(harness="codex", scope=params["scope"], action=params["action"])
        ag.require_policy_write(home, decision=decision, approval_gate_grant=grant, now=now)
    elif method == "require_request_resolution":
        ag.require_request_resolution(
            home,
            resolution_action=params["action"],
            resolution_scope=params["scope"],
            approval_gate_grant=grant,
            now=now,
        )
    elif method == "require_policy_clear":
        ag.require_policy_clear(home, approval_gate_grant=grant, now=now)
    elif method == "require_settings_write":
        ag.require_settings_write(home, approval_gate_grant=grant, now=now)
    elif method == "validate_grant":
        ag.validate_grant(home, grant, purpose=call.get("purpose"), strict=bool(call.get("strict")), now=now, **ctx)
        return {"validated": True}
    elif method == "create_verifier":
        approval_gate_native("create_verifier", home, params={"password": params["password"]})
        return {"verifier": "<random>"}
    else:
        raise AssertionError(f"unknown vector method {method}")
    return {"ok": True}


def _matches(expected: object, actual: object) -> bool:
    if isinstance(expected, str) and "<random>" in expected:
        prefix = expected.split("<random>", 1)[0]
        return isinstance(actual, str) and actual.startswith(prefix) and len(actual) > len(prefix)
    if isinstance(expected, dict):
        return (
            isinstance(actual, dict)
            and expected.keys() == actual.keys()
            and all(_matches(value, actual[key]) for key, value in expected.items())
        )
    return expected == actual


@pytest.fixture
def resident_home(native_hook_force: Path, tmp_path: Path):
    home = tmp_path / "guard-home"
    (home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(home, b"\x07" * 32)
    yield home
    close_native_residents(home)


@pytest.mark.parametrize("scenario", VECTORS["scenarios"], ids=lambda scenario: scenario["name"])
def test_resident_replays_recorded_vectors(scenario: dict[str, object], resident_home: Path) -> None:
    grants: dict[str, ag.ApprovalGateGrant] = {}
    secrets: dict[str, str] = {}
    mismatches: list[str] = []
    for index, recorded in enumerate(scenario["steps"]):
        call, expect = recorded["call"], recorded["expect"]
        if call.get("file"):
            _apply_file(resident_home, call["file"])
            continue
        try:
            outcome = {"status": "ok", "code": "ok", "payload": _call(resident_home, call, grants, secrets)}
        except ag.ApprovalGateError as error:
            outcome = {"status": "error", "code": error.code, "error_status": error.status, "message": str(error)}
        if not _matches(expect, outcome):
            mismatches.append(f"step {index} {call['method']}: expected {expect} got {outcome}")
    assert not mismatches, "\n".join(mismatches)

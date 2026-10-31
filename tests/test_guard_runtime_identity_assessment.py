"""Runtime identity assessment through the native command.

Matching and remediation rules are tested in Rust beside the code. These tests
cover the bridge: the compiled reply round-trips, and a malformed or failed
reply is never read as a verdict.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_identity_assessment as runtime_identity

OLD_HASH = "1" * 64
NEW_HASH = "2" * 64


def _artifact(artifact_id: str, version: str, executable_sha256: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "family": "node",
        "vendor": "nodejs",
        "version": version,
        "build_id": None,
        "os": "linux",
        "arch": "x64",
        "executable_sha256": executable_sha256,
        "component_identity_sha256": None,
        "identity_assurance": "vendor_verified",
    }


def _replacement_request(old_state: str) -> dict[str, object]:
    return {
        "artifacts": [_artifact("old", "22.3.0", OLD_HASH), _artifact("new", "22.4.1", NEW_HASH)],
        "locations": [{"location_id": "loc", "artifact_id": "new", "state": "present"}],
        "instances": [
            {
                "instance_id": "i-old",
                "boot_identity": "boot",
                "pid": 41,
                "start_identity": "s41",
                "artifact_id": "old",
                "location_id": "loc",
                "state": old_state,
                "coverage": "bound_launch",
            },
            {
                "instance_id": "i-new",
                "boot_identity": "boot",
                "pid": 42,
                "start_identity": "s42",
                "artifact_id": "new",
                "location_id": "loc",
                "state": "running",
                "coverage": "bound_launch",
            },
        ],
        "advisories": [
            {
                "advisory_id": "GHSA-node-1",
                "family": "node",
                "vendor": "nodejs",
                "version_scheme": "semver",
                "ranges": [{"introduced": "22.0.0", "fixed": "22.4.1"}],
            }
        ],
        "scope_complete": True,
    }


def test_native_reply_round_trips(native_hook_force: Path) -> None:
    running = runtime_identity.assess_runtime_identity(_replacement_request("running"))
    assert running.advisories[0].verdict == "restart_required"
    assert running.advisories[0].affected_instance_ids == ("i-old",)

    exited = runtime_identity.assess_runtime_identity(_replacement_request("exited"))
    assert exited.advisories[0].verdict == "fixed_verified"
    assert exited.advisories[0].replacement_instance_ids == ("i-new",)
    assert all(len(str(row["identity_fingerprint"])) == 64 for row in exited.artifacts)

    with pytest.raises(runtime_identity.RuntimeIdentityError) as refused:
        runtime_identity.assess_runtime_identity({"artifacts": [_artifact("a", "1.0.0", "ABC")]})
    assert refused.value.code == "runtime_identity_artifact_invalid"


@pytest.mark.parametrize(
    "reply",
    [
        {"ok": True, "result": {"schema": "other"}},
        {"ok": True, "result": {"schema": runtime_identity.RUNTIME_IDENTITY_SCHEMA, "artifacts": [], "advisories": []}},
        {
            "ok": True,
            "result": {
                "schema": runtime_identity.RUNTIME_IDENTITY_SCHEMA,
                "scope_complete": True,
                "artifacts": [],
                "advisories": [{"advisory_id": "a", "verdict": "safe", "reasons": []}],
            },
        },
        {"ok": False},
        {
            "ok": True,
            "result": {
                "schema": runtime_identity.RUNTIME_IDENTITY_SCHEMA,
                "scope_complete": True,
                "artifacts": [],
                "advisories": [
                    {
                        "advisory_id": "a",
                        "verdict": ["safe"],
                        "reasons": [],
                        "affected_artifact_ids": [],
                        "affected_instance_ids": [],
                        "replacement_instance_ids": [],
                    }
                ],
            },
        },
        {
            "ok": True,
            "result": {
                "schema": runtime_identity.RUNTIME_IDENTITY_SCHEMA,
                "scope_complete": True,
                "artifacts": [{}],
                "advisories": [],
            },
        },
    ],
)
def test_malformed_reply_is_not_a_verdict(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> None:
    monkeypatch.setattr(runtime_identity, "_native_request", lambda request: reply)
    with pytest.raises(runtime_identity.RuntimeIdentityError):
        runtime_identity.assess_runtime_identity({"artifacts": []})


def test_unavailable_runtime_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    class Unavailable:
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: Unavailable())
    with pytest.raises(runtime_identity.RuntimeIdentityError) as unavailable:
        runtime_identity.assess_runtime_identity({"artifacts": []})
    assert unavailable.value.code == "runtime_identity_native_unavailable"

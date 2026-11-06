from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm import continuity, state_file
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _prepare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MachinePaths:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    monkeypatch.setattr(continuity.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(continuity, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(continuity, "require_machine_device_context", lambda _system_name: None)
    monkeypatch.setattr(continuity, "_private_regular_file", lambda _metadata: True)
    monkeypatch.setattr(state_file, "_state_owner_uid", lambda: getattr(os, "getuid", lambda: 0)())
    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: ("active-key", frozenset({"active-key"})),
    )
    monkeypatch.setattr(
        continuity,
        "observe_boot",
        lambda **_kwargs: continuity.BootObservation("boot-a", 10_000_000_000),
    )
    return paths


def test_continuity_provision_is_idempotent_and_snapshot_read_is_immutable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)

    first = continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    before = state_path.read_bytes()
    before_stat = state_path.stat()
    second = continuity.provision_machine_continuity()
    verification = continuity.verify_installation_continuity(paths, system_name="Darwin")
    after_stat = state_path.stat()

    assert first == second
    assert len(first["machineInstallationId"]) == 32
    assert len(first["installationGeneration"]) == 32
    assert state_path.read_bytes() == before
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert verification.healthy is True
    assert verification.identity_reason_code == "installation_identity_active"
    assert verification.lease_reason_code == "lease_continuity_uninitialized"
    assert verification.record is not None and verification.record.last_issued_sequence == 0


def test_uninitialized_v1_state_without_lease_key_id_remains_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    del payload["lastLeaseKeyId"]
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.healthy is True
    assert result.record is not None and result.record.last_lease_key_id is None


def test_missing_state_creates_a_fresh_generation_without_inheriting_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    first = continuity.provision_machine_continuity()
    (paths.state_root / "installation-continuity.json").unlink()

    second = continuity.provision_machine_continuity()

    assert second["machineInstallationId"] != first["machineInstallationId"]
    assert second["installationGeneration"] != first["installationGeneration"]
    assert second["sequence"] == 0


@pytest.mark.parametrize(
    ("mutation", "identity_reason"),
    [
        (lambda payload: payload.update(schemaVersion="wrong"), "installation_identity_invalid"),
        (lambda payload: payload.update(lastIssuedSequence=-1), "installation_identity_invalid"),
        (
            lambda payload: payload.update(keyIdAtGenerationCreation="replaced-key"),
            "installation_identity_key_mismatch",
        ),
    ],
)
def test_continuity_tamper_fails_without_rewriting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    identity_reason: str,
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert callable(mutation)
    mutation(payload)
    state_path.write_text(json.dumps(payload), encoding="utf-8")
    before = state_path.read_bytes()

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "tampered"
    assert result.identity_reason_code == identity_reason
    assert state_path.read_bytes() == before
    with pytest.raises((OSError, ValueError)):
        continuity.provision_machine_continuity()
    assert state_path.read_bytes() == before


def test_continuity_accepts_retained_rotation_key_and_rejects_unrelated_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: ("new-key", frozenset({"new-key", "active-key"})),
    )
    assert continuity.verify_installation_continuity(paths, system_name="Darwin").healthy is True

    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: ("new-key", frozenset({"new-key"})),
    )
    result = continuity.verify_installation_continuity(paths, system_name="Darwin")
    assert result.state == "tampered"
    assert result.identity_reason_code == "installation_identity_key_mismatch"


def test_continuity_detects_same_boot_monotonic_regression(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload.update(
        lastIssuedSequence=8,
        lastLeaseDigest="a" * 64,
        lastLeaseBootSessionId="boot-a",
        lastLeaseMonotonicUptimeNs=20_000_000_000,
        lastLeaseKeyId="active-key",
    )
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "tampered"
    assert result.identity_reason_code == "installation_identity_active"
    assert result.lease_reason_code == "lease_continuity_monotonic_regression"


def test_continuity_allows_lower_uptime_after_reboot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload.update(
        lastIssuedSequence=8,
        lastLeaseDigest="a" * 64,
        lastLeaseBootSessionId="boot-before",
        lastLeaseMonotonicUptimeNs=20_000_000_000,
        lastLeaseKeyId="active-key",
    )
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.healthy is True
    assert result.lease_reason_code == "lease_continuity_active"


def test_boot_probe_failure_preserves_verified_installation_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    monkeypatch.setattr(
        continuity,
        "observe_boot",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("lease_continuity_boot_probe_failed")),
    )

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "unknown"
    assert result.identity_reason_code == "installation_identity_active"
    assert result.lease_reason_code == "lease_continuity_boot_probe_failed"
    assert result.record is not None


def test_rotation_in_progress_is_unknown_not_tamper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    monkeypatch.setattr(
        continuity,
        "verified_machine_device_key_ids",
        lambda _paths, **_kwargs: (_ for _ in ()).throw(OSError("device_key_rotation_incomplete")),
    )

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "unknown"
    assert result.identity_reason_code == "installation_identity_probe_failed"
    assert result.lease_reason_code == "lease_continuity_probe_failed"


def test_maximum_sequence_is_degraded_not_healthy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_path = paths.state_root / "installation-continuity.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload.update(
        lastIssuedSequence=continuity._MAX_UINT64,
        lastLeaseDigest="a" * 64,
        lastLeaseBootSessionId="boot-before",
        lastLeaseMonotonicUptimeNs=1,
        lastLeaseKeyId="active-key",
    )
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert result.state == "degraded"
    assert result.identity_reason_code == "installation_identity_active"
    assert result.lease_reason_code == "lease_continuity_sequence_exhausted"


def test_continuity_rejects_symlink_and_oversized_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    paths.state_root.mkdir()
    state_path = paths.state_root / "installation-continuity.json"
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    state_path.symlink_to(outside)

    symlink_result = continuity.verify_installation_continuity(paths, system_name="Darwin")
    assert symlink_result.identity_reason_code == "installation_identity_acl_invalid"

    state_path.unlink()
    state_path.write_bytes(b"x" * (64 * 1024 + 1))
    monkeypatch.setattr(state_file, "_state_owner_uid", lambda: getattr(os, "getuid", lambda: 0)())
    oversized = continuity.verify_installation_continuity(paths, system_name="Darwin")
    assert oversized.identity_reason_code == "installation_identity_acl_invalid"


def _fake_boot_runtime(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> list[tuple[dict[str, object], tuple[str, ...]]]:
    requests: list[tuple[dict[str, object], tuple[str, ...]]] = []

    def fake_answer(
        _feature: str, _command: str, request: dict[str, object], *, extra_features: tuple[str, ...], **_kwargs: object
    ) -> dict[str, object] | None:
        requests.append((request, extra_features))
        return answer

    monkeypatch.setattr(continuity, "runtime_answer", fake_answer)
    return requests


def test_the_runtime_observes_the_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    boot = {"boot_session_id": "boot-id", "monotonic_uptime_ns": 3_000_000_000_000_000}
    requests = _fake_boot_runtime(monkeypatch, {"ok": True, "boot": boot})

    assert continuity.observe_boot(system_name="Windows") == continuity.BootObservation(
        "boot-id", 3_000_000_000_000_000
    )
    assert requests == [
        (
            {"schema": continuity.INSTALLATION_CONTINUITY_SCHEMA, "op": "observe-boot"},
            (continuity.BOOT_OBSERVATION_FEATURE,),
        )
    ]


def test_an_unsupported_platform_never_asks_the_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = _fake_boot_runtime(monkeypatch, {"ok": True})

    with pytest.raises(OSError, match="lease_continuity_platform_unsupported"):
        continuity.observe_boot(system_name="Plan9")
    assert requests == []


@pytest.mark.parametrize(
    ("answer", "code"),
    [
        ({"ok": False, "error": "lease_continuity_boot_probe_failed"}, "lease_continuity_boot_probe_failed"),
        ({"ok": False, "error": "lease_continuity_monotonic_probe_failed"}, "lease_continuity_monotonic_probe_failed"),
        ({"ok": False, "error": "something_else"}, "lease_continuity_probe_failed"),
        ({"ok": True, "boot": None}, "lease_continuity_probe_failed"),
        ({"ok": True, "boot": {"boot_session_id": "", "monotonic_uptime_ns": 1}}, "lease_continuity_probe_failed"),
        ({"ok": True, "boot": {"boot_session_id": "b", "monotonic_uptime_ns": True}}, "lease_continuity_probe_failed"),
        ({"ok": True, "boot": {"boot_session_id": "b", "monotonic_uptime_ns": -1}}, "lease_continuity_probe_failed"),
        (None, "installation_identity_native_unavailable"),
    ],
)
def test_a_failed_or_malformed_boot_answer_raises_its_code(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None, code: str
) -> None:
    _fake_boot_runtime(monkeypatch, answer)

    with pytest.raises(OSError, match=code):
        continuity.observe_boot(system_name="Darwin")


def test_the_native_runtime_observes_this_boot() -> None:
    first = continuity.observe_boot()
    second = continuity.observe_boot()

    assert first.boot_session_id
    assert first.boot_session_id == second.boot_session_id
    assert second.monotonic_uptime_ns >= first.monotonic_uptime_ns


def test_state_file_mode_is_private(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()

    assert os.stat(paths.state_root / "installation-continuity.json").st_mode & 0o777 == 0o600
    assert os.stat(paths.state_root / ".installation-continuity.lock").st_mode & 0o777 == 0o600


def test_continuity_provision_cli_is_prompt_free(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        commands_dispatch_mdm,
        "provision_machine_continuity",
        lambda: {
            "schemaVersion": "hol-guard-mdm-status.v1",
            "operation": "continuity-provision",
            "healthy": True,
            "state": "active",
            "reasonCodes": ["installation_identity_active"],
        },
    )

    assert cli.main(["mdm", "continuity-provision", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["operation"] == "continuity-provision"


def test_continuity_fails_closed_without_the_native_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()

    def unavailable(_request: dict[str, object]) -> dict[str, object]:
        raise OSError("installation_identity_native_unavailable")

    monkeypatch.setattr(continuity, "_native_answer", unavailable)

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert (result.state, result.identity_reason_code, result.lease_reason_code) == (
        "unknown",
        "installation_identity_probe_failed",
        "lease_continuity_probe_failed",
    )
    assert result.record is None
    with pytest.raises(OSError, match="installation_identity_native_unavailable"):
        continuity.provision_machine_continuity()


@pytest.mark.parametrize("content", ["not base64!", 7])
def test_undecodable_native_content_is_a_failed_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: object
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    monkeypatch.setattr(state_file, "native_state", lambda *_args: {"ok": True, "content": content})

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert (result.state, result.identity_reason_code) == ("unknown", "installation_identity_probe_failed")
    with pytest.raises(OSError, match="installation_identity_native_unavailable"):
        state_file.read_state(paths.state_root, "continuity")


def test_continuity_sends_each_probe_outcome_to_the_native_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    state_bytes = (paths.state_root / "installation-continuity.json").read_bytes()

    def denied(_paths: MachinePaths, **_kwargs: object) -> object:
        raise PermissionError("denied")

    def boot_failed(**_kwargs: object) -> object:
        raise OSError("lease_continuity_boot_probe_failed")

    monkeypatch.setattr(continuity, "verified_machine_device_key_ids", denied)
    monkeypatch.setattr(continuity, "observe_boot", boot_failed)
    requests: list[dict[str, object]] = []

    def answer(request: dict[str, object]) -> dict[str, object]:
        requests.append(request)
        if request["op"] == "parse":
            return {"ok": True}
        return {
            "ok": True,
            "state": "tampered",
            "identity_reason_code": "installation_identity_acl_invalid",
            "lease_reason_code": "lease_continuity_invalid",
            "record": None,
            "observed": False,
        }

    monkeypatch.setattr(continuity, "_native_answer", answer)

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert [request["op"] for request in requests] == ["parse", "verify"]
    assert requests[0]["content"] == requests[1]["content"]
    assert base64.b64decode(str(requests[1]["content"])) == state_bytes
    assert requests[1]["key"] == {"kind": "permission", "error": "denied"}
    assert requests[1]["boot"] == {"kind": "os", "error": "lease_continuity_boot_probe_failed"}
    assert result.state == "tampered"
    assert result.identity_reason_code == "installation_identity_acl_invalid"
    assert result.record is None and result.observation is None


def test_an_unreadable_record_never_runs_the_key_or_boot_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()
    probes: list[str] = []

    def key_probe(_paths: MachinePaths, **_kwargs: object) -> object:
        probes.append("key")
        raise AssertionError("key probe ran")

    def boot_probe(**_kwargs: object) -> object:
        probes.append("boot")
        raise AssertionError("boot probe ran")

    def rejected(request: dict[str, object]) -> dict[str, object]:
        assert request["op"] == "parse"
        return {"ok": False, "error": "installation_identity_invalid"}

    monkeypatch.setattr(continuity, "verified_machine_device_key_ids", key_probe)
    monkeypatch.setattr(continuity, "observe_boot", boot_probe)
    monkeypatch.setattr(continuity, "_native_answer", rejected)

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert (result.state, result.identity_reason_code, result.lease_reason_code) == (
        "tampered",
        "installation_identity_invalid",
        "lease_continuity_invalid",
    )
    assert probes == []


@pytest.mark.parametrize(
    "verdict",
    [
        {"ok": True},
        {"ok": True, "state": 1, "identity_reason_code": "x", "lease_reason_code": "y", "observed": False},
        {
            "ok": True,
            "state": "healthy",
            "identity_reason_code": "x",
            "lease_reason_code": "y",
            "record": "z",
            "observed": False,
        },
    ],
)
def test_a_malformed_native_verdict_is_a_failed_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, verdict: dict[str, object]
) -> None:
    paths = _prepare(tmp_path, monkeypatch)
    continuity.provision_machine_continuity()

    def answer(request: dict[str, object]) -> dict[str, object]:
        return {"ok": True} if request["op"] == "parse" else verdict

    monkeypatch.setattr(continuity, "_native_answer", answer)

    result = continuity.verify_installation_continuity(paths, system_name="Darwin")

    assert (result.state, result.identity_reason_code, result.lease_reason_code) == (
        "unknown",
        "installation_identity_probe_failed",
        "lease_continuity_probe_failed",
    )

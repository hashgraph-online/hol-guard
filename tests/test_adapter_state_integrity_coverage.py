"""Focused coverage for authenticated adapter-state key handling."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard import native_adapter_state_integrity as native_integrity
from codex_plugin_scanner.guard.adapters import adapter_state_integrity as integrity
from codex_plugin_scanner.guard.adapters.adapter_state_integrity import (
    AdapterStateIntegrityUnavailableError,
    adapter_state_is_authenticated,
    authenticate_adapter_state,
    authenticated_adapter_path,
)
from codex_plugin_scanner.guard.native_context import ensure_resident_prerequisite


def _key_payload(*, key_id: str = "race-key") -> dict[str, object]:
    return {
        "key": base64.urlsafe_b64encode(b"k" * 32).decode("ascii"),
        "key_id": key_id,
        "schema_version": 1,
    }


def _key_path(guard_home: Path) -> Path:
    return guard_home / "managed" / "adapter-state.key"


def _authentication(payload: dict[str, object]) -> dict[str, object]:
    return cast(dict[str, object], payload["state_authentication"])


def test_authentication_rejects_malformed_metadata_and_paths(
    tmp_path: Path,
    native_adapter_state_integrity_runtime: Path,
) -> None:
    del native_adapter_state_integrity_runtime
    guard_home = tmp_path / "guard-home"
    payload: dict[str, object] = {"path": str(tmp_path / "target.txt"), "scope": "workspace"}
    authenticated = authenticate_adapter_state(guard_home, harness="copilot", payload=payload)

    assert adapter_state_is_authenticated(guard_home, harness="copilot", payload=authenticated)
    assert not adapter_state_is_authenticated(guard_home, harness="other", payload=authenticated)

    malformed_algorithm = dict(authenticated)
    malformed_algorithm["state_authentication"] = {
        **_authentication(authenticated),
        "algorithm": "sha256",
    }
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=malformed_algorithm)

    malformed_key_id = dict(authenticated)
    malformed_key_id["state_authentication"] = {
        **_authentication(authenticated),
        "key_id": "different",
    }
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=malformed_key_id)

    malformed_mac = dict(authenticated)
    malformed_mac["state_authentication"] = {
        **_authentication(authenticated),
        "mac": 17,
    }
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=malformed_mac)

    wrong_mac = dict(authenticated)
    wrong_mac["state_authentication"] = {
        **_authentication(authenticated),
        "mac": "0" * 64,
    }
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=wrong_mac)
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload={})
    assert authenticated_adapter_path(guard_home, harness="copilot", payload=wrong_mac, field="path") is None

    for value in (None, "", "relative.txt", "contains\x00byte"):
        invalid = authenticate_adapter_state(
            guard_home,
            harness="copilot",
            payload={"path": value},  # type: ignore[dict-item]
        )
        assert authenticated_adapter_path(guard_home, harness="copilot", payload=invalid, field="path") is None

    signed_absolute = authenticate_adapter_state(
        guard_home,
        harness="copilot",
        payload={"path": str(tmp_path / "nested" / ".." / "target.txt")},
    )
    assert authenticated_adapter_path(guard_home, harness="copilot", payload=signed_absolute, field="path") == (
        tmp_path / "target.txt"
    )
    assert authenticated_adapter_path(guard_home, harness="copilot", payload=signed_absolute, field="missing") is None


def _write_key(guard_home: Path) -> None:
    key_path = _key_path(guard_home)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(json.dumps(_key_payload()), encoding="utf-8")
    if os.name == "posix":
        key_path.parent.chmod(0o700)
        key_path.chmod(0o600)


def _record_requests(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    requests: list[dict[str, object]] = []

    def record(**kwargs: object) -> dict[str, object]:
        requests.append(kwargs)
        return {"authenticated": True, "value": "/tmp/target.txt"}

    monkeypatch.setattr(integrity, "native_adapter_state_integrity", record)
    return requests


def test_the_runtime_is_named_the_key_home_and_sent_no_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    requests = _record_requests(monkeypatch)

    authenticate_adapter_state(guard_home, harness="copilot", payload={"scope": "global"})
    _write_key(guard_home)
    assert adapter_state_is_authenticated(guard_home, harness="copilot", payload=_stamped_payload())

    assert [request["key_home"] for request in requests] == [guard_home, guard_home]
    assert requests[0]["create_key"] is True
    assert all("integrity_key_b64" not in request for request in requests)


def test_a_missing_key_is_refused_before_the_runtime_when_it_may_not_be_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    requests = _record_requests(monkeypatch)

    with pytest.raises(FileNotFoundError):
        authenticate_adapter_state(guard_home, harness="copilot", payload={}, create_key=False)
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=_stamped_payload())
    assert requests == []


def _reply_with(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, code: str, bound: bool) -> None:
    monkeypatch.setattr(native_integrity, "_resolve_digest_home", lambda guard_home=None: tmp_path)
    monkeypatch.setattr(native_integrity, "ensure_resident_prerequisite", lambda _home: True)

    def reply(**kwargs: object) -> dict[str, object]:
        request = cast(dict[str, object], kwargs["request"])
        digest = "sha256:" + native_integrity._canonical_request_sha256(request)
        return {
            "request_id": request["request_id"],
            "request_sha256": digest if bound else "sha256:" + "0" * 64,
            "status": "error",
            "code": code,
        }

    monkeypatch.setattr(native_integrity, "_resident_request", reply)


def test_an_unusable_key_is_a_value_error_only_when_the_resident_says_so(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"

    _reply_with(monkeypatch, tmp_path, code="native_adapter_state_integrity_key_unavailable", bound=True)
    with pytest.raises(ValueError, match="unusable"):
        authenticate_adapter_state(guard_home, harness="copilot", payload={})

    _reply_with(monkeypatch, tmp_path, code="native_adapter_state_integrity_key_unavailable", bound=False)
    with pytest.raises(AdapterStateIntegrityUnavailableError):
        authenticate_adapter_state(guard_home, harness="copilot", payload={})

    _reply_with(monkeypatch, tmp_path, code="native_adapter_state_integrity_invalid", bound=True)
    with pytest.raises(AdapterStateIntegrityUnavailableError):
        authenticate_adapter_state(guard_home, harness="copilot", payload={})


@pytest.mark.skipif(os.name != "posix", reason="POSIX key file permissions")
def test_the_runtime_creates_an_owner_only_key(
    tmp_path: Path,
    native_adapter_state_integrity_runtime: Path,
) -> None:
    del native_adapter_state_integrity_runtime
    guard_home = tmp_path / "guard-home"

    stamped = authenticate_adapter_state(guard_home, harness="copilot", payload={"scope": "global"})

    assert stat.S_IMODE(_key_path(guard_home).stat().st_mode) == 0o600
    assert stat.S_IMODE(_key_path(guard_home).parent.stat().st_mode) == 0o700
    assert adapter_state_is_authenticated(guard_home, harness="copilot", payload=stamped)
    _key_path(guard_home).chmod(0o644)
    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=stamped)


def _stamped_payload() -> dict[str, object]:
    return {
        "path": "/tmp/target.txt",
        "state_authentication": {
            "algorithm": "hmac-sha256",
            "key_id": "id",
            "mac": "0" * 64,
            "schema_version": 1,
        },
    }


def _provision_verifier_key(guard_home: Path) -> None:
    """Write the on-disk prerequisite the resident refuses every request without."""

    from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
        NATIVE_POLICY_VERIFIER_KEY_NAME,
        NATIVE_RUNTIME_STATE_DIRECTORY,
    )

    key = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY / NATIVE_POLICY_VERIFIER_KEY_NAME
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_bytes(base64.urlsafe_b64encode(b"\x00" * 32))


def _silence_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every adapter-state request fail the way a dead socket does."""

    def refuse(**_kwargs: object) -> dict[str, object]:
        raise OSError("resident is gone")

    monkeypatch.setattr(native_integrity, "_resident_request", refuse)


def test_a_silent_runtime_is_not_read_as_an_unauthenticated_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unavailable resident must not answer "not Guard's own" for a stamped manifest.

    Uninstall reads that answer as "there is no authenticated state" and runs
    legacy cleanup, which deletes Hermes' saved previous guard section and
    skips the Copilot backup restore.
    """

    guard_home = tmp_path / "guard-home"
    _write_key(guard_home)

    def unavailable(**_kwargs: object) -> dict[str, object]:
        raise AdapterStateIntegrityUnavailableError

    monkeypatch.setattr(integrity, "native_adapter_state_integrity", unavailable)

    with pytest.raises(AdapterStateIntegrityUnavailableError):
        adapter_state_is_authenticated(guard_home, harness="copilot", payload=_stamped_payload())
    with pytest.raises(AdapterStateIntegrityUnavailableError):
        authenticated_adapter_path(guard_home, harness="copilot", payload=_stamped_payload(), field="path")


def test_a_missing_key_still_reads_as_an_unauthenticated_manifest(tmp_path: Path) -> None:
    """A key file that is absent or unusable stays a verdict, not an outage."""

    guard_home = tmp_path / "guard-home"

    assert not adapter_state_is_authenticated(guard_home, harness="copilot", payload=_stamped_payload())
    assert authenticated_adapter_path(guard_home, harness="copilot", payload=_stamped_payload(), field="path") is None


def test_a_lifecycle_change_is_refused_before_its_first_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hermes asks the resident for its whole plan before it rewrites ``config.yaml``."""

    from codex_plugin_scanner.guard import native_runner_authority
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.hermes import HermesHarnessAdapter

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    home_dir.mkdir()
    workspace_dir.mkdir()
    config_yaml = home_dir / ".hermes" / "config.yaml"
    config_yaml.parent.mkdir(parents=True)
    config_yaml.write_text("mcp_servers: {}\n", encoding="utf-8")
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=guard_home)

    _provision_verifier_key(guard_home)

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise native_runner_authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)

    with pytest.raises(ValueError, match="native_runner_authority_unavailable"):
        HermesHarnessAdapter().install(context)

    assert config_yaml.read_text(encoding="utf-8") == "mcp_servers: {}\n"
    assert not _key_path(guard_home).exists()


def test_a_provisioned_home_without_a_resident_is_still_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verifier key on disk is not an answer from the resident.

    That file survives a restart, a crash and a binary this feature was never
    compiled into, so reading it as "reachable" would admit exactly the
    install this gate exists to refuse.
    """

    guard_home = tmp_path / "guard-home"
    _provision_verifier_key(guard_home)
    assert ensure_resident_prerequisite(guard_home)

    _silence_the_resident(monkeypatch)

    assert not native_integrity.adapter_state_runtime_available(guard_home)
    with pytest.raises(AdapterStateIntegrityUnavailableError):
        integrity.require_adapter_state_runtime(guard_home)


def test_a_reachable_runtime_admits_the_lifecycle_change(
    tmp_path: Path,
    native_adapter_state_integrity_runtime: Path,
) -> None:
    """A resident that answers ``verify`` is what admits the first write."""

    del native_adapter_state_integrity_runtime
    guard_home = tmp_path / "guard-home"

    assert native_integrity.adapter_state_runtime_available(guard_home)
    integrity.require_adapter_state_runtime(guard_home)


@pytest.mark.skipif(os.name != "posix", reason="a Windows spelling is only foreign off Windows")
def test_a_foreign_absolute_path_never_resolves_against_the_working_directory(
    tmp_path: Path,
    native_adapter_state_integrity_runtime: Path,
) -> None:
    """The runtime accepts both families; this host only resolves its own.

    A Guard home carried from Windows holds manifests whose paths the runtime
    still authenticates, and ``C:\\Users\\dev\\config.json`` is a relative path
    here, so resolving it would name a file under the working directory.
    """

    del native_adapter_state_integrity_runtime
    guard_home = tmp_path / "guard-home"

    for foreign in ("C:\\Users\\dev\\config.json", "\\\\server\\share\\config.json"):
        stamped = authenticate_adapter_state(guard_home, harness="copilot", payload={"path": foreign})
        assert adapter_state_is_authenticated(guard_home, harness="copilot", payload=stamped)
        assert authenticated_adapter_path(guard_home, harness="copilot", payload=stamped, field="path") is None

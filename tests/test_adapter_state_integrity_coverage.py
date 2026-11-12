"""Focused coverage for authenticated adapter-state key handling."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
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


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-backed key handling")
def test_posix_key_creation_reuses_racing_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"
    first_key_id, _ = integrity._load_or_create_key(guard_home)
    real_open = integrity.os.open
    raced = False

    def raise_file_exists(
        path: str | os.PathLike[str], flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        nonlocal raced
        if dir_fd is not None and path == integrity._KEY_FILENAME and not raced:
            raced = True
            raise FileExistsError(path)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(integrity.os, "open", raise_file_exists)
    second_key_id, _ = integrity._load_or_create_key(guard_home)

    assert raced
    assert first_key_id == second_key_id


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-backed key handling")
def test_posix_key_write_failure_removes_partial_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("simulated key fsync failure")

    monkeypatch.setattr(integrity.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="fsync"):
        integrity._load_or_create_key(guard_home)

    assert not _key_path(guard_home).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-backed key handling")
def test_posix_key_directory_guards_and_permissions(tmp_path: Path) -> None:
    regular = tmp_path / "not-a-directory"
    regular.write_text("not a directory", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        integrity._private_key_directory_descriptor(regular, create=False)

    real_open = integrity.os.open
    regular_descriptor = real_open(regular, os.O_RDONLY)

    def return_regular_descriptor(
        path: str | os.PathLike[str], flags: int, mode: int = 0o777, *args: object, **kwargs: object
    ) -> int:
        if Path(path) == regular:
            return regular_descriptor
        del args, kwargs
        return real_open(path, flags, mode)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(integrity.os, "open", return_regular_descriptor)
    try:
        with pytest.raises(ValueError, match="not a directory"):
            integrity._private_key_directory_descriptor(regular, create=False)
    finally:
        monkeypatch.undo()

    managed = tmp_path / "managed"
    managed.mkdir()
    managed.chmod(0o755)
    with pytest.raises(ValueError, match="permissions"):
        integrity._private_key_directory_descriptor(managed, create=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-backed key handling")
@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"not utf-8: \xff", "invalid format"),
        (b"[]", "invalid format"),
    ],
)
def test_posix_key_loader_rejects_malformed_bytes(tmp_path: Path, raw: bytes, message: str) -> None:
    guard_home = tmp_path / "guard-home"
    managed = guard_home / "managed"
    managed.mkdir(parents=True, mode=0o700)
    key_path = managed / integrity._KEY_FILENAME
    key_path.write_bytes(raw)
    key_path.chmod(0o600)

    assert not adapter_state_is_authenticated(
        guard_home,
        harness="copilot",
        payload={
            "state_authentication": {
                "algorithm": "hmac-sha256",
                "key_id": "id",
                "mac": "0" * 64,
                "schema_version": 1,
            }
        },
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-backed key handling")
def test_posix_key_loader_rejects_nonregular_and_public_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    managed = guard_home / "managed"
    managed.mkdir(parents=True, mode=0o700)
    key_path = managed / integrity._KEY_FILENAME
    key_path.write_text("{}", encoding="utf-8")
    parent_descriptor = os.open(managed, os.O_RDONLY | os.O_DIRECTORY)
    try:

        def report_directory(_fd: int) -> object:
            return SimpleNamespace(st_mode=stat.S_IFDIR)

        monkeypatch.setattr(integrity.os, "fstat", report_directory)
        with pytest.raises(ValueError, match="regular file"):
            integrity._load_key_from_descriptor(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    monkeypatch.undo()

    key_path.write_text(json.dumps(_key_payload()), encoding="utf-8")
    key_path.chmod(0o644)
    assert not adapter_state_is_authenticated(
        guard_home,
        harness="copilot",
        payload={
            "state_authentication": {
                "algorithm": "hmac-sha256",
                "key_id": "id",
                "mac": "0" * 64,
                "schema_version": 1,
            }
        },
    )


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "invalid metadata"),
        ({"schema_version": 1, "key_id": "id"}, "invalid key material"),
        ({"schema_version": 1, "key_id": "id", "key": 7}, "invalid key material"),
        ({"schema_version": 1, "key_id": "id", "key": "é"}, "invalid key material"),
        ({"schema_version": 1, "key_id": "id", "key": "%%%"}, "invalid key length"),
        (
            {"schema_version": 1, "key_id": "id", "key": base64.urlsafe_b64encode(b"short").decode()},
            "invalid key length",
        ),
    ],
)
def test_key_parser_rejects_malformed_key_material(payload: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        integrity._parse_key(payload)


@pytest.mark.parametrize("platform_name", ["darwin", "nt"])
def test_non_posix_key_creation_and_existing_key_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_name: str,
) -> None:
    monkeypatch.setattr(integrity.os, "name", platform_name)
    guard_home = tmp_path / f"guard-{platform_name}"
    first_key_id, _ = integrity._load_or_create_key(guard_home)
    second_key_id, _ = integrity._load_or_create_key(guard_home)

    assert first_key_id == second_key_id
    assert _key_path(guard_home).is_file()
    if platform_name == "darwin":
        assert stat.S_IMODE(_key_path(guard_home).parent.stat().st_mode) == 0o700


def test_non_posix_key_creation_race_and_write_failure_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integrity.os, "name", "darwin")
    guard_home = tmp_path / "guard-home"
    key_path = _key_path(guard_home)
    real_open = integrity.os.open
    raced = False

    def create_then_report_exists(path: str | os.PathLike[str], flags: int, mode: int = 0o777) -> int:
        nonlocal raced
        if Path(path) == key_path and not raced:
            raced = True
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(json.dumps(_key_payload()), encoding="utf-8")
            key_path.chmod(0o600)
            raise FileExistsError(path)
        return real_open(path, flags, mode)

    monkeypatch.setattr(integrity.os, "open", create_then_report_exists)
    key_id, _ = integrity._load_or_create_key(guard_home)
    assert raced
    assert key_id == "race-key"

    failing_home = tmp_path / "failing-home"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("simulated key fsync failure")

    monkeypatch.setattr(integrity.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="fsync"):
        integrity._load_or_create_key(failing_home)
    assert not _key_path(failing_home).exists()


def test_non_posix_key_loader_rejects_directory_permissions_and_bad_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(integrity.os, "name", "darwin")
    guard_home = tmp_path / "guard-home"
    managed = guard_home / "managed"
    managed.mkdir(parents=True)
    key_path = managed / integrity._KEY_FILENAME
    key_path.mkdir()
    assert not integrity.adapter_state_is_authenticated(
        guard_home,
        harness="copilot",
        payload={"state_authentication": {}},
    )

    key_path.rmdir()
    key_path.write_text(json.dumps(_key_payload()), encoding="utf-8")
    key_path.chmod(0o644)
    assert not integrity.adapter_state_is_authenticated(
        guard_home,
        harness="copilot",
        payload={"state_authentication": {}},
    )

    key_path.chmod(0o600)
    key_path.write_text("not json", encoding="utf-8")
    assert not integrity.adapter_state_is_authenticated(
        guard_home,
        harness="copilot",
        payload={"state_authentication": {}},
    )

    key_path.write_text("[]", encoding="utf-8")
    assert not integrity.adapter_state_is_authenticated(
        guard_home,
        harness="copilot",
        payload={"state_authentication": {}},
    )


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
    integrity._load_or_create_key(guard_home)

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
    """Hermes asks for the resident before it rewrites ``config.yaml``."""

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
    _silence_the_resident(monkeypatch)

    with pytest.raises(AdapterStateIntegrityUnavailableError):
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

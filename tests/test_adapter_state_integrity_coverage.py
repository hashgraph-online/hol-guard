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

from codex_plugin_scanner.guard.adapters import adapter_state_integrity as integrity
from codex_plugin_scanner.guard.adapters.adapter_state_integrity import (
    adapter_state_is_authenticated,
    authenticate_adapter_state,
    authenticated_adapter_path,
)


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


def test_authentication_rejects_malformed_metadata_and_paths(tmp_path: Path) -> None:
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
        "mac": b"not-text",
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
    first = authenticate_adapter_state(guard_home, harness="copilot", payload={"generation": 1})
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
    second = authenticate_adapter_state(guard_home, harness="copilot", payload={"generation": 2})

    assert raced
    assert _authentication(first)["key_id"] == _authentication(second)["key_id"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX descriptor-backed key handling")
def test_posix_key_write_failure_removes_partial_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    guard_home = tmp_path / "guard-home"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("simulated key fsync failure")

    monkeypatch.setattr(integrity.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="fsync"):
        authenticate_adapter_state(guard_home, harness="copilot", payload={"generation": 1})

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
    first = authenticate_adapter_state(guard_home, harness="copilot", payload={"generation": 1})
    second = authenticate_adapter_state(guard_home, harness="copilot", payload={"generation": 2})

    assert _authentication(first)["key_id"] == _authentication(second)["key_id"]
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
    authenticated = authenticate_adapter_state(guard_home, harness="copilot", payload={"generation": 1})
    assert raced
    assert _authentication(authenticated)["key_id"] == "race-key"

    failing_home = tmp_path / "failing-home"

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("simulated key fsync failure")

    monkeypatch.setattr(integrity.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="fsync"):
        authenticate_adapter_state(failing_home, harness="copilot", payload={"generation": 2})
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

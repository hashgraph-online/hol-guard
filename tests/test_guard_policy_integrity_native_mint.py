"""The policy-integrity key's first mint asks the native runtime first."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_policy_integrity_backend as policy_integrity_backend_module
from codex_plugin_scanner.guard import store_policy_integrity_key_mint as key_mint_module
from codex_plugin_scanner.guard import store_secret_policy_integrity as secret_policy_module
from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.store import EncryptedFileSecretStore, GuardStore, SystemKeyringSecretStore

_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii")


def _store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "_backend_is_available", classmethod(lambda cls: False))
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    assert type(store._policy_integrity_secret_store) is EncryptedFileSecretStore
    return store


def _no_python_mint(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> str | None:
        raise AssertionError("the Python mint must not run")

    monkeypatch.setattr(secret_policy_module, "mint_policy_integrity_key_once", refuse)


def test_a_native_mint_is_read_back_from_the_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    key_ref = store._policy_integrity_key_ref

    def native_mint(guard_home: Path) -> str:
        assert guard_home == store.guard_home
        secret_store.set_secret(key_ref, _KEY)
        return "present"

    monkeypatch.setattr(secret_policy_module, "native_policy_integrity_key_mint", native_mint)
    _no_python_mint(monkeypatch)

    raw_key, key_id = store._policy_integrity_secret_material(create=True)

    assert raw_key == bytes(range(32))
    assert key_id is not None


@pytest.mark.parametrize("state", ["armed", "busy"])
def test_a_native_refusal_mints_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(secret_policy_module, "native_policy_integrity_key_mint", lambda _home: state)
    _no_python_mint(monkeypatch)

    assert store._policy_integrity_secret_material(create=True) == (None, None)
    assert store._get_policy_integrity_secret_from_store(store._policy_integrity_key_ref) is None


@pytest.mark.parametrize("state", [None, "unavailable"])
def test_without_a_native_mint_python_mints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str | None) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(secret_policy_module, "native_policy_integrity_key_mint", lambda _home: state)

    raw_key, key_id = store._policy_integrity_secret_material(create=True)

    assert raw_key is not None and len(raw_key) == 32
    assert key_id is not None


def test_a_stored_key_asks_no_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    secret_store.set_secret(store._policy_integrity_key_ref, _KEY)

    def no_native(_home: Path) -> str | None:
        raise AssertionError("no mint is needed")

    monkeypatch.setattr(secret_policy_module, "native_policy_integrity_key_mint", no_native)
    _no_python_mint(monkeypatch)

    assert store._policy_integrity_secret_material(create=True)[0] == bytes(range(32))


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        (None, None),
        ({"state": "present"}, "present"),
        ({"state": "armed"}, "armed"),
        ({"state": "busy"}, "busy"),
        ({"state": "unavailable"}, "unavailable"),
        ({"state": "minted"}, None),
        ({"state": 1}, None),
        ({"state": "present", "key": _KEY}, None),
        ({}, None),
    ],
)
def test_only_a_known_state_is_taken_from_the_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    answer: dict[str, object] | None,
    expected: str | None,
) -> None:
    seen: list[tuple[str, str, object]] = []

    def fake_answer(feature: str, command: str, request: object, **kwargs: object) -> dict[str, object] | None:
        seen.append((feature, command, request))
        assert "timeout_seconds" not in kwargs
        assert isinstance(kwargs["deadline"], float)
        return answer

    monkeypatch.setattr(runtime_request, "runtime_answer", fake_answer)

    assert key_mint_module.native_policy_integrity_key_mint(tmp_path) == expected
    assert seen == [
        (
            "native-policy-integrity-key-mint-v1",
            "policy-integrity-key-mint",
            {"guard_home": str(tmp_path.resolve())},
        )
    ]


def test_a_relative_home_is_sent_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_answer(_feature: str, _command: str, request: object, **_kwargs: object) -> dict[str, object]:
        seen.append(request)
        return {"state": "busy"}

    monkeypatch.setattr(runtime_request, "runtime_answer", fake_answer)
    monkeypatch.chdir(tmp_path)

    assert key_mint_module.native_policy_integrity_key_mint(Path("guard-home")) == "busy"
    assert seen == [{"guard_home": str(tmp_path.resolve() / "guard-home")}]

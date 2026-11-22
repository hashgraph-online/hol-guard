"""The policy-integrity key's first mint asks the native runtime first."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import store_policy_integrity_backend as policy_integrity_backend_module
from codex_plugin_scanner.guard import store_policy_integrity_key_mint as key_mint_module
from codex_plugin_scanner.guard import store_secret_policy_integrity as secret_policy_module
from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.store import EncryptedFileSecretStore, GuardStore, SystemKeyringSecretStore
from codex_plugin_scanner.guard.store_policy_integrity_backend import MirroredPolicyIntegritySecretStore

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

    def native_mint(guard_home: Path, *, keyring_service: str | None = None) -> str:
        assert guard_home == store.guard_home
        assert keyring_service is None
        secret_store.set_secret(key_ref, _KEY)
        return "present"

    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", native_mint)
    _no_python_mint(monkeypatch)

    raw_key, key_id = store._policy_integrity_secret_material(create=True)

    assert raw_key == bytes(range(32))
    assert key_id is not None


@pytest.mark.parametrize("state", ["armed", "busy"])
def test_a_native_refusal_mints_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", lambda _home, **_kwargs: state)
    _no_python_mint(monkeypatch)

    assert store._policy_integrity_secret_material(create=True) == (None, None)
    assert store._get_policy_integrity_secret_from_store(store._policy_integrity_key_ref) is None


@pytest.mark.parametrize("state", [None, "unavailable"])
def test_without_a_native_mint_python_mints(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str | None) -> None:
    store = _store(tmp_path, monkeypatch)
    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", lambda _home, **_kwargs: state)

    raw_key, key_id = store._policy_integrity_secret_material(create=True)

    assert raw_key is not None and len(raw_key) == 32
    assert key_id is not None


def test_a_stored_key_asks_no_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store(tmp_path, monkeypatch)
    secret_store = store._policy_integrity_secret_store
    assert secret_store is not None
    secret_store.set_secret(store._policy_integrity_key_ref, _KEY)

    def no_native(_home: Path, **_kwargs: object) -> str | None:
        raise AssertionError("no mint is needed")

    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", no_native)
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
        assert kwargs["environment_keys"] == ()
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


_SERVICE = "hol-guard.policy-integrity"


def _backend(module: str = "keyring.backends.SecretService", name: str = "Keyring", **attributes: object) -> object:
    return type(name, (), {"__module__": module, "preferred_collection": None, **attributes})()


def _keyring(monkeypatch: pytest.MonkeyPatch, backend: object) -> None:
    monkeypatch.setattr(key_mint_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(SystemKeyringSecretStore, "_test_keyring_module", staticmethod(lambda: None))
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_load_keyring_module_or_none",
        classmethod(lambda cls: SimpleNamespace(get_keyring=lambda: backend)),
    )


def _mirrored(home: Path, service: str = _SERVICE) -> MirroredPolicyIntegritySecretStore:
    return MirroredPolicyIntegritySecretStore(
        SystemKeyringSecretStore(service_name=service), EncryptedFileSecretStore(home), guard_home=home
    )


def test_the_secret_service_mirror_asks_the_keyring_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _keyring(monkeypatch, _backend())

    assert key_mint_module.native_mint_keyring_service(tmp_path, _mirrored(tmp_path)) == _SERVICE


@pytest.mark.parametrize(
    "backend",
    [
        _backend(module="keyring.backends.chainer", name="ChainerBackend"),
        _backend(module="keyring.backends.kwallet", name="DBusKeyring"),
        _backend(preferred_collection="/org/freedesktop/secrets/collection/login"),
    ],
)
def test_other_keyring_backends_keep_the_python_mint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: object
) -> None:
    _keyring(monkeypatch, backend)

    assert key_mint_module.native_mint_keyring_service(tmp_path, _mirrored(tmp_path)) is None


def test_only_the_mirrored_policy_store_qualifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _keyring(monkeypatch, _backend())

    assert key_mint_module.native_mint_keyring_service(tmp_path, EncryptedFileSecretStore(tmp_path)) is None
    assert key_mint_module.native_mint_keyring_service(tmp_path, _mirrored(tmp_path, "other-service")) is None
    assert key_mint_module.native_mint_keyring_service(tmp_path / "elsewhere", _mirrored(tmp_path)) is None
    monkeypatch.setattr(key_mint_module.sys, "platform", "darwin", raising=False)
    assert key_mint_module.native_mint_keyring_service(tmp_path, _mirrored(tmp_path)) is None


def test_a_test_keyring_keeps_the_python_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _keyring(monkeypatch, _backend())
    monkeypatch.setattr(SystemKeyringSecretStore, "_test_keyring_module", staticmethod(lambda: object()))

    assert key_mint_module.native_mint_keyring_service(tmp_path, _mirrored(tmp_path)) is None


def test_the_keyring_mint_names_its_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, object]] = []

    def fake_answer(feature: str, _command: str, request: object, **kwargs: object) -> dict[str, object]:
        seen.append((feature, request))
        assert kwargs["environment_keys"] == ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR")
        return {"state": "busy"}

    monkeypatch.setattr(runtime_request, "runtime_answer", fake_answer)

    assert key_mint_module.native_policy_integrity_key_mint(tmp_path, keyring_service=_SERVICE) == "busy"
    assert seen == [
        (
            "native-policy-integrity-key-mint-secret-service-v1",
            {"guard_home": str(tmp_path.resolve()), "keyring": {"service_name": _SERVICE}},
        )
    ]


def test_the_store_hands_its_keyring_service_to_the_native_mint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path, monkeypatch)
    seen: list[str | None] = []

    def native_mint(_home: Path, *, keyring_service: str | None = None) -> str:
        seen.append(keyring_service)
        return "armed"

    monkeypatch.setattr(key_mint_module, "native_mint_keyring_service", lambda _home, _store: _SERVICE)
    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", native_mint)
    _no_python_mint(monkeypatch)

    assert store._policy_integrity_secret_material(create=True) == (None, None)
    assert seen == [_SERVICE]


def test_a_relative_home_is_sent_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[object] = []

    def fake_answer(_feature: str, _command: str, request: object, **_kwargs: object) -> dict[str, object]:
        seen.append(request)
        return {"state": "busy"}

    monkeypatch.setattr(runtime_request, "runtime_answer", fake_answer)
    monkeypatch.chdir(tmp_path)

    assert key_mint_module.native_policy_integrity_key_mint(Path("guard-home")) == "busy"
    assert seen == [{"guard_home": str(tmp_path.resolve() / "guard-home")}]


def test_other_stores_ask_no_native_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_native(_home: Path, **_kwargs: object) -> str | None:
        raise AssertionError("only qualifying stores ask the native mint")

    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", no_native)

    assert key_mint_module.native_mint_for_store(tmp_path, object()) is None


def test_named_bus_variables_reach_the_native_child(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/example/bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/example")

    plain = native_runtime._isolated_environment()
    extended = native_runtime._isolated_environment_with(("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"))

    assert "DBUS_SESSION_BUS_ADDRESS" not in plain and "XDG_RUNTIME_DIR" not in plain
    assert extended["DBUS_SESSION_BUS_ADDRESS"] == "unix:path=/run/example/bus"
    assert extended["XDG_RUNTIME_DIR"] == "/run/example"


def _asked_vault_mint(monkeypatch: pytest.MonkeyPatch) -> list[str | None]:
    seen: list[str | None] = []

    def native_mint(_home: Path, *, keyring_service: str | None = None) -> str:
        seen.append(keyring_service)
        return "present"

    monkeypatch.setattr(key_mint_module, "native_policy_integrity_key_mint", native_mint)
    return seen


def test_the_windows_vault_store_asks_the_vault_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.store_policy_integrity_windows import WindowsPolicyIntegritySecretStore

    seen = _asked_vault_mint(monkeypatch)
    store = WindowsPolicyIntegritySecretStore(
        SystemKeyringSecretStore(service_name=_SERVICE), EncryptedFileSecretStore(tmp_path)
    )

    assert key_mint_module.native_mint_for_store(tmp_path, store) == "present"
    assert key_mint_module.native_mint_for_store(tmp_path, EncryptedFileSecretStore(tmp_path)) == "present"
    assert seen == [None, None]


def test_a_vault_outside_the_guard_home_keeps_the_python_mint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.store_policy_integrity_windows import WindowsPolicyIntegritySecretStore

    seen = _asked_vault_mint(monkeypatch)
    elsewhere = EncryptedFileSecretStore(tmp_path / "elsewhere")
    store = WindowsPolicyIntegritySecretStore(SystemKeyringSecretStore(service_name=_SERVICE), elsewhere)

    assert key_mint_module.native_mint_for_store(tmp_path, store) is None
    assert key_mint_module.native_mint_for_store(tmp_path, elsewhere) is None
    assert seen == []

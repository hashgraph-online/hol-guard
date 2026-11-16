"""Reuse of a resolved Cloud sign-in across command queue polls."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime import command_queue_auth

_STATE_KEY = "oauth-local-credentials"


class _Store:
    _oauth_local_credentials_state_key = _STATE_KEY

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.records: dict[str, object] = {_STATE_KEY: {"key_id": "first", "issuer": "https://issuer.test"}}

    def get_sync_payload(self, key: str) -> object:
        return self.records.get(key)


class _Resolver:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, _store: object, **_kwargs: object) -> dict[str, object]:
        self.calls += 1
        return {"sync_url": "https://cloud.test/sync", "resolved": self.calls}


def _reuse(store: _Store, resolver: _Resolver) -> dict[str, object]:
    return command_queue_auth.reuse_command_queue_auth_context(store, resolve_auth_context=resolver)  # pyright: ignore[reportArgumentType]


def test_an_unchanged_sign_in_is_resolved_once(tmp_path: Path) -> None:
    store, resolver = _Store(tmp_path), _Resolver()

    assert _reuse(store, resolver) == _reuse(store, resolver)
    assert resolver.calls == 1


def test_a_new_sign_in_is_resolved_on_the_next_poll(tmp_path: Path) -> None:
    store, resolver = _Store(tmp_path), _Resolver()
    _reuse(store, resolver)

    store.records[_STATE_KEY] = {"key_id": "second", "issuer": "https://issuer.test"}

    assert _reuse(store, resolver)["resolved"] == 2


def test_a_signed_out_home_is_never_served_the_previous_sign_in(tmp_path: Path) -> None:
    store, resolver = _Store(tmp_path), _Resolver()
    _reuse(store, resolver)

    del store.records[_STATE_KEY]

    assert _reuse(store, resolver)["resolved"] == 2
    assert _reuse(store, resolver)["resolved"] == 3


def test_a_forced_refresh_skips_the_reused_context(tmp_path: Path) -> None:
    store, resolver = _Store(tmp_path), _Resolver()
    _reuse(store, resolver)

    refreshed = command_queue_auth.reuse_command_queue_auth_context(
        store,  # pyright: ignore[reportArgumentType]
        force_refresh=True,
        resolve_auth_context=resolver,
    )

    assert refreshed["resolved"] == 2

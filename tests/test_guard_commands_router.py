from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local, commands_router
from codex_plugin_scanner.guard.store import GuardStore


def test_normalize_guard_handler_result_treats_none_as_success() -> None:
    assert commands_router._normalize_guard_handler_result(None) == 0
    assert commands_router._normalize_guard_handler_result(2) == 2
    assert commands_router._normalize_guard_handler_result({"status": "unexpected"}) == 1


def test_only_daemon_server_eagerly_primes_policy_integrity() -> None:
    assert commands_router._should_prime_policy_integrity(Namespace(guard_command="daemon", serve=True))
    assert not commands_router._should_prime_policy_integrity(Namespace(guard_command="daemon", serve=False))
    assert not commands_router._should_prime_policy_integrity(Namespace(guard_command="trust"))
    assert not commands_router._should_prime_policy_integrity(Namespace(guard_command="codex-mcp-proxy"))
    assert not commands_router._should_prime_policy_integrity(Namespace(guard_command="hook"))


def test_only_explicit_account_actions_allow_system_keyring() -> None:
    for command in ("connect", "disconnect", "login", "remote-pair"):
        assert commands_router._should_allow_system_keyring(Namespace(guard_command=command))
    for command in ("daemon", "hook", "status", "sync", "codex-mcp-proxy"):
        assert not commands_router._should_allow_system_keyring(Namespace(guard_command=command))


def test_foreground_migration_stops_after_first_failed_keychain_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PassiveStore:
        guard_home = tmp_path

        @staticmethod
        def legacy_macos_oauth_secret_migration_required() -> bool:
            return True

        @staticmethod
        def legacy_extension_control_authority_secret_migration_required() -> bool:
            return True

    migration_calls: list[str] = []

    class ExplicitStore:
        @staticmethod
        def migrate_legacy_macos_oauth_secret() -> bool:
            migration_calls.append("oauth")
            return False

        @staticmethod
        def migrate_legacy_extension_control_authority_secrets() -> bool:
            migration_calls.append("extension")
            return True

    monkeypatch.setattr(commands_dispatch_local, "GuardStore", lambda *_args, **_kwargs: ExplicitStore())

    commands_dispatch_local._migrate_legacy_macos_secrets(cast(GuardStore, PassiveStore()))

    assert migration_calls == ["oauth"]

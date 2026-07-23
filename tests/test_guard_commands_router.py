from __future__ import annotations

from argparse import Namespace

from codex_plugin_scanner.guard.cli import commands_router


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

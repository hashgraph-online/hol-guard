"""Coverage for the verdict-derived native-unavailable exit-code mapper."""
import argparse
import pytest

from codex_plugin_scanner.guard.cli.commands_hook_native_availability import (
    _availability_response_is_deny,
    _native_unavailable_exit_code,
)


def _args(harness):
    return argparse.Namespace(harness=harness)


class TestAvailabilityResponseIsDeny:
    def test_non_mapping_is_not_deny(self):
        assert _availability_response_is_deny("deny") is False
        assert _availability_response_is_deny(None) is False
        assert _availability_response_is_deny(2) is False

    def test_cursor_permission_deny(self):
        assert _availability_response_is_deny({"permission": "deny"}) is True
        assert _availability_response_is_deny({"permission": "DENY"}) is True
        assert _availability_response_is_deny({"permission": "allow"}) is False
        assert _availability_response_is_deny({"permission": "ask"}) is False

    def test_hook_specific_output_permission_decision(self):
        body = {"hookSpecificOutput": {"permissionDecision": "deny"}}
        assert _availability_response_is_deny(body) is True
        body = {"hookSpecificOutput": {"permissionDecision": "allow"}}
        assert _availability_response_is_deny(body) is False

    def test_hook_specific_output_decision(self):
        for verdict in ("deny", "block", "review"):
            body = {"hookSpecificOutput": {"decision": verdict}}
            assert _availability_response_is_deny(body) is True, verdict
        body = {"hookSpecificOutput": {"decision": "allow"}}
        assert _availability_response_is_deny(body) is False

    def test_policy_action_blocking_set(self):
        for action in ("deny", "block", "review", "require-reapproval", "sandbox-required"):
            assert _availability_response_is_deny({"policy_action": action}) is True, action
        for action in ("allow", "warn", "observe"):
            assert _availability_response_is_deny({"policy_action": action}) is False, action

    def test_empty_response_not_deny(self):
        assert _availability_response_is_deny({}) is False
        assert _availability_response_is_deny({"reason_code": "x"}) is False


class TestNativeUnavailableExitCode:
    def test_cursor_deny_rc2_allow_rc0(self):
        assert _native_unavailable_exit_code(_args("cursor"), {"permission": "deny"}, "PreToolUse") == 2
        assert _native_unavailable_exit_code(_args("cursor"), {"permission": "allow"}, "PreToolUse") == 0

    def test_grok_deny_uses_adapter(self):
        # grok_hook_process_exit returns 2 for blocking action, 0 for allow.
        deny_rc = _native_unavailable_exit_code(_args("grok"), {"policy_action": "block"}, "PreToolUse")
        allow_rc = _native_unavailable_exit_code(_args("grok"), {"policy_action": "allow"}, "PreToolUse")
        assert deny_rc == 2
        assert allow_rc == 0

    def test_zcode_block_and_ask(self):
        # zcode: block -> 2, but PreToolUse ask -> 0 (prompt opens).
        assert _native_unavailable_exit_code(_args("zcode"), {"policy_action": "block"}, "PreToolUse") == 2
        assert _native_unavailable_exit_code(_args("zcode"), {"policy_action": "allow"}, "PreToolUse") == 0

    def test_devin_and_generic(self):
        assert _native_unavailable_exit_code(_args("devin"), {"policy_action": "block"}, "PreToolUse") == 2
        assert _native_unavailable_exit_code(_args("devin"), {"policy_action": "allow"}, "PreToolUse") == 0
        # generic/codex/kimi/opencode: deny -> 1, allow -> 0
        for h in ("codex", "kimi", "opencode", "omp", "pi"):
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "block"}, "PreToolUse") == 1, h
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "allow"}, "PreToolUse") == 0, h

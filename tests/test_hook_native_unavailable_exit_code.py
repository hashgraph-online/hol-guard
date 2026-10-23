"""Coverage for the verdict-derived native-hook exit-code contract.

Exercises both the shared ``native_hook_verdict_exit_code`` table and the
availability wrapper ``_native_unavailable_exit_code`` that feeds an emitted
deny/allow envelope through it.
"""

import argparse
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_hook_native_availability import (
    _availability_response_is_deny,
    _native_unavailable_exit_code,
)
from codex_plugin_scanner.guard.cli.native_hook_exit_code import (
    _BLOCKING_ACTIONS,
    _PREEMPTIVE_EVENTS,
    _RC_BLOCK_IS_ONE,
    _RC_BLOCK_IS_TWO,
    _RC_BLOCK_IS_ZERO_ENVELOPE,
    native_hook_verdict_exit_code,
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
        assert _availability_response_is_deny({"hookSpecificOutput": {"permissionDecision": "deny"}}) is True
        assert _availability_response_is_deny({"hookSpecificOutput": {"permissionDecision": "allow"}}) is False

    def test_hook_specific_output_decision(self):
        for verdict in ("deny", "block", "review"):
            assert _availability_response_is_deny({"hookSpecificOutput": {"decision": verdict}}) is True, verdict
        assert _availability_response_is_deny({"hookSpecificOutput": {"decision": "allow"}}) is False

    def test_policy_action_blocking_set(self):
        for action in ("deny", "block", "review", "require-reapproval", "sandbox-required"):
            assert _availability_response_is_deny({"policy_action": action}) is True, action
        for action in ("allow", "warn", "observe"):
            assert _availability_response_is_deny({"policy_action": action}) is False, action

    def test_empty_response_not_deny(self):
        assert _availability_response_is_deny({}) is False
        assert _availability_response_is_deny({"reason_code": "x"}) is False


class TestVerdictExitCodeContract:
    """The shared table every emit path delegates to."""

    @pytest.mark.parametrize("h", ("cursor", "devin", "kimi", "hermes"))
    def test_rc_block_is_two(self, h):
        assert native_hook_verdict_exit_code(h, "block") == 2
        assert native_hook_verdict_exit_code(h, "allow") == 0
        assert native_hook_verdict_exit_code(h, "review") == 2

    @pytest.mark.parametrize("h", ("opencode", "superagent"))
    def test_rc_block_is_one(self, h):
        # rc-driven generic contract: exitCode 1 -> block, 0 -> allow.
        assert native_hook_verdict_exit_code(h, "block") == 1
        assert native_hook_verdict_exit_code(h, "allow") == 0

    @pytest.mark.parametrize("h", ("codex", "claude-code", "copilot", "pi", "omp"))
    def test_envelope_driven_deny_rc0(self, h):
        # Deny rides the decision envelope (permissionDecision / decision);
        # a nonzero PREEMPTIVE rc would read as a hook error and permit the
        # action.  Gauntlet-verified for omp.
        assert native_hook_verdict_exit_code(h, "block", "PreToolUse") == 0
        assert native_hook_verdict_exit_code(h, "block", "UserPromptSubmit") == 0
        assert native_hook_verdict_exit_code(h, "block", "PermissionRequest") == 0
        assert native_hook_verdict_exit_code(h, "allow", "PreToolUse") == 0

    @pytest.mark.parametrize("h", ("codex", "claude-code", "copilot", "pi", "omp"))
    def test_envelope_post_tool_block_rc1(self, h):
        # PostToolUse cannot preempt (the tool already ran) — a blocking
        # verdict flags the violation on the exit status instead.
        assert native_hook_verdict_exit_code(h, "block", "PostToolUse") == 1
        assert native_hook_verdict_exit_code(h, "allow", "PostToolUse") == 0

    def test_unknown_harness_fails_safe(self):
        assert native_hook_verdict_exit_code("some-future-harness", "block") == 1
        assert native_hook_verdict_exit_code("some-future-harness", "allow") == 0


class TestNativeUnavailableExitCode:
    """The availability wrapper must route deny->block and allow->allow."""

    def test_cursor_deny_rc2_allow_rc0(self):
        assert _native_unavailable_exit_code(_args("cursor"), {"permission": "deny"}, "PreToolUse") == 2
        assert _native_unavailable_exit_code(_args("cursor"), {"permission": "allow"}, "PreToolUse") == 0

    def test_grok_uses_adapter(self, monkeypatch):
        from codex_plugin_scanner.guard.adapters import grok_hooks

        monkeypatch.setattr(grok_hooks, "_last_grok_policy_action", "block")
        assert _native_unavailable_exit_code(_args("grok"), {"policy_action": "block"}, "PreToolUse") == 2
        monkeypatch.setattr(grok_hooks, "_last_grok_policy_action", "allow")
        assert _native_unavailable_exit_code(_args("grok"), {"policy_action": "allow"}, "PreToolUse") == 0

    def test_zcode_block(self):
        assert _native_unavailable_exit_code(_args("zcode"), {"policy_action": "block"}, "PreToolUse") == 2
        assert _native_unavailable_exit_code(_args("zcode"), {"policy_action": "allow"}, "PreToolUse") == 0

    def test_devin(self):
        assert _native_unavailable_exit_code(_args("devin"), {"policy_action": "block"}, "PreToolUse") == 2

    def test_envelope_driven_deny_rc0(self):
        for h in ("codex", "claude-code"):
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "block"}, "PreToolUse") == 0, h
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "allow"}, "PreToolUse") == 0, h

    def test_envelope_harnesses_deny_rc0(self):
        for h in ("pi", "omp"):
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "block"}, "PreToolUse") == 0, h
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "allow"}, "PreToolUse") == 0, h

    def test_rc_driven_deny_rc1(self):
        for h in ("opencode", "superagent"):
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "block"}, "PreToolUse") == 1, h
            assert _native_unavailable_exit_code(_args(h), {"policy_action": "allow"}, "PreToolUse") == 0, h


class TestRustTableParity:
    """The unavailable path is the one place Python decides an exit code itself.

    Everywhere else the resident's directive carries it
    (``rust/crates/guard-runtime/src/hook_decision_directive.rs``). Native is
    gone by definition on this path, so the table cannot be fetched from the
    resident and has to be restated here -- which makes it the second source
    of truth for a contract the hosts read. This pins the two together: the
    harness sets and preemptive events are parsed out of the Rust source, and
    every harness/action/event the two share has to resolve the same way.
    """

    RUST_DIRECTIVE = Path(__file__).resolve().parents[1] / "rust/crates/guard-runtime/src/hook_decision_directive.rs"
    ACTIONS = (
        "allow",
        "observe",
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    )
    EVENTS = (
        "PreToolUse",
        "UserPromptSubmit",
        "PermissionRequest",
        "PostToolUse",
        None,
    )

    @classmethod
    def _rust_list(cls, name):
        source = cls.RUST_DIRECTIVE.read_text(encoding="utf-8")
        match = re.search(rf"const {name}: \[&str; \d+\] = \[(.*?)\];", source, re.DOTALL)
        assert match, f"{name} is no longer declared in {cls.RUST_DIRECTIVE.name}"
        return tuple(re.findall(r'"([^"]+)"', match.group(1)))

    def test_harness_sets_match_the_resident_directive(self):
        # Each table is pinned twice: against the literal the contract was
        # written with, and against the Python set the CLI actually reads.
        # Comparing only with the literal would let a Python-only addition
        # pass; comparing only the two tables would let both drift together.
        for rust_name, python_set, expected in (
            ("EXIT_TWO_HARNESSES", _RC_BLOCK_IS_TWO, {"cursor", "devin", "kimi", "hermes"}),
            ("EXIT_ONE_HARNESSES", _RC_BLOCK_IS_ONE, {"opencode", "superagent"}),
            (
                "ENVELOPE_HARNESSES",
                _RC_BLOCK_IS_ZERO_ENVELOPE,
                {"codex", "claude-code", "copilot", "pi", "omp"},
            ),
            (
                "PREEMPTIVE_EVENTS",
                _PREEMPTIVE_EVENTS,
                {"PreToolUse", "UserPromptSubmit", "PermissionRequest"},
            ),
        ):
            rust_set = set(self._rust_list(rust_name))
            assert rust_set == expected, f"{rust_name} changed in the resident"
            assert set(python_set) == expected, f"{rust_name} drifted on the Python side"

    def test_blocking_actions_match_the_contract(self):
        # The resident declares no blocking-action array to parse, so the
        # Python set is pinned to the literal the exit-code contract names.
        assert set(_BLOCKING_ACTIONS) == {
            "review",
            "require-reapproval",
            "sandbox-required",
            "block",
        }

    def test_every_shared_harness_resolves_the_same_exit_code(self):
        # Expectations come from the resident's own arrays, not from the
        # Python tables the function under test reads.
        blocking = {"review", "require-reapproval", "sandbox-required", "block"}
        two = set(self._rust_list("EXIT_TWO_HARNESSES"))
        one = set(self._rust_list("EXIT_ONE_HARNESSES"))
        envelope = set(self._rust_list("ENVELOPE_HARNESSES"))
        preemptive = set(self._rust_list("PREEMPTIVE_EVENTS"))
        # grok and zcode keep their adapter's own contract on both sides and
        # are covered by the cases above; everything else is table-driven.
        for harness in sorted(two | one | envelope | {"unknown-harness"}):
            for action in self.ACTIONS:
                for event in self.EVENTS:
                    blocks = action in blocking
                    if harness in two:
                        expected = 2 if blocks else 0
                    elif harness in one:
                        expected = int(blocks)
                    elif harness in envelope:
                        expected = int(blocks and event not in preemptive)
                    else:
                        expected = int(blocks)
                    assert native_hook_verdict_exit_code(harness, action, event_name=event) == expected, (
                        f"{harness}/{action}/{event} drifted from the resident's table"
                    )

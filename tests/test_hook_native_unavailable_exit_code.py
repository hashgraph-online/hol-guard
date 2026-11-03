"""Coverage for the verdict-derived native-hook exit-code contract."""

import re
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.native_hook_exit_code import (
    _BLOCKING_ACTIONS,
    _PREEMPTIVE_EVENTS,
    _RC_BLOCK_IS_ONE,
    _RC_BLOCK_IS_TWO,
    _RC_BLOCK_IS_ZERO_ENVELOPE,
    native_hook_verdict_exit_code,
)


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

    @pytest.mark.parametrize("h", ("codex", "claude-code", "copilot", "pi", "omp", "muse"))
    def test_envelope_driven_deny_rc0(self, h):
        # Deny rides the decision envelope (permissionDecision / decision);
        # a nonzero PREEMPTIVE rc would read as a hook error and permit the
        # action.  Gauntlet-verified for omp.
        assert native_hook_verdict_exit_code(h, "block", "PreToolUse") == 0
        assert native_hook_verdict_exit_code(h, "block", "UserPromptSubmit") == 0
        assert native_hook_verdict_exit_code(h, "block", "PermissionRequest") == 0
        assert native_hook_verdict_exit_code(h, "allow", "PreToolUse") == 0

    @pytest.mark.parametrize("h", ("codex", "claude-code", "copilot", "pi", "omp", "muse"))
    def test_envelope_post_tool_block_rc1(self, h):
        # PostToolUse cannot preempt (the tool already ran) — a blocking
        # verdict flags the violation on the exit status instead.
        assert native_hook_verdict_exit_code(h, "block", "PostToolUse") == 1
        assert native_hook_verdict_exit_code(h, "allow", "PostToolUse") == 0

    def test_unknown_harness_fails_safe(self):
        assert native_hook_verdict_exit_code("some-future-harness", "block") == 1
        assert native_hook_verdict_exit_code("some-future-harness", "allow") == 0


class TestUnknownActionFailsClosed:
    """An action outside the lattice is not evidence of permission.

    ``policy_action`` reaches this table as a bare string decoded from the
    resident's response, so a newer resident, a truncated value or a corrupted
    field can name an action this build has never heard of. Testing membership
    in the blocking set made every such value non-blocking, which is the one
    direction the contract cannot afford. The lattice normalizes an unknown
    action to the review tier instead, so each harness renders its own
    review-tier code.
    """

    UNKNOWN = ("quarantine-required", "", "BLOCK", "ask ", "deny", "0")

    @pytest.fixture(autouse=True)
    def _protection_is_on(self, monkeypatch):
        # grok reads the Guard home to honour recording-only mode, which would
        # otherwise answer 0 for every action regardless of the lattice.
        monkeypatch.delenv("HOL_GUARD_HOME", raising=False)
        monkeypatch.setattr(sys, "argv", ["hol-guard"])

    @pytest.mark.parametrize("action", UNKNOWN)
    @pytest.mark.parametrize("h", ("cursor", "devin", "kimi", "hermes", "grok"))
    def test_rc_two_harnesses_block_an_unknown_action(self, action, h):
        assert native_hook_verdict_exit_code(h, action, "PreToolUse") == 2
        assert native_hook_verdict_exit_code(h, action, "PostToolUse") == 2

    @pytest.mark.parametrize("action", UNKNOWN)
    @pytest.mark.parametrize("h", ("opencode", "superagent", "some-future-harness"))
    def test_rc_one_harnesses_block_an_unknown_action(self, action, h):
        assert native_hook_verdict_exit_code(h, action, "PreToolUse") == 1
        assert native_hook_verdict_exit_code(h, action, "PostToolUse") == 1

    @pytest.mark.parametrize("action", UNKNOWN)
    @pytest.mark.parametrize("h", ("codex", "claude-code", "copilot", "pi", "omp", "muse"))
    def test_envelope_harnesses_flag_an_unknown_action_after_the_fact(self, action, h):
        # The envelope carries the deny before execution, so a preemptive
        # event still exits 0; PostToolUse has nothing left to preempt and
        # resolves to the review tier's nonzero status.
        assert native_hook_verdict_exit_code(h, action, "PreToolUse") == 0
        assert native_hook_verdict_exit_code(h, action, "PostToolUse") == 1

    @pytest.mark.parametrize("action", UNKNOWN)
    def test_zcode_treats_an_unknown_action_as_review(self, action):
        # zcode discards stdout when a hook exits 2, so its review tier has to
        # exit 0 for the ``ask`` envelope to reach the permission prompt. Every
        # other event takes the blocking status.
        assert native_hook_verdict_exit_code("zcode", action, "PreToolUse") == 0
        assert native_hook_verdict_exit_code("zcode", action, "PostToolUse") == 2

    @pytest.mark.parametrize("h", ("cursor", "opencode", "codex", "grok", "zcode", "some-future-harness"))
    def test_a_non_string_action_never_reads_as_allow(self, h):
        # A decoder that hands back ``None`` or a number has not established
        # permission either.
        for action in (None, 7, {"policy_action": "allow"}, ["allow"]):
            assert native_hook_verdict_exit_code(h, action, "PostToolUse") == native_hook_verdict_exit_code(
                h, "review", "PostToolUse"
            )

    @pytest.mark.parametrize("h", ("cursor", "opencode", "codex", "grok", "zcode"))
    def test_the_legacy_ask_alias_resolves_to_review(self, h):
        # ``ask`` predates the lattice and used to exit 0 everywhere; the
        # lattice maps it onto ``review`` rather than onto a permissive rank.
        for event in ("PreToolUse", "PostToolUse"):
            assert native_hook_verdict_exit_code(h, "ask", event) == native_hook_verdict_exit_code(h, "review", event)


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
        "warn",
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
                {"codex", "claude-code", "copilot", "pi", "omp", "muse"},
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

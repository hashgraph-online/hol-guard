"""Structured rules and metadata for the agi-memory command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    _after_leading_options,
    _segment_matches_executable,
)

# Surface verified against agi-memory 0.5.0 (mcp_server.py dispatch, sync.py
# argparse, pyproject console_scripts).
#
# The four reviewed operations mutate persistent agent memory:
# - `sync dedupe` rewrites the canonical append-only JSONL vault in place. It is
#   the only operation in the tool that rewrites rather than appends, and it has
#   collapsed distinct observations into one before.
# - `delete <id> --hard` permanently removes an observation, cascades into the
#   facts promoted from it, and appends a vault tombstone that propagates the
#   deletion to every other machine on the next sync.
# - `pin` writes a core-memory block that is injected into every later session.
# - `unpin` removes one, silently dropping an invariant later sessions relied on.
#
# Reads stay out of scope by design: `sync status`, `log`, `inspect`, `blocks`,
# `recall`, `timeline` and the code-graph queries are side-effect free, and
# gating them would put a prompt in front of every lookup.
#
# Two properties of this CLI drive the matcher shape:
#
# 1. Four console scripts reach the same entry point. `agent-memory` is an exact
#    alias of `agi-memory` and both ship in every install, so a rule naming only
#    one is bypassed by typing the other.
# 2. `sync` dispatches on a literal positional subcommand. Only `status`, `now`,
#    `dedupe` and `init` reach the sync module; every other form (including bare
#    `agi-memory sync`) falls through to the installer, so `dedupe` must be
#    matched as an exact positional rather than by prefix.
_AGI_MEMORY_EXECUTABLES: tuple[str, ...] = ("agi-memory", "agent-memory")
_AGI_MEMORY_MODULES: tuple[str, ...] = ("agi_memory.mcp_server",)
_PYTHON_LAUNCHERS: tuple[str, ...] = ("python", "python3", "py")
_SHELL_WRAPPERS: tuple[str, ...] = ("exec", "xargs")


def _launchers() -> tuple[tuple[str, ...], ...]:
    """Every argv prefix that reaches the agi-memory CLI."""
    direct: list[tuple[str, ...]] = [(name,) for name in _AGI_MEMORY_EXECUTABLES]
    direct += [(interpreter, "-m", module) for interpreter in _PYTHON_LAUNCHERS for module in _AGI_MEMORY_MODULES]
    wrapped = [(wrapper, *launcher) for wrapper in _SHELL_WRAPPERS for launcher in direct]
    return (*direct, *wrapped)


_AGI_MEMORY_LAUNCHERS: tuple[tuple[str, ...], ...] = _launchers()
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})

# argparse resolves any unambiguous long-option prefix. `delete` declares
# --hard alongside argparse's own --help, so --h is ambiguous and exits without
# deleting anything; --ha is the shortest prefix that actually means --hard.
_HARD_FLAGS: tuple[str, ...] = ("--hard", "--har", "--ha")
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})

_AGI_MEMORY_SYNC_DEDUPE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "sync",
            "dedupe",
            allow_leading_options=launcher[0] in _SHELL_WRAPPERS,
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in _SHELL_WRAPPERS else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AGI_MEMORY_LAUNCHERS
    )
)

_AGI_MEMORY_DELETE_HARD = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "delete",
            required_flags=frozenset({hard_flag}),
            allow_leading_options=launcher[0] in _SHELL_WRAPPERS,
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in _SHELL_WRAPPERS else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AGI_MEMORY_LAUNCHERS
        for hard_flag in _HARD_FLAGS
    )
)

_AGI_MEMORY_PIN = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "pin",
            options_with_values=frozenset({"--category", "-c", "--project", "-p"}),
            allow_leading_options=launcher[0] in _SHELL_WRAPPERS,
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in _SHELL_WRAPPERS else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AGI_MEMORY_LAUNCHERS
    )
)

_AGI_MEMORY_UNPIN = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "unpin",
            allow_leading_options=launcher[0] in _SHELL_WRAPPERS,
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in _SHELL_WRAPPERS else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AGI_MEMORY_LAUNCHERS
    )
)


@dataclass(frozen=True, slots=True)
class AgiMemoryUnresolvedExpansionMatcher:
    """Match agi-memory commands whose arguments may be supplied by expansion.

    A `$VAR`, `${VAR}`, `$(...)` or backtick token can expand at execution time
    into the argument that makes the command destructive: `dedupe` after `sync`,
    which is a positional subcommand, or `--hard` after `delete`, which is a
    flag. Either way the destructive form cannot be proven absent.
    """

    subcommand: str
    launchers: tuple[tuple[str, ...], ...] = _AGI_MEMORY_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS
    detail: str = "Matched agi-memory arguments that may expand to destructive operations."

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                candidate_arguments = lowered_arguments
                if launcher[0] in _SHELL_WRAPPERS:
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                prefix = (*launcher[1:], self.subcommand)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                remaining_arguments = candidate_arguments[len(prefix) :]
                if any(
                    any(marker in argument for marker in self.expansion_markers) for argument in remaining_arguments
                ):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail=self.detail,
                        )
                    )
                break
        return tuple(evidence)


# The literal matchers stay free of custom children so `--help` safe variants
# keep cloning pure executable matchers; each rule adds its expansion overlay on
# top, exactly as the repo2nb extension does.
_AGI_MEMORY_SYNC_DEDUPE_WITH_EXPANSIONS = AnyMatcher(
    matchers=(
        *_AGI_MEMORY_SYNC_DEDUPE.matchers,
        AgiMemoryUnresolvedExpansionMatcher(
            subcommand="sync",
            detail="Matched agi-memory sync arguments that may expand to the dedupe subcommand.",
        ),
    ),
)

_AGI_MEMORY_DELETE_HARD_WITH_EXPANSIONS = AnyMatcher(
    matchers=(
        *_AGI_MEMORY_DELETE_HARD.matchers,
        AgiMemoryUnresolvedExpansionMatcher(
            subcommand="delete",
            detail="Matched agi-memory delete arguments that may expand to --hard.",
        ),
    ),
)

AGI_MEMORY_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.agi-memory.sync-dedupe",
        title="agi-memory vault deduplication",
        description=(
            "Identifies `agi-memory sync dedupe`, which rewrites the canonical "
            "append-only memory vault in place. It is the only agi-memory "
            "operation that rewrites rather than appends, it prunes records it "
            "judges redundant, and a similarity key that merges two distinct "
            "memories destroys the loser with no undo. Sync invocations "
            "carrying unresolved shell expansions are reviewed because they "
            "cannot prove the dedupe subcommand absent."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("agi-memory vault rewrite command",),
        safer_alternatives=(
            "Run agi-memory sync status first to see the vault state that dedupe would rewrite.",
            (
                "Copy ~/.agi-memory/vault (or $AGI_MEMORY_VAULT) before compacting: the vault is the "
                "canonical store and the SQLite index is only derived from it."
            ),
            "Expand shell variables and command substitutions before running agi-memory sync.",
        ),
        matcher=_AGI_MEMORY_SYNC_DEDUPE_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AGI_MEMORY_SYNC_DEDUPE,
                variant_id="help",
                title="agi-memory sync command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.agi-memory.delete-hard",
        title="agi-memory permanent memory deletion",
        description=(
            "Identifies `agi-memory delete <id> --hard`, which permanently "
            "removes an observation rather than marking it superseded. The "
            "delete cascades into the long-term facts promoted from that "
            "observation and appends a vault tombstone, so the removal "
            "propagates to every other machine sharing the vault on the next "
            "sync. Delete invocations carrying unresolved shell expansions are "
            "reviewed because they cannot prove --hard absent."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("agi-memory permanent memory deletion command",),
        safer_alternatives=(
            "Run agi-memory inspect <id> first to confirm which memory the id refers to.",
            "Omit --hard to soft-delete, which marks the observation superseded and is reversible.",
            "Expand shell variables and command substitutions before running agi-memory delete.",
        ),
        matcher=_AGI_MEMORY_DELETE_HARD_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AGI_MEMORY_DELETE_HARD,
                variant_id="help",
                title="agi-memory delete command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.agi-memory.pin",
        title="agi-memory core memory pin",
        description=(
            "Identifies `agi-memory pin`, which writes a core-memory block that "
            "is injected into the context of every later session for the "
            "project. Pinning under an existing key overwrites that block, "
            "replacing an invariant later sessions were relying on."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("agi-memory core memory pin command",),
        safer_alternatives=(
            "Run agi-memory blocks first to see whether the key already holds a different invariant.",
            "Choose a new key rather than overwriting an existing block.",
        ),
        matcher=_AGI_MEMORY_PIN,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AGI_MEMORY_PIN,
                variant_id="help",
                title="agi-memory pin command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.agi-memory.unpin",
        title="agi-memory core memory unpin",
        description=(
            "Identifies `agi-memory unpin`, which removes a core-memory block. "
            "Later sessions stop receiving the invariant it held, and nothing "
            "in a later session reveals that it was ever there."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("agi-memory core memory unpin command",),
        safer_alternatives=(
            "Run agi-memory blocks first to record the content of the block before removing it.",
            "Confirm no project rule still depends on the invariant the block carried.",
        ),
        matcher=_AGI_MEMORY_UNPIN,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AGI_MEMORY_UNPIN,
                variant_id="help",
                title="agi-memory unpin command help",
                flag="--help",
            ),
        ),
    ),
)

AGI_MEMORY_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.agi-memory",
        name="agi-memory command protection",
        description=(
            "Reviews agi-memory commands that rewrite the canonical memory "
            "vault, permanently delete a memory across every synced machine, or "
            "change the invariants injected into later sessions. Reads such as "
            "recall, log, inspect, blocks and sync status stay unreviewed."
        ),
        action_classes=(
            "agi-memory vault rewrite command",
            "agi-memory permanent memory deletion command",
            "agi-memory core memory pin command",
            "agi-memory core memory unpin command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Run agi-memory sync status or agi-memory blocks first to see what the destructive command would change.",
            "Soft-delete instead of --hard: it marks the memory superseded and is reversible.",
        ),
        reference_urls=("https://github.com/kdbhalala/agi-memory",),
    ),
)

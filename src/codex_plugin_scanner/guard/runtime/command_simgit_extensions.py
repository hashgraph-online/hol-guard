"""Structured rules and metadata for the simgit command safety extension."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import (
    known_option_advance,
    long_flag_assignment_is_enabled,
    subcommand_parse_tails,
)
from .command_rules import AnyMatcher, CommandSafetyRule, _segment_matches_executable

# Flag surface verified against simgit 0.3.0 (`sg/src/commands/worktree.rs`) and
# the project's published stability contract in AGENTS.md, "What approval gates
# depend on". Exactly two flags destroy work Git cannot return:
#
# - `--discard-dirty` removes a worktree that still holds uncommitted and
#   untracked files. A worktree lives outside the source repository, so those
#   files are not recoverable from the repository afterwards.
# - `--delete-unmerged` deletes a branch past Git's merged check. It only
#   relaxes an accompanying `--delete-branch` (remove) or `--delete-branches`
#   (gc).
#
# Both flags exist on `remove` and on `gc`, and simgit's contract requires any
# future destructive operation to sit behind one of them. Everything else
# refuses first: `remove` and `gc` will not touch a dirty worktree, `gc` reaps
# only ephemeral worktrees idle past `--older-than` and skips locked ones,
# branch deletion stops at the merged check, `prune` drops only caches that
# rematerialize, `repair` remounts, and `unlock` refuses while the recorded
# owner PID is alive and has no override flag. Plain `add`, `remove`, `gc`,
# `doctor`, `list`, `unlock`, `prune` and `repair` therefore stay unreviewed.
#
# `simgit run [BRANCH] -- <command>` executes a caller-supplied command inside a
# worktree. The risk there is that argv, which Guard's existing command handling
# already judges, so `run` is not matched here.
#
# Conservative matching covers:
# - Both launchers: `simgit` is canonical and `sg` is an equivalent alias built
#   from the same source, so both carry the same authority.
# - The global `--json` flag, which is accepted before or after the subcommand.
# - Shell wrappers: `exec simgit ...`, `xargs simgit ...`, including the
#   portable `.exe`/`.cmd` spellings of the nested launcher, and including the
#   wrapper options that take a separate value before the nested launcher.
# - Value-taking options, so `-m --discard-dirty` (a commit message) and
#   `--prefix --discard-dirty` (a branch prefix) are read as values.
# - Fail-secure subcommand resolution, so an unknown option cannot hide a
#   destructive subcommand.
# - Unresolved shell expansions that can occupy a flag slot, because argv then
#   cannot prove either destructive flag absent, with quoting deciding whether
#   an expansion is one word or an unbounded list of them.

_SIMGIT_EXECUTABLES: tuple[str, ...] = ("simgit", "sg")
# Wrapper options that take a separate value hold the slot the nested launcher
# would otherwise occupy (`exec -a worker simgit ...`, `xargs -a FILE simgit
# ...`). Guard lowercases argv before matching, which folds `-I` onto `-i`,
# `-L` onto `-l`, `-E` onto `-e` and `-P` onto `-p` — pairs whose spellings
# disagree about taking a separate value — so only options that survive that
# fold with one arity are declared. Everything else is deliberately left
# unknown: bounded parsing then explores both readings of the option and the
# nested launcher is found in whichever reading places it, which is why an
# unenumerated wrapper option cannot hide a destructive simgit command.
_EXEC_LEADING_OPTIONS_WITH_VALUES = frozenset({"-a"})
_XARGS_LEADING_OPTIONS_WITH_VALUES = frozenset(
    {
        "-a",
        "-d",
        "-n",
        "-s",
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-chars",
        "--max-procs",
        "--process-slot-var",
    }
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES: Mapping[str, frozenset[str]] = {
    "exec": _EXEC_LEADING_OPTIONS_WITH_VALUES,
    "xargs": _XARGS_LEADING_OPTIONS_WITH_VALUES,
}
# A wrapper names its child in argv, so the portable `.exe`/`.cmd` spellings are
# enumerated here; the leading token is matched through `executable_names`.
_SIMGIT_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    *((executable,) for executable in _SIMGIT_EXECUTABLES),
    *(
        (wrapper, nested)
        for wrapper in _WRAPPER_LEADING_OPTIONS_WITH_VALUES
        for executable in _SIMGIT_EXECUTABLES
        for nested in sorted(executable_names(executable))
    ),
)
# `--json` is a global flag and may appear before or after the subcommand.
_SIMGIT_GLOBAL_FLAGS = frozenset({"--json"})
_REMOVE_OPTIONS_WITH_VALUES = frozenset({"-m", "--message"})
_GC_OPTIONS_WITH_VALUES = frozenset({"--older-than", "--prefix"})
# Every other boolean flag the subcommand accepts, so a companion flag is never
# read as an unknown option. `simgit gc --delete-unmerged` requires
# `--delete-branches`, so without this the `--dry-run` preview of exactly that
# command could not be recognised as its safe counterpart. `--dry-run` and
# `--help` are deliberately absent: the safe variants require them, and an
# interspersed flag is stripped before required flags are checked.
_REMOVE_COMPANION_FLAGS = frozenset({"--commit", "--delete-branch", "--discard-dirty", "--delete-unmerged"})
_GC_COMPANION_FLAGS = frozenset({"--include-persistent", "--delete-branches", "--discard-dirty", "--delete-unmerged"})
_COMMIT_ALTERNATIVE = (
    'Keep the work with `simgit remove --commit -m "<message>"`, which commits to the worktree branch first.'
)


def _leading_options_with_values(launcher: tuple[str, ...]) -> frozenset[str]:
    """Return the wrapper options that can consume the nested launcher's slot."""

    return _WRAPPER_LEADING_OPTIONS_WITH_VALUES.get(launcher[0], frozenset())


def _flagged_subcommand(
    subcommand: str,
    flag: str,
    options_with_values: frozenset[str],
    companion_flags: frozenset[str],
) -> AnyMatcher:
    """Match one simgit subcommand carrying one destructive flag."""

    known_flags = _SIMGIT_GLOBAL_FLAGS | (companion_flags - {flag})
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                subcommand,
                required_flags=frozenset({flag}),
                global_flags=known_flags,
                options_with_values=options_with_values,
                allow_leading_options=launcher[0] in _WRAPPER_LEADING_OPTIONS_WITH_VALUES,
                leading_options_with_values=_leading_options_with_values(launcher),
                fail_secure_unknown_options=True,
            )
            for launcher in _SIMGIT_LAUNCHERS
        )
    )


_SIMGIT_REMOVE_DISCARD_DIRTY = _flagged_subcommand(
    "remove", "--discard-dirty", _REMOVE_OPTIONS_WITH_VALUES, _REMOVE_COMPANION_FLAGS
)
_SIMGIT_GC_DISCARD_DIRTY = _flagged_subcommand("gc", "--discard-dirty", _GC_OPTIONS_WITH_VALUES, _GC_COMPANION_FLAGS)
_SIMGIT_DISCARD_DIRTY = AnyMatcher(
    matchers=(*_SIMGIT_REMOVE_DISCARD_DIRTY.matchers, *_SIMGIT_GC_DISCARD_DIRTY.matchers),
)

_SIMGIT_REMOVE_DELETE_UNMERGED = _flagged_subcommand(
    "remove", "--delete-unmerged", _REMOVE_OPTIONS_WITH_VALUES, _REMOVE_COMPANION_FLAGS
)
_SIMGIT_GC_DELETE_UNMERGED = _flagged_subcommand(
    "gc", "--delete-unmerged", _GC_OPTIONS_WITH_VALUES, _GC_COMPANION_FLAGS
)
_SIMGIT_DELETE_UNMERGED = AnyMatcher(
    matchers=(*_SIMGIT_REMOVE_DELETE_UNMERGED.matchers, *_SIMGIT_GC_DELETE_UNMERGED.matchers),
)

# A `$VAR`, `${VAR}`, `$(...)` or backtick token is decided by the shell after
# Guard sees argv, so it can arrive as `--discard-dirty` or `--delete-unmerged`.
# Two properties decide whether argv can still prove the flags absent.
#
# Quoting decides how many words the token becomes. A quoted expansion is one
# word and can only fill the slot it already occupies, so `simgit remove
# "$CLEANUP_TOKEN"` — simgit's documented allocator cleanup — stays quiet. An
# unquoted one is field-split by the shell into any number of words, so
# `simgit remove $CLEANUP_TOKEN` can arrive as `--discard-dirty /tmp/worktree`
# and is reviewed wherever it sits. Escaped and single-quoted markers expand to
# nothing at all and count as quoted. Quoting does not bound `"$@"`, `"${@}"`
# or `"${args[@]}"`, which expand to one word per element however they are
# quoted, so those keep the unquoted verdict; `"$*"` and `"${args[*]}"` join
# their elements into one word and keep the quoted one.
#
# Arity decides the rest. `remove` accepts one positional target and `gc` none,
# so even a single-word expansion past that arity, or one spelled as an option
# name (`--$FLAG`), cannot be a positional value and is reviewed.
#
# `--dry-run` and `--help` only make a run quiet when option parsing puts them
# in a flag slot of their own. `simgit gc --prefix --dry-run $FLAGS` spends the
# token as the `--prefix` value, so the run previews nothing and `$FLAGS` is
# still an unproven flag slot; reading the token before parsing would hand any
# argv a two-token cloak for a destructive expansion.
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})
_QUOTES: frozenset[str] = frozenset({'"', "'"})


def _quoted_expansions(segment_text: str) -> frozenset[str]:
    """Return lowercased tokens whose every expansion marker is quoted or escaped.

    Tokenization strips quotes long before a matcher sees argv, so the quoted
    and unquoted spellings of one expansion are indistinguishable there. This
    re-reads the segment to recover that context, and reports only what it can
    prove quoted: a token this does not name stays capable of field splitting.
    """

    quoted: set[str] = set()
    exposed: set[str] = set()
    token: list[str] = []
    carries_marker = False
    marker_exposed = False
    quote: str | None = None
    index = 0
    while index <= len(segment_text):
        character = segment_text[index] if index < len(segment_text) else " "
        if quote is None and character.isspace():
            if carries_marker:
                (exposed if marker_exposed else quoted).add("".join(token).lower())
            token = []
            carries_marker = False
            marker_exposed = False
            index += 1
            continue
        if quote != "'" and character == "\\":
            escaped = segment_text[index + 1 : index + 2]
            carries_marker = carries_marker or escaped in _EXPANSION_MARKERS
            token.append(escaped)
            index += 2
            continue
        if quote is None and character in _QUOTES:
            quote = character
            index += 1
            continue
        if character == quote:
            quote = None
            index += 1
            continue
        if character in _EXPANSION_MARKERS:
            carries_marker = True
            marker_exposed = (
                marker_exposed or quote is None or (quote == '"' and _expands_to_many_words(segment_text, index))
            )
        token.append(character)
        index += 1
    return frozenset(quoted - exposed)


def _expands_to_many_words(segment_text: str, index: int) -> bool:
    """Return whether an expansion yields one word per element despite quoting."""

    if segment_text[index] != "$":
        return False
    following = segment_text[index + 1 : index + 2]
    if following == "@":
        return True
    if following != "{":
        return False
    closing = segment_text.find("}", index + 2)
    body = segment_text[index + 2 :] if closing < 0 else segment_text[index + 2 : closing]
    return body.startswith("@") or "[@]" in body


@dataclass(frozen=True, slots=True)
class SimgitFlagSlotExpansionMatcher:
    """Match simgit commands whose unresolved expansion can supply a destructive flag."""

    subcommand: str
    positional_arity: int
    options_with_values: frozenset[str]
    known_flags: frozenset[str]
    quiet_flags: frozenset[str]
    launchers: tuple[tuple[str, ...], ...] = _SIMGIT_LAUNCHERS
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            if not any(self._is_unresolved(argument) for argument in lowered_arguments):
                continue
            quoted_expansions = _quoted_expansions(segment.text)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, executable_names(launcher[0])):
                    continue
                # An unknown wrapper option may or may not consume the token
                # after it, so the nested launcher is looked for in every
                # bounded reading rather than in one assumed option arity.
                tails = subcommand_parse_tails(
                    lowered_arguments,
                    (*launcher[1:], self.subcommand),
                    options_with_values=self.options_with_values | _leading_options_with_values(launcher),
                    known_flags=self.known_flags,
                )
                if tails is not None and not tails:
                    continue
                if tails is None or any(self._flag_slot_is_unresolved(tail, quoted_expansions) for tail in tails):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched a simgit argument slot that may expand to a destructive flag.",
                        )
                    )
                break
        return tuple(evidence)

    def _flag_slot_is_unresolved(self, arguments: tuple[str, ...], quoted_expansions: frozenset[str]) -> bool:
        """Return whether an expansion sits where a flag, not a value, can land."""

        positionals = 0
        saw_expansion = False
        saw_field_splitting = False
        saw_quiet_flag = False
        unresolved_option_name = False
        options_ended = False
        index = 0
        while index < len(arguments):
            argument = arguments[index]
            if not options_ended and argument == "--":
                options_ended = True
                index += 1
                continue
            if not options_ended and len(argument) > 1 and argument.startswith("-"):
                advance = known_option_advance(
                    argument,
                    options_with_values=self.options_with_values,
                    known_flags=self.known_flags,
                )
                if advance is None:
                    if self._is_unresolved(argument.partition("=")[0]):
                        unresolved_option_name = True
                    advance = 1
                elif self._occupies_quiet_flag_slot(argument):
                    saw_quiet_flag = True
                window = arguments[index : index + advance]
                saw_expansion = saw_expansion or any(self._is_unresolved(token) for token in window)
                saw_field_splitting = saw_field_splitting or any(
                    self._splits_into_words(token, quoted_expansions) for token in window
                )
                index += advance
                continue
            positionals += 1
            saw_expansion = saw_expansion or self._is_unresolved(argument)
            # Words after `--` are positional however the shell splits them.
            saw_field_splitting = saw_field_splitting or (
                not options_ended and self._splits_into_words(argument, quoted_expansions)
            )
            index += 1
        # The quiet verdict is the whole parse's, not one token's: a preview or
        # help run anywhere in argv acts on nothing, and an unresolved option
        # name earlier in the same argv does not change that.
        if saw_quiet_flag:
            return False
        if unresolved_option_name or saw_field_splitting:
            return True
        return saw_expansion and positionals > self.positional_arity

    def _occupies_quiet_flag_slot(self, argument: str) -> bool:
        """Return whether a parsed option is a quiet flag in its own flag slot."""

        name, _, _ = argument.partition("=")
        return name in self.quiet_flags and long_flag_assignment_is_enabled(argument)

    def _splits_into_words(self, argument: str, quoted_expansions: frozenset[str]) -> bool:
        """Return whether the shell can split one token into a flag and a value."""

        return self._is_unresolved(argument) and argument not in quoted_expansions

    def _is_unresolved(self, argument: str) -> bool:
        """Return whether a token carries shell syntax argv cannot resolve."""

        return any(marker in argument for marker in self.expansion_markers)


_SIMGIT_FLAG_SLOT_EXPANSIONS: tuple[SimgitFlagSlotExpansionMatcher, ...] = (
    SimgitFlagSlotExpansionMatcher(
        subcommand="remove",
        positional_arity=1,
        options_with_values=_REMOVE_OPTIONS_WITH_VALUES,
        known_flags=_SIMGIT_GLOBAL_FLAGS | _REMOVE_COMPANION_FLAGS | frozenset({"--help"}),
        quiet_flags=frozenset({"--help"}),
    ),
    SimgitFlagSlotExpansionMatcher(
        subcommand="gc",
        positional_arity=0,
        options_with_values=_GC_OPTIONS_WITH_VALUES,
        known_flags=_SIMGIT_GLOBAL_FLAGS | _GC_COMPANION_FLAGS | frozenset({"--dry-run", "--help"}),
        quiet_flags=frozenset({"--dry-run", "--help"}),
    ),
)

# The literal-flag matchers stay free of custom children so the safe variants
# keep cloning pure executable matchers; each rule adds the flag-slot overlay on
# top. Both rules carry it because an unresolved flag slot proves neither flag
# absent, and the two permissions are enabled independently.
_SIMGIT_DISCARD_DIRTY_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_SIMGIT_DISCARD_DIRTY.matchers, *_SIMGIT_FLAG_SLOT_EXPANSIONS),
)
_SIMGIT_DELETE_UNMERGED_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_SIMGIT_DELETE_UNMERGED.matchers, *_SIMGIT_FLAG_SLOT_EXPANSIONS),
)

SIMGIT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.simgit.discard-dirty",
        title="simgit uncommitted worktree discard",
        description=(
            "Identifies `--discard-dirty` on `simgit remove` and `simgit "
            "gc`, which delete a worktree still holding uncommitted and "
            "untracked files. A worktree lives outside the source "
            "repository, so those files are not recoverable there. Without "
            "the flag both commands refuse a dirty worktree. An invocation "
            "whose unresolved expansion can occupy a flag slot is reviewed "
            "too: argv cannot prove the flag absent."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("simgit uncommitted worktree discard command",),
        safer_alternatives=(
            "Drop the flag: plain `simgit remove` refuses a dirty worktree and names the path it kept.",
            _COMMIT_ALTERNATIVE,
            "Preview the selection with `simgit gc --dry-run` before letting GC discard anything.",
            "Expand shell variables and command substitutions so argv shows which flags simgit receives.",
        ),
        matcher=_SIMGIT_DISCARD_DIRTY_WITH_EXPANSIONS,
        default_mode="review",
        example_command="simgit remove /path/to/worktree --discard-dirty",
        safe_variants=(
            safe_flag_variant(
                _SIMGIT_GC_DISCARD_DIRTY,
                variant_id="dry-run",
                title="simgit gc discard preview",
                flag="--dry-run",
            ),
            safe_flag_variant(
                _SIMGIT_DISCARD_DIRTY,
                variant_id="help",
                title="simgit command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.simgit.delete-unmerged",
        title="simgit unmerged branch deletion",
        description=(
            "Identifies `--delete-unmerged` on `simgit remove` and `simgit "
            "gc`, which deletes a worktree's branch past Git's merged check "
            "and drops commits that were never integrated. Without it, branch "
            "deletion retains unmerged branches and reports them as retained. "
            "A `remove` or `gc` invocation whose unresolved shell expansion "
            "can occupy a flag slot is reviewed too, because argv cannot "
            "prove the flag absent."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("simgit unmerged branch deletion command",),
        safer_alternatives=(
            "Drop the flag: `--delete-branch` alone keeps an unmerged branch and reports it as retained.",
            "Merge or push the branch before deleting the worktree that produced it.",
            "Preview the selection with `simgit gc --dry-run` before deleting branches in bulk.",
            "Expand shell variables and command substitutions so argv shows which flags simgit receives.",
        ),
        matcher=_SIMGIT_DELETE_UNMERGED_WITH_EXPANSIONS,
        default_mode="review",
        example_command="simgit remove feature-branch --delete-branch --delete-unmerged",
        safe_variants=(
            safe_flag_variant(
                _SIMGIT_GC_DELETE_UNMERGED,
                variant_id="dry-run",
                title="simgit gc branch deletion preview",
                flag="--dry-run",
            ),
            safe_flag_variant(
                _SIMGIT_DELETE_UNMERGED,
                variant_id="help",
                title="simgit command help",
                flag="--help",
            ),
        ),
    ),
)

SIMGIT_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.simgit",
        name="simgit command protection",
        description=(
            "Reviews the two simgit flags that destroy work Git cannot return: "
            "discarding a dirty worktree and deleting an unmerged branch."
        ),
        action_classes=(
            "simgit uncommitted worktree discard command",
            "simgit unmerged branch deletion command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Run the command without --discard-dirty or --delete-unmerged and read what it refuses to touch.",
            "Commit the worktree's changes with `simgit remove --commit` instead of discarding them.",
        ),
        reference_urls=("https://github.com/abendrothj/simgit",),
        executables=("simgit", "sg"),
        ecosystem_ids=("simgit",),
    ),
)

"""Structured rules and metadata for the simgit command safety extension."""

from __future__ import annotations

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_rules import AnyMatcher, CommandSafetyRule

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
# - Shell wrappers: `exec simgit ...`, `xargs simgit ...`.
# - Value-taking options, so `-m --discard-dirty` (a commit message) and
#   `--prefix --discard-dirty` (a branch prefix) are read as values.
# - Fail-secure subcommand resolution, so an unknown option cannot hide a
#   destructive subcommand.
#
# Unresolved shell expansions are deliberately not treated as uncertainty here.
# simgit's documented allocator pattern passes the worktree path in a variable
# (`simgit remove "$CLEANUP_TOKEN"`), so reviewing every expansion would review
# every ordinary cleanup, while these two flags stay literal argv tokens in the
# harness integrations this extension protects.

_SIMGIT_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("simgit",),
    ("sg",),
    ("exec", "simgit"),
    ("exec", "sg"),
    ("xargs", "simgit"),
    ("xargs", "sg"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
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
                allow_leading_options=launcher[0] in ("exec", "xargs"),
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
                ),
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

SIMGIT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.simgit.discard-dirty",
        title="simgit uncommitted worktree discard",
        description=(
            "Identifies `simgit remove --discard-dirty` and `simgit gc "
            "--discard-dirty`, which delete a worktree that still holds "
            "uncommitted and untracked files. A worktree lives outside the "
            "source repository, so those files are not recoverable from the "
            "repository afterwards. Without the flag both commands refuse a "
            "dirty worktree and keep it."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("simgit uncommitted worktree discard command",),
        safer_alternatives=(
            "Drop the flag: plain `simgit remove` refuses a dirty worktree and names the path it kept.",
            _COMMIT_ALTERNATIVE,
            "Preview the selection with `simgit gc --dry-run` before letting GC discard anything.",
        ),
        matcher=_SIMGIT_DISCARD_DIRTY,
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
            "deletion retains unmerged branches and reports them as retained."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("simgit unmerged branch deletion command",),
        safer_alternatives=(
            "Drop the flag: `--delete-branch` alone keeps an unmerged branch and reports it as retained.",
            "Merge or push the branch before deleting the worktree that produced it.",
            "Preview the selection with `simgit gc --dry-run` before deleting branches in bulk.",
        ),
        matcher=_SIMGIT_DELETE_UNMERGED,
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

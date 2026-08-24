"""Catalog rules for everyday Git porcelain commands."""

from __future__ import annotations

from .command_rules import (
    AnyMatcher,
    CommandMatcher,
    CommandRuleMode,
    CommandRuleSeverity,
    CommandSafetyRule,
    ExecutableMatcher,
)

_GIT_GLOBAL_OPTIONS = frozenset(
    {
        "-c",
        "-C",
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--help",
        "--namespace",
        "--super-prefix",
        "--version",
        "--work-tree",
        "-h",
    }
)
_GIT_HELP_FLAGS = frozenset({"--help", "--version", "-h"})
_UNSAFE_READ_FLAGS = frozenset({"--output", "--ext-diff", "--textconv"})
_NONE: frozenset[str] = frozenset()
_READ = "Read-only Git inspection does not change repository state."
_WORK = "Inspect the current branch and working tree before changing them."
_HISTORY = "Inspect the current history and create a backup branch before rewriting it."
_REMOTE = "Inspect the remote and local refs before updating them."
_WORK_ACT = "git workspace command"
_READ_ACT = "git read command"


def _git(
    *subs: str,
    required: frozenset[str] = _NONE,
    forbidden: frozenset[str] = _NONE,
    options_with_values: frozenset[str] = _NONE,
) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            ExecutableMatcher(
                executables=frozenset({"git"}),
                subcommands=subs,
                required_flags=required,
                forbidden_flags=forbidden | _GIT_HELP_FLAGS,
                allow_leading_options=True,
                leading_options_with_values=_GIT_GLOBAL_OPTIONS,
                options_with_values=options_with_values,
            ),
        )
    )


def _risk(family: str, mode: CommandRuleMode) -> tuple[str, ...]:
    if family == "git-remote":
        return ("destructive_shell", "network_egress") if mode != "disabled" else ("network_egress",)
    if family == "git-read":
        return ("local_secret_read",)
    return ("destructive_shell",)


def _rule(
    suffix: str,
    title: str,
    matcher: CommandMatcher | None,
    *,
    action: str,
    family: str,
    safer: str,
    mode: CommandRuleMode = "review",
    severity: CommandRuleSeverity = "high",
    example: str | None = None,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=f"command.git.{suffix}",
        title=title,
        description=f"Identifies {title.lower()} operations.",
        severity=severity,
        risk_classes=_risk(family, mode),
        action_classes=(action,),
        safer_alternatives=(safer,),
        matcher=matcher,
        default_mode=mode,
        family=family,
        example_command=example,
    )


def _workspace(suffix: str, title: str, matcher: AnyMatcher, *, family: str = "git-workspace") -> CommandSafetyRule:
    safer = _HISTORY if family == "git-history" else _WORK
    return _rule(
        suffix,
        title,
        matcher,
        action=_WORK_ACT,
        family=family,
        safer=safer,
        example=f"git {suffix}",
    )


def _remote(suffix: str, title: str) -> CommandSafetyRule:
    return _rule(
        suffix,
        title,
        None,
        action=_WORK_ACT,
        family="git-remote",
        safer=_REMOTE,
        mode="disabled",
        example=f"git {suffix}",
    )


def _read(suffix: str, title: str) -> CommandSafetyRule:
    return _rule(
        suffix,
        title,
        None,
        action=_READ_ACT,
        family="git-read",
        safer=_READ,
        mode="disabled",
        severity="low",
        example=f"git {suffix}",
    )


def _unsafe_read_matcher() -> AnyMatcher:
    output_values = frozenset({"--output"})
    cached = frozenset({"--cached", "--staged"})
    return AnyMatcher(
        matchers=tuple(
            matcher
            for subcommand in ("diff", "show", "log")
            for matcher in (
                *_git(
                    subcommand,
                    required=output_values,
                    forbidden=cached if subcommand == "diff" else _NONE,
                    options_with_values=output_values,
                ).matchers,
                *(
                    inner
                    for flag in ("--ext-diff", "--textconv")
                    for inner in _git(subcommand, required=frozenset({flag})).matchers
                ),
            )
        )
    )


GIT_PORCELAIN_COMMAND_RULES = (
    _workspace("switch", "Git switch", _git("switch")),
    _workspace("checkout", "Git checkout", _git("checkout")),
    _workspace("restore", "Git restore", _git("restore")),
    _workspace("stash", "Git stash", _git("stash")),
    _workspace("add", "Git add", _git("add")),
    _workspace("commit", "Git commit", _git("commit")),
    _workspace("mv", "Git move", _git("mv")),
    _workspace("rm", "Git remove", _git("rm")),
    _workspace("branch", "Git branch", _git("branch", forbidden=frozenset({"-D"}))),
    _workspace("worktree", "Git worktree", _git("worktree")),
    _workspace("tag", "Git tag", _git("tag")),
    _workspace("clean", "Git clean", _git("clean", forbidden=frozenset({"-f", "--force"}))),
    _workspace("rebase", "Git rebase", _git("rebase"), family="git-history"),
    _workspace("merge", "Git merge", _git("merge"), family="git-history"),
    _workspace("cherry-pick", "Git cherry-pick", _git("cherry-pick"), family="git-history"),
    _workspace("revert", "Git revert", _git("revert"), family="git-history"),
    _workspace("reset", "Git reset", _git("reset", forbidden=frozenset({"--hard"})), family="git-history"),
    _remote("pull", "Git pull"),
    _remote("push", "Git push"),
    _remote("clone", "Git clone"),
    _remote("fetch", "Git fetch"),
    _remote("remote", "Git remote"),
    _rule(
        "unsafe-read",
        "Git helper or output write",
        _unsafe_read_matcher(),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git diff --output",
    ),
    _read("status", "Git status"),
    _read("log", "Git log"),
    _read("diff", "Git diff"),
    _read("show", "Git show"),
    _read("blame", "Git blame"),
    _read("grep", "Git grep"),
    _read("describe", "Git describe"),
    _read("ls-files", "Git ls-files"),
    _read("reflog", "Git reflog"),
)

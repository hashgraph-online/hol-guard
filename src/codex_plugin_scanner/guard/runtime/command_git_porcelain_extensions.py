"""Catalog rules for everyday Git porcelain commands."""

from __future__ import annotations

from .command_rules import (
    AnyMatcher,
    CommandRuleMode,
    CommandRuleSeverity,
    CommandSafetyRule,
    ExecutableMatcher,
)

_GIT_GLOBAL_OPTIONS = frozenset(
    {"-c", "-C", "--config-env", "--exec-path", "--git-dir", "--namespace", "--super-prefix", "--work-tree"}
)
_NONE: frozenset[str] = frozenset()
_READ = "Read-only Git inspection does not change repository state."
_WORK = "Inspect the current branch and working tree before changing them."
_HISTORY = "Inspect the current history and create a backup branch before rewriting it."
_REMOTE = "Inspect the remote and local refs before updating them."
_WORK_ACT = "git workspace command"
_READ_ACT = "git read command"


def _git(*subs: str, required: frozenset[str] = _NONE, forbidden: frozenset[str] = _NONE) -> AnyMatcher:
    return AnyMatcher(
        matchers=(
            ExecutableMatcher(
                executables=frozenset({"git"}),
                subcommands=subs,
                required_flags=required,
                forbidden_flags=forbidden,
                allow_leading_options=True,
                leading_options_with_values=_GIT_GLOBAL_OPTIONS,
            ),
        )
    )


def _rule(
    suffix: str,
    title: str,
    matcher: AnyMatcher,
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
        risk_classes=("local_secret_read",) if mode == "disabled" else ("destructive_shell",),
        action_classes=(action,),
        safer_alternatives=(safer,),
        matcher=matcher,
        default_mode=mode,
        family=family,
        example_command=example,
    )


def _read(suffix: str, title: str, matcher: AnyMatcher) -> CommandSafetyRule:
    return _rule(
        suffix,
        title,
        matcher,
        action=_READ_ACT,
        family="git-read",
        safer=_READ,
        mode="disabled",
        severity="low",
        example=f"git {suffix.replace('-', '-')}",
    )


GIT_PORCELAIN_COMMAND_RULES = (
    _rule(
        "switch",
        "Git switch",
        _git("switch"),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git switch",
    ),
    _rule(
        "checkout",
        "Git checkout",
        _git("checkout"),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git checkout",
    ),
    _rule(
        "restore",
        "Git restore",
        _git("restore"),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git restore",
    ),
    _rule(
        "stash",
        "Git stash",
        _git("stash"),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git stash",
    ),
    _rule("add", "Git add", _git("add"), action=_WORK_ACT, family="git-workspace", safer=_WORK, example="git add"),
    _rule(
        "commit",
        "Git commit",
        _git("commit"),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git commit",
    ),
    _rule("mv", "Git move", _git("mv"), action=_WORK_ACT, family="git-workspace", safer=_WORK, example="git mv"),
    _rule("rm", "Git remove", _git("rm"), action=_WORK_ACT, family="git-workspace", safer=_WORK, example="git rm"),
    _rule(
        "branch",
        "Git branch",
        _git("branch", forbidden=frozenset({"-D"})),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git branch",
    ),
    _rule(
        "worktree",
        "Git worktree",
        _git("worktree"),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git worktree",
    ),
    _rule("tag", "Git tag", _git("tag"), action=_WORK_ACT, family="git-workspace", safer=_WORK, example="git tag"),
    _rule(
        "clean",
        "Git clean",
        _git("clean", forbidden=frozenset({"-f", "--force"})),
        action=_WORK_ACT,
        family="git-workspace",
        safer=_WORK,
        example="git clean",
    ),
    _rule(
        "rebase",
        "Git rebase",
        _git("rebase"),
        action=_WORK_ACT,
        family="git-history",
        safer=_HISTORY,
        example="git rebase",
    ),
    _rule(
        "merge",
        "Git merge",
        _git("merge"),
        action=_WORK_ACT,
        family="git-history",
        safer=_HISTORY,
        example="git merge",
    ),
    _rule(
        "cherry-pick",
        "Git cherry-pick",
        _git("cherry-pick"),
        action=_WORK_ACT,
        family="git-history",
        safer=_HISTORY,
        example="git cherry-pick",
    ),
    _rule(
        "revert",
        "Git revert",
        _git("revert"),
        action=_WORK_ACT,
        family="git-history",
        safer=_HISTORY,
        example="git revert",
    ),
    _rule(
        "reset",
        "Git reset",
        _git("reset", forbidden=frozenset({"--hard"})),
        action=_WORK_ACT,
        family="git-history",
        safer=_HISTORY,
        example="git reset",
    ),
    _rule("pull", "Git pull", _git("pull"), action=_WORK_ACT, family="git-remote", safer=_REMOTE, example="git pull"),
    _rule(
        "push",
        "Git push",
        _git("push", forbidden=frozenset({"--force", "-f", "--delete"})),
        action=_WORK_ACT,
        family="git-remote",
        safer=_REMOTE,
        example="git push",
    ),
    _rule(
        "clone",
        "Git clone",
        _git("clone"),
        action=_WORK_ACT,
        family="git-remote",
        safer=_REMOTE,
        example="git clone",
    ),
    _rule(
        "fetch",
        "Git fetch",
        _git("fetch"),
        action=_WORK_ACT,
        family="git-remote",
        safer=_REMOTE,
        example="git fetch",
    ),
    _rule(
        "remote",
        "Git remote",
        _git("remote"),
        action=_WORK_ACT,
        family="git-remote",
        safer=_REMOTE,
        example="git remote",
    ),
    _read("status", "Git status", _git("status")),
    _read("log", "Git log", _git("log")),
    _read("diff", "Git diff", _git("diff")),
    _read("show", "Git show", _git("show")),
    _read("blame", "Git blame", _git("blame")),
    _read("grep", "Git grep", _git("grep")),
    _read("describe", "Git describe", _git("describe")),
    _read("reflog", "Git reflog", _git("reflog")),
    _read("ls-files", "Git ls-files", _git("ls-files")),
)

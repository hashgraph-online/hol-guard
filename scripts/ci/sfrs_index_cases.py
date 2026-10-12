"""Record staged-index Git inspection cases for the filesystem fixture."""

from __future__ import annotations

import os
import shlex
from collections.abc import Callable
from pathlib import Path

from codex_plugin_scanner.guard.runtime import git_index_inspection as index

TEXTS = [
    "git diff --cached",
    "git diff --staged --stat",
    "git diff --cached --name-only",
    "git diff --cached --check HEAD",
    "git diff --cached -- src/a.txt",
    "git diff --cached -- src/a.txt src/b.txt",
    "git diff --cached -- bad/a.txt",
    "git diff --cached -- -x",
    "git diff --cached -- :!docs",
    "git diff -- src/a.txt",
    "git diff --cached --ext-diff",
    "git diff --cached --output=x",
    "git -C {P} diff --cached --stat",
    "git -C {P} diff --cached -- src/a.txt",
    "git -C unsafe-seg diff --cached --stat",
    "git -C -x diff --cached --stat",
    "git -C {P} -C src diff --cached",
    "git -c core.pager=x diff --cached",
    "git -ccore.pager=x diff --cached",
    "git --exec-path=x diff --cached",
    "git --config-env=x=Y diff --cached",
    "git --git-dir=.git diff --cached",
    "git --git-dir= diff --cached",
    "git --no-pager diff --cached",
    "git --no-pager --no-optional-locks diff --cached --stat",
    "git --work-tree=. diff --cached",
    "git --paginate diff --cached",
    "git diff --cached | rg foo",
    "git diff --cached | rg -in foo",
    "git diff --cached | rg --no-config foo",
    "git diff --cached | rg foo bar",
    "git diff --cached | rg -e foo",
    "git diff --cached | rg '$x'",
    "git diff --cached | rg ''",
    "git diff --cached | grep foo",
    "git diff --cached | head -5",
    "RIPGREP_CONFIG_PATH=x git diff --cached | rg foo",
    "git diff --cached | RIPGREP_CONFIG_PATH=x rg foo",
    "git diff --cached | RIPGREP_CONFIG_PATH=x rg --no-config foo",
    "rg foo",
    "if git diff --cached --name-only | rg foo; then echo found; fi",
    "if git diff --cached --name-only | rg foo; then echo found; else echo none; fi",
    "if git diff --cached --name-only; then echo $HOME; fi",
    "if git diff --cached --name-only; then echo $?; fi",
    "if git diff --cached --name-only; then echo `id`; fi",
    "git diff --cached && echo ok",
    "git diff --cached; echo ok",
    "git diff --cached || echo no",
    "git diff --cached > out.txt",
    "git diff --cached 2>/dev/null",
    "git diff --cached &",
    "git diff --cached && git diff --cached --stat",
    "echo hi",
    "echo hi && git diff --cached",
    "/usr/bin/git diff --cached",
    "git status",
    "git log",
    "! git diff --cached --quiet",
    "fi",
    "if fi",
    "git diff --cached $(id)",
    "git diff --cached `id`",
    "ls && git diff --cached",
    "cd {P} && git diff --cached --stat",
    "git diff --cached " + " ".join(f"-- f{i}" for i in range(1)),
]
PURE_TEXTS = [t for t in TEXTS if "{P}" not in t and "$(" not in t and "`" not in t]
RG_ARGS = [
    ["foo"],
    ["-i", "foo"],
    ["--no-config", "foo"],
    ["--no-config"],
    ["foo", "bar"],
    ["-e", "foo"],
    ["RIPGREP_CONFIG_PATH=x", "foo"],
    ["foo$"],
    ["foo\x00"],
    [""],
    ["--line-number", "-ni", "pat"],
    [],
]
OPERANDS = [
    ["--cached"],
    ["--staged", "--stat"],
    ["--cached", "--bogus"],
    ["HEAD"],
    ["--cached", "--"],
    ["--cached", "--", "a"],
    ["--cached", "--", "bad"],
    ["--cached", "--", "-x"],
    ["--cached", "--", "a", "b"],
    ["--cached", "--", *[f"f{i}" for i in range(16)]],
    ["--cached", "--", *[f"f{i}" for i in range(17)]],
    ["--cached", "--bogus", "--", "a"],
    ["--stat", "--", "a"],
    ["--cached", *["--stat"] * 20],
]


def _stand_in_pathspecs(values):
    return bool(values) and all(v and not v.startswith("-") and "bad" not in v for v in values)


def _stand_in_segment(segment, *, home_dir=None):
    return not any("unsafe-seg" in token for token in segment.tokens)


def _stand_in_show(segment, *, repository_path):
    return repository_path is None or "unsafe-repo" not in repository_path


def _stand_in_standalone(context, *, home_dir=None):
    return any("standalone-ok" in token for segment in context.segments for token in segment.tokens)


def _wire(value):
    return value if isinstance(value, (str, bool, int, type(None))) else list(value)


def index_cases(root: Path, add: Callable[[str, list[object], object], None]) -> None:
    """Needs HOL_GUARD_NATIVE=force, HOL_GUARD_NATIVE_BINARY and HOL_GUARD_HOME set."""

    home = root / "home"
    proj = home / "proj"
    saved = (
        index._cached_diff_pathspecs_allowed,
        index.is_low_risk_git_inspection_segment,
        index._git_show_has_execution_free_config,
        index.is_low_risk_standalone_git_routine,
    )
    index._cached_diff_pathspecs_allowed = _stand_in_pathspecs
    index.is_low_risk_git_inspection_segment = _stand_in_segment
    index._git_show_has_execution_free_config = _stand_in_show
    index.is_low_risk_standalone_git_routine = _stand_in_standalone
    original_env = os.environ.pop("RIPGREP_CONFIG_PATH", None)
    try:
        for text in PURE_TEXTS:
            for segment_text in (text, *(part for part in text.replace("|", ";").split(";"))):
                try:
                    tokens = tuple(shlex.split(segment_text))
                except ValueError:
                    continue
                kind = index.cached_diff_kind(tokens)
                operands = index.git_diff_operands(tokens)
                add("git_index_cached_diff_kind", [list(tokens)], kind)
                add("git_index_diff_operands", [list(tokens)], None if operands is None else list(operands))
                add("git_index_executable_tokens", [list(tokens)], _wire(index.executable_tokens(tokens)))
                add("git_index_unproven_selector", [list(tokens)], index._has_unproven_repository_selector(tokens))
                add("git_index_proof_tokens", [list(tokens)], list(index._proof_cached_diff_tokens(tokens)))
        chains = [[list(shlex.split(part)) for part in text.split("&&")] for text in PURE_TEXTS]
        for chain in chains:
            as_tuples = tuple(tuple(tokens) for tokens in chain)
            add("git_index_chain_owned", [chain], index.command_has_owned_git_cached_diff(as_tuples))
            add("git_index_chain_routed", [chain], index.command_has_execution_routed_git_cached_diff(as_tuples))
        for operands in OPERANDS:
            add("git_index_operands_safe", [operands], index._cached_diff_operands_are_safe(tuple(operands)))
        for config_set in (False, True):
            if config_set:
                os.environ["RIPGREP_CONFIG_PATH"] = "x"
            for args in RG_ARGS:
                add("git_index_rg_args", [args, config_set], index._index_scan_rg_args_are_safe(tuple(args)))
            os.environ.pop("RIPGREP_CONFIG_PATH", None)
        for template in TEXTS:
            text = template.replace("{P}", str(proj))
            for cwd in (None, proj, proj / "src"):
                args = [text, None if cwd is None else str(cwd), str(home)]
                add(
                    "git_index_is_low_risk",
                    args,
                    index.is_low_risk_git_index_inspection(text, cwd=cwd, home_dir=home),
                )
                add(
                    "git_index_action_class",
                    args,
                    index.owned_git_index_inspection_action_class(text, cwd=cwd, home_dir=home),
                )
    finally:
        (
            index._cached_diff_pathspecs_allowed,
            index.is_low_risk_git_inspection_segment,
            index._git_show_has_execution_free_config,
            index.is_low_risk_standalone_git_routine,
        ) = saved
        if original_env is not None:
            os.environ["RIPGREP_CONFIG_PATH"] = original_env

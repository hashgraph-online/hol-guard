"""Record whole-command developer execution context cases (source edits)."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from sfrs_graph_cases import _stand_in
from sfrs_index_cases import _stand_in_pathspecs, _stand_in_segment, _stand_in_show, _stand_in_standalone

from codex_plugin_scanner.guard.runtime import git_index_inspection as index
from codex_plugin_scanner.guard.runtime import github_shell_capabilities as gh_shell
from codex_plugin_scanner.guard.runtime.secret_file_request_services import developer_inspection, source_edit_context

EDIT = "sed -i '' 's/alpha/ALPHA/' src/a.txt"
TEXTS = [
    f"cd {{P}} && {EDIT} && grep ALPHA src/a.txt",
    f"cd {{P}} && {EDIT} && grep -n ALPHA src/a.txt",
    f"cd {{P}} && {EDIT} && echo verify && grep ALPHA src/a.txt",
    f"cd {{P}} && {EDIT} && echo $HOME && grep ALPHA src/a.txt",
    f"cd {{P}} && {EDIT}\ngrep ALPHA src/a.txt",
    f"cd {{P}} && {EDIT} && echo ok\ngrep ALPHA src/a.txt",
    f"cd {{P}} && {EDIT} \\\n  && grep ALPHA src/a.txt",
    f"cd {{P}} && {EDIT} && grep ALPHA src/b.txt",
    f"cd {{P}} && {EDIT} && grep ALPHA ./src/a.txt",
    f"cd {{P}} && {EDIT} && grep ALPHA src/../src/a.txt",
    f"cd {{P}} && {EDIT} && grep ALPHA link.txt",
    f"cd {{P}} && {EDIT} && grep -r ALPHA src",
    f"cd {{P}} && {EDIT} && grep ALPHA src/a.txt src/b.txt",
    f"cd {{P}} && {EDIT} && cat src/a.txt",
    f"cd {{P}} && {EDIT}",
    f"cd {{P}} && {EDIT} && grep ALPHA src/a.txt && ls",
    f"cd {{P}} && {EDIT} && grep ALPHA src/a.txt > out.txt",
    f"cd {{P}} && {EDIT} && grep $(id) src/a.txt",
    f"cd {{P}} && {EDIT} && grep `id` src/a.txt",
    f"cd {{P}} && sed -i '' -e 's/alpha/ALPHA/' -e 's/beta/BETA/' src/a.txt && grep ALPHA src/a.txt",
    "cd {P} && sed -i '' 's/al.*/ALPHA/' src/a.txt && grep ALPHA src/a.txt",
    "cd {P} && sed -i .bak 's/alpha/ALPHA/' src/a.txt && grep ALPHA src/a.txt",
    "cd {P} && sed -i 's/alpha/ALPHA/' src/a.txt && grep ALPHA src/a.txt",
    "cd {P} && sed -i '' 's/alpha/ALPHA/' ../bare/f.txt && grep ALPHA ../bare/f.txt",
    "cd {P} && sed -i '' 's/alpha/ALPHA/' link.txt && grep ALPHA link.txt",
    "cd {P} && sed -i '' 's/alpha/ALPHA/' dirlink/a.txt && grep ALPHA dirlink/a.txt",
    "cd {P} && sed -i '' 's/alpha/ALPHA/' src/missing.txt && grep ALPHA src/missing.txt",
    "cd {P} && sed -i '' 's/alpha/ALPHA/' src && grep ALPHA src",
    "cd {P}/src && sed -i '' 's/alpha/ALPHA/' a.txt && grep ALPHA a.txt",
    "cd {ROOT}/home/pyproj && sed -i '' 's/a/b/' x.txt && grep b x.txt",
    "cd {ROOT}/home/.hidden && sed -i '' 's/x/y/' x.txt && grep y x.txt",
    "cd {ROOT}/home/bare && sed -i '' 's/f/g/' f.txt && grep g f.txt",
    "cd {ROOT}/home && sed -i '' 's/a/b/' proj/src/a.txt && grep b proj/src/a.txt",
    "cd {ROOT}/elsewhere && sed -i '' 's/o/p/' out.txt && grep p out.txt",
    f"sleep 5 && cd {{P}} && {EDIT} && grep ALPHA src/a.txt",
    f"sleep 3600 && cd {{P}} && {EDIT} && grep ALPHA src/a.txt",
    f"sleep 3601 && cd {{P}} && {EDIT} && grep ALPHA src/a.txt",
    f"sleep 0 && cd {{P}} && {EDIT} && grep ALPHA src/a.txt",
    "sleep 5 && cd {P} && ls src",
    "sleep 5 && cd {P} && git diff --cached --stat",
    "sleep 5 && ls",
    "  sleep   12   &&   cd {P} && cat src/a.txt",
    "cd {P} && sed -i '' 's/alpha/ALPHA/' missing/../src/a.txt && grep ALPHA src/a.txt",
    "cd {ROOT}/home/missing/../proj && sed -i '' 's/alpha/ALPHA/' src/a.txt && grep ALPHA src/a.txt",
    "cd {P} && ls src",
    "cd {P} && git diff --cached --stat",
    "cd {P} && git diff --cached | rg foo",
    "cd {P} && if git diff --cached --name-only | rg foo; then echo found; fi",
    "if git diff --cached --name-only | rg foo; then echo found; fi",
    "git diff --cached --stat",
    "git status",
    "ls",
    "cd {P} && gh pr view 1",
]


def source_edit_cases(root: Path, add: Callable[[str, list[object], object], None]) -> None:
    home = root / "home"
    proj = home / "proj"
    saved = (
        gh_shell.classify_github_cli,
        developer_inspection.is_low_risk_compound_git_inspection,
        developer_inspection.is_low_risk_git_inspection_segment,
        index._cached_diff_pathspecs_allowed,
        index.is_low_risk_git_inspection_segment,
        index._git_show_has_execution_free_config,
        index.is_low_risk_standalone_git_routine,
    )
    gh_shell.classify_github_cli = _stand_in
    developer_inspection.is_low_risk_compound_git_inspection = lambda *_a, **_k: False
    developer_inspection.is_low_risk_git_inspection_segment = _stand_in_segment
    index._cached_diff_pathspecs_allowed = _stand_in_pathspecs
    index.is_low_risk_git_inspection_segment = _stand_in_segment
    index._git_show_has_execution_free_config = _stand_in_show
    index.is_low_risk_standalone_git_routine = _stand_in_standalone
    original_env = os.environ.pop("RIPGREP_CONFIG_PATH", None)
    try:
        for template in TEXTS:
            text = template.replace("{P}", str(proj)).replace("{ROOT}", str(root))
            for cwd in (None, proj):
                context = source_edit_context.low_risk_compound_developer_execution_context(
                    text, cwd=cwd, home_dir=home
                )
                summary = (
                    None
                    if context is None
                    else {
                        "complete": context.complete,
                        "segments": len(context.segments),
                        "command_text": context.command_text,
                        "workspace_root": str(context.workspace_root) if context.workspace_root else None,
                    }
                )
                add(
                    "low_risk_developer_context",
                    [text, None if cwd is None else str(cwd), str(home)],
                    summary,
                )
    finally:
        (
            gh_shell.classify_github_cli,
            developer_inspection.is_low_risk_compound_git_inspection,
            developer_inspection.is_low_risk_git_inspection_segment,
            index._cached_diff_pathspecs_allowed,
            index.is_low_risk_git_inspection_segment,
            index._git_show_has_execution_free_config,
            index.is_low_risk_standalone_git_routine,
        ) = saved
        if original_env is not None:
            os.environ["RIPGREP_CONFIG_PATH"] = original_env

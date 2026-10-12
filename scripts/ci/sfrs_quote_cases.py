"""Record working-directory and runner-chain parsing cases."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_quote_parsing as sqp

N = "{N}"
RUNNER_TEXTS = [
    f"cd {N} && bunx eslint",
    f"cd {N} && bunx eslint src",
    f"cd {N} && npx --no-install eslint .",
    f"cd {N} && bunx --bun --no jest",
    f"cd {N} && bunx --no-install --no jest src",
    f"cd {N} && bunx tsc",
    f"cd {N} && bunx vitest run",
    f"cd {N} && bunx eslint ../x",
    f"cd {N} && bunx eslint ../../elsewhere/out.txt",
    f"cd {N} && bunx eslint $X",
    f"cd {N} && bunx eslint --config=~/x",
    f"cd {N} && bunx eslint --config=../y",
    f"cd {N} && bunx eslint ~/x",
    f"cd {N} && bunx eslint $(id)",
    f"cd {N} && bunx eslint `id`",
    f"cd {N} && bunx eslint /abs/path",
    f"cd {N} && bunx eslint -f=json",
    f"cd {N} && bunx eslint 'a b'",
    f"cd {N} && npx jest | head -50",
    f"cd {N} && npx jest | tail -1000",
    f"cd {N} && npx jest | tail -1001",
    f"cd {N} && npx jest | head -0",
    f"cd {N} && npx jest | head -5 -6",
    f"cd {N} && npx jest | head 5",
    f"cd {N} && npx jest | head -x",
    f"cd {N} && npx jest | head -",
    f"cd {N} && npx jest | cat",
    f"cd {N} && npx jest && echo done",
    f"cd {N} && bunx prettier",
    f"cd {N} && bunx",
    f"cd {N} && bunx --bun",
    f"cd {N} && ./node_modules/.bin/eslint",
    f"cd {N} && bun run check",
    f"cd {N} && bun run bad",
    f"cd {N} && bun run check src",
    f"cd {N} && bun test",
    f"cd {N} && bun x eslint",
    f"cd {N} && bun run check | head -20",
    f"cd {N} && bun run check | tail -5 | head -1",
    f"cd {N} && bun run check | cat",
    f"cd {N} && bun run check | head -n 5",
    f"cd {N} && echo hi && bun run check",
    f"cd {N} && echo $HOME && bun run check",
    f"cd {N}; bun run check",
    f"cd {N}\nbun run check",
    f"cd {N} && bun run check; echo done | head -1",
    f"cd {N} && bun run check && bun run check",
    f"cd {N} && bun run check > out.txt",
    f"cd {N} && bun run check 2>&1",
    f"cd {N} && echo hi",
    f"cd {N} && ls",
    f"cd {N}",
    f"cd {N} && bun run check || true",
    "cd ~/node && bun run check",
    "cd ~ && bun run check",
    "bun run check",
    "cd /nonexistent && bun run check",
]
EDIT_TEXTS = [
    "sed -i '' 's/alpha/ALPHA/' src/a.txt",
    "sed -i '' 's/alpha/ALPHA/' src/b.txt && echo done",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt && echo $HOME",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt && echo ok && echo more",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt; echo done",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt\necho done",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt \\\n && echo done",
    "sed -i '' -e 's/a/b/' -e 's/c/d/' src/a.txt",
    "sed -i '' 's/al.*/ALPHA/' src/a.txt",
    "sed -i '' 's/alpha/ALPHA/' ../bare/f.txt",
    "sed -i '' 's/alpha/ALPHA/' link.txt",
    "sed -i '' 's/alpha/ALPHA/' src/missing.txt",
    "sed -i '' 's/alpha/ALPHA/' src",
    "cd src && sed -i '' 's/alpha/ALPHA/' a.txt",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt $(id)",
    "sed -i '' 's/alpha/ALPHA/' `id`",
    "echo hi",
    "ls",
    "sed -i '' 's/alpha/ALPHA/' src/a.txt > out.txt",
    "sed -n 1p src/a.txt",
    "sed -i '' 's/alpha/ALPHA/' missing/../src/a.txt",
    "sed -i '' 's/alpha/ALPHA/' src/../src/a.txt",
    "sed -i '' 's/alpha/ALPHA/' src/missing/../a.txt",
    "sed -i '' 's/alpha/ALPHA/' link.txt/../src/a.txt",
]
TOKEN_TEXTS = [
    'env -S "echo $(id)" gh pr view',
    "env -S 'a b' x",
    'env -S"foo $(x)" y',
    "env --split-string=$(id) y",
    "env -i FOO=1 gh pr list",
    "env -S '$(id) x' -S 'a b'",
    "env FOO=bar",
    "gh pr view -R o/r 1",
    "gh pr view --repo=o/r -- 1",
    "gh pr view -Ro/r 1",
    "gh pr view --repo o/r --web 1",
    "gh pr view --json x 1",
    "gh pr view -- -x",
    "sudo -u root -E ls",
    "sudo -ni ls",
    "timeout -s KILL 5 ls",
    "nice -n 5 ls",
    "env -u X -C d ls",
    "env -- ls",
    "command -p ls",
    "time -p ls",
    "x",
]
WRAPPERS = ["sudo", "env", "nice", "timeout", "time", "command", "nohup", "xargs"]


def _trusted(command, *, cwd, home_dir):
    return command in {"bun", "head", "tail"} and "untrusted" not in str(cwd)


def _evidence(manager, script_key, *, workspace):
    return SimpleNamespace(status="incomplete" if len(script_key) > 1 and script_key[1] == "bad" else "complete")


def _summary(context):
    if context is None:
        return None
    return {
        "complete": context.complete,
        "segments": len(context.segments),
        "command_text": context.command_text,
        "workspace_root": str(context.workspace_root) if context.workspace_root else None,
    }


def quote_cases(root: Path, add: Callable[[str, list[object], object], None]) -> None:
    home = root / "home"
    proj = home / "proj"
    node = home / "node"
    saved = (sqp._trusted_path_command, sqp.build_local_package_script_evidence)
    sqp._trusted_path_command = _trusted
    sqp.build_local_package_script_evidence = _evidence
    try:
        for template in RUNNER_TEXTS:
            text = template.replace(N, str(node))
            add("literal_cd_context", [text, str(home)], _summary(sqp.literal_cd_execution_context(text, home_dir=home)))
        for text in EDIT_TEXTS:
            for cwd in (None, proj, proj / "src", node, home):
                context = sqp._bounded_current_workspace_source_edit_execution_context(text, cwd=cwd, home_dir=home)
                add("current_workspace_edit", [text, None if cwd is None else str(cwd), str(home)], _summary(context))
        for text in TOKEN_TEXTS:
            segments = sqp._shell_token_segments(sqp._shell_tokens_preserving_quote_context(text))
            for position, segment in enumerate(segments):
                add(
                    "quote_env_payloads",
                    [text, position],
                    list(sqp._gh_pr_env_split_string_payloads_with_substitution(segment)),
                )
                for start in range(len(segment) + 1):
                    add("quote_skip_gh_pr", [text, position, start], sqp._skip_gh_pr_options(segment, start))
                    for name in WRAPPERS:
                        add(
                            "quote_skip_wrapper",
                            [text, position, start, name],
                            sqp._skip_generic_shell_wrapper_options(name, segment, start),
                        )
        for arg in ["--x=1", "-f=~/a", "-f=$X", "~", "a/../b", "../a", "x", "-", "-f=../a", "$(x)", "-f=", "=a", "-f=a=b", "a=b"]:
            for cwd in (node, proj):
                add("runner_arg_escapes", [arg, str(cwd), str(node)], sqp._runner_argument_escapes_root(arg, cwd=cwd, root=node))
    finally:
        sqp._trusted_path_command, sqp.build_local_package_script_evidence = saved

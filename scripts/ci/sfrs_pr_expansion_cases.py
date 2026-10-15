"""Record GitHub pull-request argument expansion cases."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_request_services import github_pr_expansion as gpe
from codex_plugin_scanner.guard.runtime.secret_file_request_services import shell_quote_parsing as sqp

TEXTS = [
    "gh pr create --title t --body 'plain'",
    'gh pr create --title t --body "$(cat secret)"',
    "gh pr create --title t --body '$(cat secret)'",
    "gh pr create --title t --body=`id`",
    "gh pr create -b$(id)",
    "gh pr create -F $(echo x)",
    "gh pr create --body-file=$(x)",
    "gh pr create --body-file",
    "gh pr create --body",
    'gh pr new --body "$HOME"',
    'gh pr create --body "${HOME}"',
    'gh pr create --body "$1 $@ $# $?"',
    'gh pr create --body "cost $5"',
    "gh pr create --body 'a' \"$(id)\"",
    'gh pr create --body "\\$(id)"',
    'gh pr create --body "a \\\\$(id)"',
    "gh pr create --body $'a$(id)'",
    'gh pr edit 1 --body "$(id)"',
    "gh pr edit 1 --body plain",
    "gh pr view 1 --json body",
    'gh pr comment 1 --body "$(id)"',
    'gh -R o/r pr create --body "$(id)"',
    'gh pr -R o/r create --body "$(id)"',
    'gh pr --repo=o/r create --body "$(id)"',
    "gh pr",
    "gh pr -R",
    'gh issue create --body "$(id)"',
    'FOO=1 gh pr create --body "$(id)"',
    'command gh pr create --body "$(id)"',
    'command -v gh pr create --body "$(id)"',
    'command -p gh pr create --body "$(id)"',
    'command -- gh pr create --body "$(id)"',
    'time gh pr create --body "$(id)"',
    'time -p gh pr create --body "$(id)"',
    'nice -n 5 gh pr create --body "$(id)"',
    'nohup gh pr create --body "$(id)"',
    'stdbuf -oL gh pr create --body "$(id)"',
    'env gh pr create --body "$(id)"',
    'env -i FOO=1 gh pr create --body "$(id)"',
    "env -S 'gh pr create --body x' y",
    'env -u X gh pr create --body "$(id)"',
    'env -S "gh pr create --body $(id)"',
    'env -S "gh pr create --body \\"$(id)\\""',
    "env -S 'gh pr create --body $(id)'",
    'env -S"gh pr create --body `id`" x',
    "env -S '$X' gh pr create",
    "env",
    "env --",
    'sudo gh pr create --body "$(id)"',
    'sudo -u root gh pr create --body "$(id)"',
    'sudo -E -n gh pr create --body "$(id)"',
    'sudo --user=root gh pr create --body "$(id)"',
    'sudo --user root gh pr create --body "$(id)"',
    'sudo -ni gh pr create --body "$(id)"',
    'case x in a) gh pr create --body "$(id)";; esac',
    "case $x in",
    'select x in a b; do gh pr create --body "$(id)"; done',
    "select x in a b",
    'if true; then gh pr create --body "$(id)"; fi',
    'while true; do gh pr create --body "$(id)"; done',
    '! gh pr create --body "$(id)"',
    '{ gh pr create --body "$(id)"; }',
    '( gh pr create --body "$(id)" )',
    'gh pr create --body "$(id)" > out.txt',
    'gh pr create > out.txt --body "$(id)"',
    'gh pr create 2>/dev/null --body "$(id)"',
    "gh pr create >$(id) --body ok",
    "gh pr create --body ok >$(id)",
    "cat < <(id) | gh pr create --body ok",
    "echo $(id) && gh pr create --body ok",
    'echo hi; gh pr create --body "$(id)"',
    'echo hi\ngh pr create --body "$(id)"',
    'echo ok | gh pr create -F - --body "`id`"',
    "x=$(id) gh pr create --body ok",
    "ls",
    "",
    "$",
    "echo $",
    "echo '$'",
    'echo "$"',
    "echo `",
    "echo \\",
    "echo '$(id)'",
    'echo "$(id)"',
    "echo $(( 1 + 2 ))",
    "echo ${x:-y}",
    "echo $-",
    "echo $!",
    "echo $_",
    "echo $.",
    "echo $=",
    "echo $\u00e9",
    "echo $\u0661",
    'gh pr create --body "$(echo $(id))"',
    "env -S 'env -S \"gh pr create --body $(id)\" x' y",
    'env -S \'env -S "env -S \\"gh pr create --body $(id)\\" x" y\' z',
    "env -S 'a b' -S 'gh pr create --body $(id)'",
]
INTERPRETERS = [
    "python",
    "python3",
    "python3.12",
    "python3.12.1",
    "pythonw",
    "pythonw3",
    "python.exe",
    "python3.exe",
    "pythonw3.11.exe",
    "python3.",
    "python.3",
    "pypy",
    "Python3",
    "python3 ",
    " python",
    "python\n",
    "python\u0663",
    "python3..1",
    "python-3",
    "py",
    "",
    "python2",
    "pythonww",
]


def pr_expansion_cases(root: Path, add: Callable[[str, list[object], object], None]) -> None:
    for text in TEXTS:
        add("pr_body_substitution", [text], gpe._gh_pr_create_body_has_shell_command_substitution(text))
        add("pr_edit_substitution", [text], gpe._gh_pr_edit_has_shell_command_substitution(text))
        add("pr_active_expansion", [text], gpe._gh_pr_create_has_active_shell_expansion(text))
        segments = sqp._shell_token_segments(sqp._shell_tokens_preserving_quote_context(text))
        for position, segment in enumerate(segments):
            add(
                "pr_active_payloads",
                [text, position],
                list(gpe._gh_pr_env_split_string_payloads_with_active_expansion(segment)),
            )
            add("pr_create_start", [text, position], gpe._gh_pr_create_body_args_start_index(segment))
            add(
                "pr_edit_start",
                [text, position],
                gpe._gh_pr_body_args_start_index(segment, operations=frozenset({"edit"})),
            )
            for token in segment:
                add("pr_token_active", [token.raw], gpe._shell_token_has_active_expansion(token.raw))
            for start in range(len(segment) + 2):
                add("pr_skip_command", [text, position, start], gpe._skip_command_builtin_options(segment, start))
                add("pr_skip_case", [text, position, start], gpe._skip_shell_case_header(segment, start))
                add("pr_skip_select", [text, position, start], gpe._skip_shell_select_header(segment, start))
                add("pr_skip_env", [text, position, start], gpe._skip_env_wrapper_options(segment, start))
                add("pr_skip_sudo", [text, position, start], gpe._skip_sudo_wrapper_options(segment, start))
                add(
                    "pr_args_substitution",
                    [text, position, start],
                    gpe._gh_pr_create_body_args_have_substitution(segment[start:]),
                )
    for name in INTERPRETERS:
        add("pr_python_interpreter", [name], gpe._is_pytest_python_interpreter_command(name))

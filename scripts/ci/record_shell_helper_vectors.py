"""Record shell-helper outcomes before replacing the original Python owners."""

from __future__ import annotations

import hashlib
import itertools
import json
import subprocess
import sys
import types
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {
    "src/codex_plugin_scanner/guard/runtime/data_flow.py": (
        "2cae49b5d617d61d89f7b6da5788f75652e8c4043088902267c50adec50c9d09"
    ),
    "src/codex_plugin_scanner/guard/runtime/shell_structure.py": (
        "01fb4f0525876ab940cb5f3480254d112a46e3a4b823459a28247c9a005bb65e"
    ),
    "src/codex_plugin_scanner/guard/runtime/shell_command_wrappers.py": (
        "5b9cfa2345ffbbcb059220d97e3b70df74612dfc49b3804cd2a2701477579842"
    ),
}


def record() -> None:
    # This offline recorder is never an executable oracle in runtime tests.
    # Retrieve only the pinned original sources; tests consume frozen values.
    sources = {}
    originals = {}
    for name in ("shell_structure", "data_flow", "shell_command_wrappers"):
        path = f"src/codex_plugin_scanner/guard/runtime/{name}.py"
        code = subprocess.run(
            ["git", "show", f"da723a48b221c135cbce3bade1bab3ddb4959044:{path}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        sources[path] = hashlib.sha256(code).hexdigest()
        if sources[path] != EXPECTED[path]:
            raise RuntimeError("Recording requires the pinned original Python sources")
        module_name = f"codex_plugin_scanner.guard.runtime.{name}"
        module = types.ModuleType(module_name)
        module.__package__ = "codex_plugin_scanner.guard.runtime"
        sys.modules[module_name] = module
        exec(compile(code, path, "exec"), module.__dict__)
        originals[name] = module
    data_flow = originals["data_flow"]
    shell_structure = originals["shell_structure"]
    shell_command_wrappers = originals["shell_command_wrappers"]
    commands = [
        "",
        "echo ok",
        "cat < input.txt | grep value",
        "a && b || c; d & e\nf",
        "cat <<<EOF\nnpm install item",
        "cat <<EOF\n$(echo value)\nEOF\necho done",
        "cat <<'EOF'\n$(echo value)\nEOF",
        "cat <<-EOF\n\tvalue\n\tEOF\nnext",
        'cat <<ONE <<"TWO"\nfirst\nONE\nsecond\nTWO\nnext',
        "echo $(printf 'é🙂'; echo $(date))",
        "echo `printf value` | cat",
        'echo "apostrophe\'s | value" | cat',
        "(echo a | cat); echo b",
        "printf 'é🙂' | cat < 'input file'",
        "echo $(unfinished",
        "echo `unfinished",
        "cat <<EOF\nunfinished",
        "echo \\; value",
        "echo '$(literal)' |& cat",
        "a >&2 & b",
        "a &>output; b",
        "echo \u001c; echo end",
        "echo $(\u001c é🙂 \u001f)",
        "echo `\u001c é🙂 \u001f`",
    ]
    wrappers = ["env FOO=bar", "command", "time -p", "nice -n 2", "nohup", "stdbuf -o L"]
    commands.extend(
        f"{wrapper} {inner}"
        for wrapper, inner in itertools.product(
            wrappers, ["echo value", "cat < input.txt | cat", "bash -lc 'echo value'"]
        )
    )
    commands.extend(
        [
            "PATH=relative lean-ctx -c 'echo value'",
            "lean-ctx -c 'echo value' -- tail",
            "env -i FOO=bar echo value",
            "env --chdir=relative echo value",
            "bash -lc 'unterminated",
            "./bin/bash -c 'echo value'",
            "echo " + "é" * 4100,
            "echo " + "x" * 20_000,
            "bash --norc -c 'echo value'",
            "bash --init-file /dev/null -c 'echo value'",
            "bash -O extglob -c 'echo value'",
            "bash -oc extglob 'echo value' -- tail",
            "bash --rcfile=/dev/null +o nounset -c 'echo value'",
            "bash \u001c--norc\u001f -c '\u001cecho value\u001f'",
            "bash -c '\u001c\u001f'",
        ]
    )
    vectors = []
    for command in commands:
        heredocs = shell_structure.extract_heredocs(command)
        state = shell_structure.ShellScanState()
        trace = []
        index = 0
        while index < len(command):
            start = index
            index = state.advance(command, index)
            trace.append([start, index, state.quote, state.subshell_depth, state.in_backtick, state.is_top_level])
        vectors.append(
            {
                "command": command,
                "expected": {
                    "segments": data_flow.extract_command_segments(command),
                    "redirects": data_flow.extract_input_redirects(command),
                    "pipe_segments": data_flow._split_top_level_pipes(command),
                    "pipes": [asdict(p) for p in data_flow.extract_pipes(command)],
                    "heredocs": [asdict(h) for h in heredocs],
                    "substitutions": [asdict(s) for s in shell_structure.extract_command_substitution_spans(command)],
                    "expanded_substitutions": [
                        asdict(s) for s in shell_structure.extract_expanded_heredoc_substitution_spans(command)
                    ],
                    "masked_bodies": shell_structure.mask_heredoc_bodies(command, heredocs),
                    "masked_complete": shell_structure.mask_complete_heredocs(command, heredocs),
                    "normalization": asdict(shell_command_wrappers.normalize_transparent_shell_command(command)),
                    "trace": trace,
                },
            }
        )
    for command in (
        "echo " + "x" * 65_536,
        "cat <<EOF\n" + "x" * 190_000 + "\nEOF\necho done",
        "cat <<EOF\n" + "\u001c" * 140_000 + "\nEOF",
    ):
        heredocs = shell_structure.extract_heredocs(command)
        vectors.append(
            {
                "command": command,
                "expected": {
                    "heredocs": [asdict(h) for h in heredocs],
                    "substitutions": [asdict(s) for s in shell_structure.extract_command_substitution_spans(command)],
                    "masked_bodies": shell_structure.mask_heredoc_bodies(command, heredocs),
                    "masked_complete": shell_structure.mask_complete_heredocs(command, heredocs),
                },
            }
        )
    command = "bash -c '" + "é" * 4100 + "'"
    vectors.append(
        {
            "command": command,
            "expected": {
                "normalization": asdict(shell_command_wrappers.normalize_transparent_shell_command(command)),
            },
        }
    )
    target = ROOT / "tests/fixtures/shell-helper-python.v1.json"
    target.write_text(
        json.dumps(
            {"schema": "shell-helper-python.v1", "sources": sources, "vectors": vectors}, ensure_ascii=True, indent=2
        )
        + "\n"
    )
    print(f"Recorded {len(vectors)} original Python vectors")


if __name__ == "__main__":
    record()

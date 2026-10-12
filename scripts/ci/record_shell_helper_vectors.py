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
    "src/codex_plugin_scanner/guard/runtime/command_option_parsing.py": (
        "cf9143df681b5db68cd5f03f12028dda0ad4e88ad9a9f7c9e09c330af7f2dd68"
    ),
    "src/codex_plugin_scanner/guard/runtime/env_wrapper.py": (
        "e4f46e49ca92b342d9449245eb67064b749d13a844934dcc68b83a383cfe4bcd"
    ),
    "src/codex_plugin_scanner/guard/runtime/interpreter_options.py": (
        "193d26d4434ac4b7a079f3ec311ee9dcfd4d097a5cfec2a1cec63ebbf273d17f"
    ),
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
    legacy_path = "tests/test_interpreter_options.py"
    legacy = subprocess.run(
        ["git", "show", f"da723a48b221c135cbce3bade1bab3ddb4959044:{legacy_path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    legacy_digest = hashlib.sha256(legacy).hexdigest()
    if legacy_digest != "478f2f9c313000563d8326fa43c8af6e4b87a22a77a21d5f3239c3576e391082":
        raise RuntimeError("Recording requires the original interpreter tests")
    for name in (
        "env_wrapper",
        "interpreter_options",
        "shell_structure",
        "data_flow",
        "shell_command_wrappers",
        "command_option_parsing",
    ):
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
            "bash --command 'echo value'",
            "fish --command='echo value'",
            "bash --rcfile /example/setup.rc -c 'echo value'",
            "bash -co pipefail 'echo value'",
            "bash -cOextglob 'echo value'",
            "bash --command -c 'tail value'",
            "bash --rcfile --command -c 'echo value'",
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
        "cat <<EOF\n" + "x" * 512_000 + "\nEOF",
        "cat <<EOF\n" + "x" * 2_200_000 + "\nEOF",
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
    for command in ("bash -c '" + "é" * 4100 + "'", "  " + "x" * 1_500_000 + "  "):
        vectors.append(
            {
                "command": command,
                "expected": {
                    "normalization": asdict(shell_command_wrappers.normalize_transparent_shell_command(command)),
                },
            }
        )
    command = ":<<E\nE\n" * 20_000
    heredocs = shell_structure.extract_heredocs(command)
    vectors.append(
        {
            "command": command,
            "expected": {
                "heredocs": [asdict(h) for h in heredocs],
                "masked_bodies": shell_structure.mask_heredoc_bodies(command, heredocs),
                "masked_complete": shell_structure.mask_complete_heredocs(command, heredocs),
            },
        }
    )
    interpreter = originals["interpreter_options"]
    interpreter_parts = [
        ["bash", "-c", "sentinel"],
        ["bash", "-lc", "sentinel"],
        ["bash", "-cl", "sentinel"],
        ["bash", "-co", "pipefail", "sentinel"],
        ["bash", "-cOextglob", "sentinel"],
        ["bash", "--noprofile", "-cl", "sentinel"],
        ["bash", "--rcfile", "setup.rc", "-cl", "sentinel"],
        ["fish", "--command", "sentinel"],
        ["fish", "--command=sentinel"],
        ["bash", "-oc", "sentinel"],
        ["bash", "--", "-cl", "sentinel"],
        ["bash", "--rcfile"],
        ["bash", "-cl"],
        ["bash", "script.sh", "-cl", "sentinel"],
        ["fish", "--command="],
        ["bash", "-cl", "sentinel", "argument-zero", "-c", "ignored"],
        ["bash", "-éc", "sentinel"],
        ["bash", "-\u0345c", "sentinel"],
        ["bash", "\u001c--command\u001f", "\u001csentinel\u001f"],
    ]
    interpreter_vectors = []
    for parts in interpreter_parts:
        result = interpreter.shell_interpreter_command_payload(parts, 0)
        interpreter_vectors.append({"parts": parts, "command_index": 0, "expected": asdict(result) if result else None})
    target = ROOT / "tests/fixtures/shell-helper-python.v1.json"
    options = originals["command_option_parsing"]
    option_vectors = []
    values, flags = frozenset({"-a", "--body"}), frozenset({"-f", "-j", "--force", "--no-force"})
    arguments_cases = [()]
    for count in range(1, 4):
        arguments_cases.extend(itertools.product(("-a", "-ja", "--future", "--", "value", "-f"), repeat=count))
    arguments_cases.extend(
        (
            ("--force", "--no-force=false"),
            ("--force=false", "--force=YES"),
            ("-é", "--body=value"),
            ("-a",),
            ("--body", "-a"),
            ("--body=value", "-ja", "value"),
        )
    )
    for arguments in arguments_cases:
        common = {"arguments": list(arguments), "options_with_values": sorted(values), "known_flags": sorted(flags)}
        semantics = options.argument_semantics(
            arguments, options_with_values=values, inverse_flag_pairs=frozenset({("--force", "--no-force")})
        )
        option_vectors.extend(
            (
                {
                    "action": "argument_semantics",
                    "input": {**common, "inverse_flag_pairs": [["--force", "--no-force"]]},
                    "expected": {
                        "present_flags": sorted(semantics.present_flags),
                        "effective_options": semantics.effective_options,
                    },
                },
                {
                    "action": "matches_subcommands",
                    "input": {**common, "subcommands": ["value"]},
                    "expected": options.matches_subcommands_conservatively(
                        arguments, ("value",), options_with_values=values, known_flags=flags
                    ),
                },
                {
                    "action": "flags_all",
                    "input": {**common, "required_flags": ["-a"]},
                    "expected": options.flags_present_in_all_option_parses(
                        arguments, frozenset({"-a"}), options_with_values=values, known_flags=flags
                    ),
                },
            )
        )
    for argument in (
        "-a",
        "-ja",
        "-aVALUE",
        "--body=value",
        "--body",
        "--force",
        "--future",
        "value",
        "--force=false",
        "--force=YES",
    ):
        common = {"argument": argument, "options_with_values": sorted(values), "known_flags": sorted(flags)}
        option_vectors.extend(
            (
                {
                    "action": "option_advance",
                    "input": common,
                    "expected": options.known_option_advance(argument, options_with_values=values, known_flags=flags),
                },
                {
                    "action": "long_flag",
                    "input": {"argument": argument},
                    "expected": options.long_flag_assignment_is_enabled(argument),
                },
            )
        )
    option_test = "tests/test_command_option_parsing_reference.py"
    for arguments in (
        ("-a", "synthetic"),
        ("-asynthetic",),
        ("-ja", "synthetic"),
        ("-a",),
        ("-ja",),
        ("-a", "synthetic", "--body"),
        ("--body", "-a"),
        ("--", "-a", "synthetic"),
        ("--future", "-a", "synthetic"),
    ):
        option_vectors.append(
            {
                "action": "flags_all",
                "input": {
                    "arguments": list(arguments),
                    "required_flags": ["-a"],
                    "options_with_values": ["-a", "--body"],
                    "known_flags": ["-j"],
                },
                "expected": options.flags_present_in_all_option_parses(
                    arguments,
                    frozenset({"-a"}),
                    options_with_values=frozenset({"-a", "--body"}),
                    known_flags=frozenset({"-j"}),
                ),
            }
        )
    option_test_bytes = subprocess.run(
        ["git", "show", f"da723a48b221c135cbce3bade1bab3ddb4959044:{option_test}"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    if (
        hashlib.sha256(option_test_bytes).hexdigest()
        != "f67d36beecd254159e14b44090ab9cda1123bf744ee23c40d4461083a34083e5"
    ):
        raise RuntimeError("Original option test digest mismatch")
    target.write_text(
        json.dumps(
            {
                "schema": "shell-helper-python.v1",
                "sources": sources,
                "vectors": vectors,
                "interpreter_vectors": interpreter_vectors,
                "option_vectors": option_vectors,
                "legacy_test_sources": {
                    legacy_path: legacy_digest,
                    option_test: hashlib.sha256(option_test_bytes).hexdigest(),
                },
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n"
    )
    print(f"Recorded {len(vectors)} original Python vectors")


if __name__ == "__main__":
    record()

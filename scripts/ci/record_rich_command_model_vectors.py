"""Record the original command model; refuse to record replacement code."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HASHES = {
    f"src/codex_plugin_scanner/guard/runtime/{name}.py": digest
    for name, digest in {
        "command_model": "08e5cd246e20bd6e327f77d0986ac37ad89fa1ef6dd42e336addf2dfcd9d721c",
        "command_structure": "d07b8da7b625a170acee771889ea340c049731b28c032b6179931de746adef5a",
        "command_tokens": "2bb624010d3dfea8cfff5f5b16face626033b76c894e313b2221df2ecd23f358",
        "command_segment_parsing": "718973d25bf5d91943a27453c26ec505c00c0b89e827757e1ae6edf362955be5",
        "env_wrapper": "e4f46e49ca92b342d9449245eb67064b749d13a844934dcc68b83a383cfe4bcd",
    }.items()
}

sys.path.insert(0, str(ROOT / "src"))


def json_value(value: object) -> object:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: json_value(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: json_value(item) for key, item in value.items()}
    return value


def main() -> None:
    for path, digest in HASHES.items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != digest:
            raise SystemExit("Original source hashes differ; use the pinned source checkout")
    from codex_plugin_scanner.guard.runtime import command_model, command_tokens, env_wrapper

    rows: list[dict[str, object]] = []

    def record(action: str, args: dict[str, object], function: object) -> None:
        try:
            result = function()  # type: ignore[operator]
            rows.append({"action": action, "args": args, "result": json_value(result)})
        except ValueError as error:
            rows.append({"action": action, "args": args, "error": str(error)})

    commands = [
        "",
        "   ",
        "echo ok",
        "PATH=/bin env -i X=1 git status",
        "sudo -n env PATH=/bin git push --force",
        "env -u -i python -m pytest",
        "bash -lc 'git clean -fdx'",
        "sh -c 'echo ok' -- arg",
        "echo 'unterminated",
        "printf café; echo 雪",
        "echo $HOME",
        "echo $(git status)",
        "echo `git status`",
        "echo $(echo $(pwd))",
        "cat < input > output 2>>error",
        "echo 'value>help'",
        "echo a|cat&&pwd",
        "cat <<'EOF'\n$(echo inert)\nEOF",
        "cat <<EOF\n$(echo active)\nEOF",
        "sh <<EOF\ngit status\nEOF",
        "bash <<'EOF'\necho hello\nEOF",
        "cat <<-EOF\n\ttext\n\tEOF",
        "echo hi & echo bye",
        "(echo a); echo b",
        "env -S 'X=1 git status'",
        "sudo --user=root -- git status",
        r"'C:\\tools\\tool.exe' --help",
        "echo a\\ b",
        'echo "a\\q"',
        "x" * 32769,
        "é" * 16385,
        " ; ".join("echo ok" for _ in range(129)),
        "echo " + "x " * 2049,
    ]

    def model_value(command: str, **kwargs: object) -> dict[str, object]:
        model = command_model.parse_shell_command(command, **kwargs)
        return {
            "raw_text": model.raw_text,
            **model.to_dict(),
            "embedded_commands": [{**item.to_dict(), "text": item.text} for item in model.embedded_commands],
        }

    # Harvest literal command inputs from the original regression suite.
    tree = ast.parse((ROOT / "tests/test_guard_command_model.py").read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "parse_shell_command"
            and node.args
        ):
            try:
                value = ast.literal_eval(node.args[0])
            except (ValueError, TypeError):
                continue
            if isinstance(value, str):
                commands.append(value)
    for command in dict.fromkeys(commands):
        for normalize in (True, False):
            args = {
                "command": command,
                "cwd": "/workspace",
                "home_dir": "/profile",
                "dialect": "posix",
                "transport": "shell_string",
                "extraction_provenance": "fixture",
                "normalize_wrappers": normalize,
            }
            record(
                "parse",
                args,
                lambda command=command, normalize=normalize: model_value(
                    command,
                    cwd=Path("/workspace"),
                    home_dir=Path("/profile"),
                    extraction_provenance="fixture",
                    normalize_wrappers=normalize,
                ),
            )
        record("tokens", {"command": command}, lambda command=command: command_tokens.shell_tokens(command))
    for dialect in ("powershell", "cmd", "argv", "unknown"):
        args = {"command": "echo hi", "dialect": dialect}
        record(
            "parse",
            args,
            lambda dialect=dialect: {
                "raw_text": "echo hi",
                **command_model.parse_shell_command("echo hi", dialect=dialect).to_dict(),
            },
        )
    for value in (None, "git", "/bin/TOOL", r"C:\\bin\\TOOL.EXE"):
        record("executable", {"value": value}, lambda value=value: command_tokens.executable_name(value))
    env_cases = [
        [],
        ["-i"],
        ["-u"],
        ["-u", "-i", "echo"],
        ["--", "X=1", "echo"],
        ["-i", "-u", "OLD", "X=1", "echo", "ok"],
        ["-C", "src", "echo"],
        ["--chdir=/workspace/sub", "echo"],
        ["-P", "/bin", "echo"],
        ["--unknown", "echo"],
        ["-S", "X=1 git status"],
        ["--split-string=echo 'a b'"],
        ["-S", "'bad"],
        ["-v", "-0", "echo"],
        ["X=1", "X=2", "echo"],
        ["--unset=OLD", "echo"],
        ["--ignore-environment", "echo"],
        ["-S", "env -S 'echo ok'"],
        ["x"] * 257,
    ]
    for tokens in env_cases:
        args = {"tokens": tokens, "inherited_environment": {"OLD": "prior", "KEEP": "kept"}, "cwd": "/workspace"}
        record(
            "env",
            args,
            lambda tokens=tokens: env_wrapper.parse_env_wrapper(
                tokens, inherited_environment={"OLD": "prior", "KEEP": "kept"}, cwd=Path("/workspace")
            ),
        )
        record(
            "leading_environment",
            {"tokens": tokens},
            lambda tokens=tokens: command_tokens.leading_environment(tuple(tokens)),
        )
    output = {
        "schema": "guard-rich-command-model-vectors.v1",
        "source_hashes": HASHES,
        "source_commit": "da723a48b221c135cbce3bade1bab3ddb4959044",
        "vectors": rows,
    }
    destination = ROOT / "tests/fixtures/native_rich_command_model.json"
    destination.write_text(json.dumps(output, ensure_ascii=True, indent=2) + "\n")
    print(f"Recorded {len(rows)} original outcomes")


if __name__ == "__main__":
    main()

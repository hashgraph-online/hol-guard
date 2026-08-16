#!/usr/bin/env python3
"""Differential checks for the shadow-only Rust command model."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command

EXACT_FIXTURES = (
    "git status --short",
    "printf 'hello world'",
    "printf '' \"\"",
    "FOO=bar PATH=/tmp tool --name 'two words'",
    "A_B=one FOO='two words' tool ''",
    "FOO=bar",
    "printf 'a|b' | grep b",
    "echo one && echo two",
    "echo one || echo two",
    "echo one; echo two",
    "echo one\necho two",
    "printf 'a&&b' 'a||b' 'a;b'",
    r'printf "%s" "a\q" "a\$b" "a\"b" "a\\b"',
    "echo foo\\\nbar",
    "printf x\u00a0y",
    r"printf escaped\ space",
    r"printf \#not-a-comment",
    "./tool --flag=value",
)
UNCERTAIN_FIXTURES = (
    "echo $(uname)",
    "echo `uname`",
    "cat <<EOF",
    "echo hello > out.txt",
    "sleep 1 &",
    "sudo rm -rf /tmp/example",
    "env FOO=bar tool",
    "time tool",
    "stdbuf -o0 tool",
    "sh -c 'rm -rf /tmp/example'",
    "bash ./script.sh",
    "eval 'rm -rf /tmp/example'",
    "exec rm -rf /tmp/example",
    "source ./script.sh",
    ". ./script.sh",
    "if true; then echo yes; fi",
    "for item in one two; do echo \"$item\"; done",
    "while true; do break; done",
    "case \"$value\" in one) echo one;; esac",
    "[[ -f Cargo.toml ]]",
    "echo $'non-posix quote'",
    'echo $"localized quote"',
    "xargs rm -rf",
    "parallel rm ::: one",
    "find . -exec rm {} ;",
    "(echo nested)",
    "{ echo nested; }",
    "echo 'unterminated",
    "echo trailing\\",
)


def _native(binary: Path, command: str) -> dict[str, object]:
    payload = json.dumps(
        {
            "command": command,
            "dialect": "posix",
            "transport": "shell_string",
            "extraction_provenance": "guard-shell",
        }
    )
    completed = subprocess.run(
        [str(binary), "command-model", "--stdin"],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    )
    return json.loads(completed.stdout)


def _comparable(command: dict[str, object]) -> dict[str, object]:
    return {
        "normalized_text": command["normalized_text"],
        "dialect": command["dialect"],
        "transport": command["transport"],
        "extraction_provenance": command["extraction_provenance"],
        "wrapper_chain": command["wrapper_chain"],
        "segments": command["segments"],
        "confidence": command["confidence"],
        "uncertainty_reason": command["uncertainty_reason"],
        "path_overridden": command["path_overridden"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()

    capabilities = subprocess.run(
        [str(args.binary), "capabilities", "--json"],
        text=True,
        capture_output=True,
        check=True,
        timeout=5,
    )
    features = set(json.loads(capabilities.stdout)["features"])
    assert "pre-tool-command-model-shadow-v1" in features

    for fixture in EXACT_FIXTURES:
        python_model = parse_shell_command(fixture).to_dict()
        native_model = _native(args.binary, fixture)
        assert python_model["confidence"] == "exact", fixture
        assert native_model["confidence"] == "exact", fixture
        assert _comparable(native_model) == _comparable(python_model), fixture

    for fixture in UNCERTAIN_FIXTURES:
        native_model = _native(args.binary, fixture)
        assert native_model["confidence"] == "uncertain", fixture
        assert native_model["segments"] == [], fixture
        assert native_model["uncertainty_reason"], fixture

    print(
        json.dumps(
            {
                "exact_fixture_count": len(EXACT_FIXTURES),
                "uncertain_fixture_count": len(UNCERTAIN_FIXTURES),
                "status": "ok",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

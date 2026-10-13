"""Freeze native-free outcomes from pinned Python shell helper bodies."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

BASE = "68558a59d9e8b6d4a8a86ef9de9263de41248068"
ROOT = Path(__file__).resolve().parents[2]
SERVICE = "src/codex_plugin_scanner/guard/runtime/secret_file_request_services/"
FUNCTIONS = {
    "github_pr_body_safety.py": (),
    "github_shell_capabilities.py": (
        "_github_environment_name",
        "_github_shell_has_dynamic_arguments",
        "_shell_token_has_expansion",
        "github_argument_token_has_untrusted_expansion",
        "_shell_command_substitution_payloads",
        "_read_command_substitution",
        "_read_backtick_command_substitution",
        "_iter_shell_pipelines",
    ),
    "github_pr_expansion.py": ("_shell_token_has_active_expansion", "_is_pytest_python_interpreter_command"),
}


def main() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from codex_plugin_scanner.guard import native_resident_client

    def forbid_native(*args, **kwargs):
        raise AssertionError("Parity capture must never invoke a native client")

    native_resident_client.native_resident_client_request = forbid_native
    namespaces = {}
    hashes = {}
    for filename, functions in FUNCTIONS.items():
        source = subprocess.check_output(["git", "show", f"{BASE}:{SERVICE}{filename}"], cwd=ROOT)
        hashes[SERVICE + filename] = hashlib.sha256(source).hexdigest()
        namespace = {
            "__name__": "frozen_python_shell_helpers",
            "__package__": "codex_plugin_scanner.guard.runtime.secret_file_request_services",
        }
        exec(compile(source, filename, "exec"), namespace)
        namespaces.update({name: namespace[name] for name in functions})
    file_proof = "src/codex_plugin_scanner/guard/runtime/github_pr_body_file.py"
    hashes[file_proof] = hashlib.sha256(
        subprocess.check_output(["git", "show", f"{BASE}:{file_proof}"], cwd=ROOT)
    ).hexdigest()
    tokens = [
        "",
        "plain",
        "$HOME",
        "${HOME}",
        "$9",
        "$$",
        "$(pwd)",
        "`pwd`",
        "'$HOME'",
        '"$HOME"',
        r"\$HOME",
        "é",
        "雪",
        "a$b",
        "gh",
        "python",
        "python3.12",
        "pythonw.exe",
        "python3x",
        "GH_TOKEN",
        "GH_HOST",
        "GITHUB_TOKEN",
        "OTHER",
    ]
    scripts = [
        "",
        "gh pr view 1",
        "echo '$HOME'",
        'gh api "$ENDPOINT"',
        "gh api ${URL}",
        "gh pr create --body $(cat notes.md)",
        "echo `pwd`",
        "echo $(printf $(pwd))",
        "echo $(printf 'a)b')",
        "echo é$(printf 雪)",
        "echo $(unfinished",
        "echo `unfinished",
    ]
    cases = []

    def record(name, *args):
        try:
            result = namespaces[name](*args)
            cases.append({"call": name, "args": list(args), "result": result})
        except AssertionError:
            raise
        except Exception as error:
            cases.append({"call": name, "args": list(args), "exception": type(error).__name__, "error": str(error)})

    for token in tokens:
        for name in (
            "_github_environment_name",
            "_shell_token_has_expansion",
            "github_argument_token_has_untrusted_expansion",
            "_shell_token_has_active_expansion",
            "_is_pytest_python_interpreter_command",
        ):
            record(name, token)
    for script in scripts:
        record("_shell_command_substitution_payloads", script)
        record("_github_shell_has_dynamic_arguments", script)
        for index, character in enumerate(script):
            if character == "`":
                record("_read_backtick_command_substitution", script, index + 1)
            if script[index : index + 2] == "$(":
                record("_read_command_substitution", script, index + 2)
    for parts in (
        [],
        ["gh", "pr", "view"],
        ["gh", "api", "|", "cat"],
        ["echo", "x", ";", "gh", "pr", "list"],
        ["a", "&&", "b", "||", "c"],
        ["(", "gh", "pr", "list", ")"],
    ):
        record("_iter_shell_pipelines", parts)
    fixtures = {}
    for name in ("classify_github_shell_capabilities", "intermediate_tokens", "fs_helpers", "github_body"):
        path = ROOT / "rust/crates/guard-command/tests/fixtures/sfrs" / (name + ".json.gz")
        if path.exists():
            fixtures[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    output = ROOT / "rust/crates/guard-command/tests/fixtures/shell_request_authority.json"
    output.write_text(
        json.dumps(
            {
                "schema": "guard-shell-request-authority-python-parity.v1",
                "source_commit": BASE,
                "source_sha256": hashes,
                "retained_original_fixture_sha256": fixtures,
                "cases": cases,
            },
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    print(f"Frozen {len(cases)} native-free old Python outcomes; {len(fixtures)} original fixture hashes pinned.")


if __name__ == "__main__":
    main()

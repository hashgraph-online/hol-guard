"""Generate independent CPython 3.12 matcher observations for native tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.command_path_set_matcher import ExecutablePathSetMatcher
from codex_plugin_scanner.guard.runtime.command_rules import AllMatcher, AnyMatcher, ExecutableMatcher, PipelineMatcher


def examples(matcher: object) -> set[str]:
    if isinstance(matcher, (AnyMatcher, AllMatcher)):
        return {value for child in matcher.matchers for value in examples(child)}
    if isinstance(matcher, PipelineMatcher):
        return {f"{left} | {right}" for left in examples(matcher.producer) for right in examples(matcher.consumer)}
    if isinstance(matcher, (ExecutableMatcher, ExecutablePathSetMatcher)):
        paths = [matcher.subcommands] if isinstance(matcher, ExecutableMatcher) else sorted(matcher.paths)
        selected = paths[:1] + paths[-1:]
        flags = sorted(matcher.required_flags)
        values = [token for option, allowed in matcher.required_option_values for token in (option, min(allowed))]
        return {" ".join((min(matcher.executables), *path, *flags, *values, "fixture-target")) for path in selected}
    return set()


def main() -> None:
    if sys.version_info[:2] != (3, 12):
        raise SystemExit("Native v1 oracle requires CPython 3.12 / UCD15.")
    commands = {
        value for extension in REGISTRY.extensions for rule in extension.rules for value in examples(rule.matcher)
    }
    commands.update(
        {
            "pwd",
            "printf café",
            "ollama push -\ua7cbh model",
            "ollama push -\u0130h model",
            "ollama push -\u212ah model",
            "ollama push -\u03a3h model",
            "ollama push CAFÉ",
            "python -m json.tool café",
            "php script.php café",
            "repo2nb reverse café$FLAGS",
            "echo 'ollama push model'",
            "notollama push model",
            "ollama list",
            "ollama push model",
            "ollama push",
            "ollama rm",
            "ollama rm model",
            "ollama.exe push model",
            "ollama.cmd rm model",
            "/usr/local/bin/ollama push model",
            "ollama --unknown push model",
            "ollama push model --help",
            "ollama --help push model",
            "ollama push -h",
            "ollama push --unknown --help model",
            "ollama push --unknown=value --help model",
            "ollama push --help=false model",
            "ollama push --help=true model",
            "ollama push model -- -h",
            "ollama rm one --help && ollama push two",
            "ollama push one | ollama rm two",
            "ollama push 'secret-token-value'",
            "zsh -lc 'ollama push model'",
            "git status",
            "rm -rf /",
        }
    )
    fixtures = []
    for text in sorted(commands):
        command = parse_shell_command(text)
        model = command.to_dict()
        model["parser_profile"] = "cpython-3.12-reference"
        fixtures.append(
            {
                "command": text,
                "model": model,
                "observations": [item.to_dict() for item in REGISTRY.observations(command)],
            }
        )
    target = (
        Path(__file__).resolve().parents[1]
        / "rust/crates/guard-command/tests/fixtures/native-command-observations-v1.json"
    )
    target.write_text(
        json.dumps(
            {"semantic_profile": "cpython-3.12-ucd15", "cases": fixtures},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"cases": len(fixtures), "bytes": target.stat().st_size}))


if __name__ == "__main__":
    main()

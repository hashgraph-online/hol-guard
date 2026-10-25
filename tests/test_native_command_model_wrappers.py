from __future__ import annotations

from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native


def _model() -> tuple[str, dict]:
    command = "sudo --command-timeout 10 git push origin main --force"
    return command, {
        "normalized_text": command,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": ["sudo"],
        "segments": [
            {
                "text": command,
                "tokens": command.split(),
                "executable": "git",
                "arguments": ["push", "origin", "main", "--force"],
                "environment_names": [],
                "wrapper_chain": ["sudo"],
                "path_overridden": False,
                "execution_context": "top:0",
                "pipeline_index": 0,
                "span": {"source": "normalized", "start": 0, "end": len(command)},
            }
        ],
        "confidence": "exact",
        "uncertainty_reason": None,
        "path_overridden": False,
        "parser_profile": "posix-bounded-wrappers-v2",
    }


def test_request_bound_wrapper_provenance_survives_conversion() -> None:
    command, model = _model()
    canonical = _canonical_command_from_native(command, model)
    assert canonical is not None
    assert canonical.normalized_text == command
    assert canonical.wrapper_chain == ("sudo",)
    assert canonical.segments[0].wrapper_chain == ("sudo",)
    assert canonical.segments[0].tokens == tuple(command.split())
    assert canonical.segments[0].executable == "git"
    assert canonical.segments[0].arguments[-1] == "--force"


@pytest.mark.parametrize(
    "mutation",
    [
        "legacy-profile",
        "missing-wrapper",
        "wrong-wrapper",
        "unknown-option",
        "invalid-timeout",
        "executable",
        "span",
        "dialect",
    ],
)
def test_mismatched_wrapper_evidence_is_rejected(mutation: str) -> None:
    command, original = _model()
    model = deepcopy(original)
    segment = model["segments"][0]
    if mutation == "legacy-profile":
        model["parser_profile"] = "posix-simple-v1"
    elif mutation == "missing-wrapper":
        model["wrapper_chain"] = []
    elif mutation == "wrong-wrapper":
        segment["wrapper_chain"] = ["env"]
    elif mutation == "unknown-option":
        segment["tokens"][1] = "--shell"
    elif mutation == "invalid-timeout":
        segment["tokens"][2] = "payload"
    elif mutation == "executable":
        segment["executable"] = "true"
    elif mutation == "span":
        segment["span"]["start"] = 1
    elif mutation == "dialect":
        model["dialect"] = "powershell"
    assert _canonical_command_from_native(command, model) is None


def _script_model(script: str) -> dict:
    return {
        "normalized_text": script,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": [],
        "segments": [
            {
                "text": script,
                "tokens": script.split(),
                "executable": script.split()[0],
                "arguments": script.split()[1:],
                "environment_names": [],
                "wrapper_chain": [],
                "path_overridden": False,
                "execution_context": "top:0",
                "pipeline_index": 0,
                "span": {"source": "normalized", "start": 0, "end": len(script)},
            }
        ],
        "confidence": "exact",
        "uncertainty_reason": None,
        "path_overridden": False,
        "parser_profile": "posix-simple-v1",
    }


def test_a_shell_carrying_its_whole_script_is_bound_to_that_script() -> None:
    script = "gh pr view 12"
    for command in (
        f"sh -c '{script}'",
        f"bash -c '{script}'",
        f'dash -c "{script}"',
    ):
        canonical = _canonical_command_from_native(command, _script_model(script))
        assert canonical is not None, command
        # The script is what runs, and the words it was written with are kept.
        assert canonical.normalized_text == script
        assert canonical.raw_text == command
        assert canonical.segments[0].executable == "gh"


@pytest.mark.parametrize(
    "command",
    [
        "sh -c 'gh pr view 12' -- argument",
        "command sh -c 'gh pr view 12'",
        "env CI=1 sh -c 'gh pr view 12'",
        'sh -c "$COMMAND"',
        "perl -e 'gh pr view 12'",
        "sh -x 'gh pr view 12'",
        # A login shell and `zsh` read a startup file before the script, so
        # the script is not the whole command either reads.
        "bash -lc 'gh pr view 12'",
        "sh -cl 'gh pr view 12'",
        "zsh -c 'gh pr view 12'",
        "gh pr view 12 ; true",
        # The tokenizer keeps an operator with the word beside it, while the
        # shell reads it as its own word around the whole invocation.
        "sh -c 'gh pr view 12'>/tmp/out",
        "sh -c 'gh pr view 12' 2>&1",
        "sh -c 'gh pr view 12'|cat",
        "sh -c 'gh pr view 12';rm -rf /tmp/x",
    ],
)
def test_any_other_spelling_keeps_the_strict_request_binding(command: str) -> None:
    assert _canonical_command_from_native(command, _script_model("gh pr view 12")) is None


def _simple_model(
    command: str, executable: str | None, environment_names: list[str], wrappers: list[str] | None = None
) -> dict:
    wrappers = wrappers or []
    tokens = command.split()
    arguments = tokens[tokens.index(executable) + 1 :] if executable in tokens else []
    path_overridden = "PATH" in environment_names
    return {
        "normalized_text": command,
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": wrappers,
        "segments": [
            {
                "text": command,
                "tokens": tokens,
                "executable": executable,
                "arguments": arguments,
                "environment_names": environment_names,
                "wrapper_chain": wrappers,
                "path_overridden": path_overridden,
                "execution_context": "top:0",
                "pipeline_index": 0,
                "span": {"source": "normalized", "start": 0, "end": len(command)},
            }
        ],
        "confidence": "exact",
        "uncertainty_reason": None,
        "path_overridden": path_overridden,
        "parser_profile": "posix-bounded-wrappers-v2" if wrappers else "posix-simple-v1",
    }


@pytest.mark.parametrize(
    ("command", "executable", "names"),
    [
        ("env MODE=dev agentbridge run app.tools", "agentbridge", ["MODE"]),
        ("env PATH=/tmp/x bun run build", "bun", ["PATH"]),
        ("FOO=1 /usr/bin/env BAR=2 npm test", "npm", ["FOO", "BAR"]),
        ("env FOO=1 env BAR=2 exec ls", "ls", ["FOO", "BAR"]),
    ],
)
def test_an_env_prefix_binds_to_the_program_behind_it(command: str, executable: str, names: list[str]) -> None:
    canonical = _canonical_command_from_native(command, _simple_model(command, executable, names))
    assert canonical is not None
    assert canonical.segments[0].executable == executable
    assert canonical.segments[0].environment_names == tuple(names)
    assert canonical.path_overridden is ("PATH" in names)


@pytest.mark.parametrize(
    ("command", "executable", "names"),
    [
        # `env` takes `A-B=1` as one more assignment, so `curl` is not the program.
        ("env FOO=1 A-B=1 curl https://example.test", "curl", ["FOO"]),
        # An option or a bare `env` leaves `env` itself as the executable.
        ("env -i FOO=1 npm test", "npm", ["FOO"]),
        ("env npm test", "npm", []),
        # A name the prefix sets is still reported.
        ("env FOO=1 npm test", "npm", []),
    ],
)
def test_an_env_spelling_the_parser_does_not_step_past_is_not_rebound(
    command: str, executable: str, names: list[str]
) -> None:
    assert _canonical_command_from_native(command, _simple_model(command, executable, names)) is None


@pytest.mark.parametrize(
    ("command", "executable", "names", "wrappers"),
    [
        ("env FOO=1 sudo ls", "ls", ["FOO"], ["sudo"]),
        ("sudo env FOO=1 ls", "ls", ["FOO"], ["sudo"]),
        ("sudo command ls", "ls", [], ["sudo"]),
        ("command sudo -n ls", "ls", [], ["sudo"]),
        ("time env FOO=1 npm test", "npm", ["FOO"], []),
        ("command ls -la", "ls", [], []),
        ("time cargo build", "cargo", [], []),
    ],
)
def test_prefixes_bind_in_the_order_the_text_writes_them(
    command: str, executable: str, names: list[str], wrappers: list[str]
) -> None:
    canonical = _canonical_command_from_native(command, _simple_model(command, executable, names, wrappers))
    assert canonical is not None
    assert canonical.segments[0].executable == executable
    assert canonical.segments[0].environment_names == tuple(names)
    assert canonical.wrapper_chain == tuple(wrappers)


@pytest.mark.parametrize(
    ("command", "executable", "wrappers"),
    [
        # An option keeps `command` and `time` as the executable.
        ("command -v ls", "ls", []),
        ("time -p ls", "ls", []),
        # A prefix with no program behind it is the prefix itself.
        ("command", None, []),
        # A wrapper the text writes must be in the chain the parser reports.
        ("env FOO=1 sudo ls", "ls", []),
    ],
)
def test_a_prefix_the_parser_does_not_step_past_is_not_rebound(
    command: str, executable: str | None, wrappers: list[str]
) -> None:
    names = ["FOO"] if "FOO=1" in command else []
    assert _canonical_command_from_native(command, _simple_model(command, executable, names, wrappers)) is None

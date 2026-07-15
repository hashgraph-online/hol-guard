from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_model import MAX_COMMAND_BYTES, parse_shell_command
from codex_plugin_scanner.guard.runtime.command_rules import (
    AllMatcher,
    AnyMatcher,
    ArgumentMatcher,
    ExecutableMatcher,
    PipelineMatcher,
)


def test_parse_shell_command_preserves_compound_suffix_and_path_override() -> None:
    parsed = parse_shell_command("PATH=/usr/bin:/bin npx vitest run && git reset --hard HEAD~1")

    assert [segment.executable for segment in parsed.segments] == ["npx", "git"]
    assert parsed.segments[0].environment_names == ("PATH",)
    assert parsed.path_overridden is True
    assert parsed.segments[1].arguments == ("reset", "--hard", "HEAD~1")
    assert parsed.confidence == "exact"


def test_parse_shell_command_tracks_env_wrapper_path_override() -> None:
    parsed = parse_shell_command("env -i PATH=/usr/bin:/bin npx vitest run")

    assert parsed.segments[0].executable == "npx"
    assert parsed.segments[0].environment_names == ("PATH",)
    assert parsed.path_overridden is True


def test_parse_shell_command_tracks_sudo_and_nested_environment_wrapper() -> None:
    parsed = parse_shell_command("sudo -n env PATH=/usr/bin:/bin git -C repo push --force")

    assert parsed.wrapper_chain == ("sudo", "env")
    assert parsed.segments[0].wrapper_chain == ("sudo", "env")
    assert parsed.segments[0].executable == "git"
    assert parsed.segments[0].arguments == ("-C", "repo", "push", "--force")
    assert parsed.path_overridden is True


def test_parse_shell_command_skips_all_sudo_options_with_values() -> None:
    parsed = parse_shell_command(
        "sudo --command-timeout 10 --login-class staff git --config-env token=TOKEN push --force"
    )

    assert parsed.segments[0].executable == "git"
    assert parsed.segments[0].arguments[:2] == ("--config-env", "token=TOKEN")


def test_parse_shell_command_normalizes_transparent_wrapper_once() -> None:
    parsed = parse_shell_command("bash -lc 'git clean -fdx'")

    assert parsed.normalized_text == "git clean -fdx"
    assert parsed.wrapper_chain == ("bash",)
    assert parsed.segments[0].executable == "git"
    assert parsed.segments[0].start == 0
    assert parsed.segments[0].end == len(parsed.normalized_text)


def test_parse_shell_command_marks_malformed_and_unsupported_input() -> None:
    malformed = parse_shell_command("git reset --hard 'unterminated")
    unsupported = parse_shell_command("Remove-Item -Force file.txt", dialect="powershell")

    assert malformed.confidence == "fallback"
    assert malformed.uncertainty_reason == "malformed_shell_quoting"
    assert unsupported.confidence == "uncertain"
    assert unsupported.uncertainty_reason == "unsupported_powershell_shell_string"
    assert unsupported.segments == ()


def test_parse_shell_command_marks_over_limit_input_uncertain() -> None:
    parsed = parse_shell_command("x" * (MAX_COMMAND_BYTES + 1))
    multibyte = parse_shell_command("é" * ((MAX_COMMAND_BYTES // 2) + 1))

    assert parsed.confidence == "uncertain"
    assert parsed.uncertainty_reason == "command_byte_limit_exceeded"
    assert parsed.segments == ()
    assert multibyte.confidence == "uncertain"
    assert multibyte.uncertainty_reason == "command_byte_limit_exceeded"


def test_executable_matcher_uses_structured_subcommands_and_flags() -> None:
    parsed = parse_shell_command("docker system prune --force && git status")
    matcher = ExecutableMatcher(
        executables=frozenset({"docker"}),
        subcommands=("system", "prune"),
        required_flags=frozenset({"--force"}),
    )

    evidence = matcher.match(parsed)

    assert len(evidence) == 1
    assert evidence[0].segment_index == 0
    assert evidence[0].executable == "docker"


def test_executable_matcher_normalizes_flag_value_and_windows_path_forms() -> None:
    parsed = parse_shell_command("'C:\\tools\\docker.exe' system prune --force=true")
    matcher = ExecutableMatcher(
        executables=frozenset({"docker.exe"}),
        subcommands=("system", "prune"),
        required_flags=frozenset({"--force"}),
    )

    assert matcher.match(parsed)


def test_executable_matcher_can_skip_declared_global_options() -> None:
    parsed = parse_shell_command("git --no-pager -C repo push origin main --force")
    matcher = ExecutableMatcher(
        executables=frozenset({"git"}),
        subcommands=("push",),
        required_flags=frozenset({"--force"}),
        allow_leading_options=True,
        leading_options_with_values=frozenset({"-c"}),
    )

    assert matcher.match(parsed)


def test_executable_matcher_does_not_treat_option_values_as_flags() -> None:
    parsed = parse_shell_command("git clean -e -f")
    matcher = ExecutableMatcher(
        executables=frozenset({"git"}),
        subcommands=("clean",),
        required_flags=frozenset({"-f"}),
        options_with_values=frozenset({"-e"}),
    )

    assert matcher.match(parsed) == ()


def test_matchers_honor_option_terminators() -> None:
    recursive_delete = ArgumentMatcher(
        executables=frozenset({"rm"}),
        required_arguments=frozenset({"-r"}),
    )
    force_push = ExecutableMatcher(
        executables=frozenset({"git"}),
        subcommands=("push",),
        required_flags=frozenset({"--force"}),
        allow_leading_options=True,
    )

    assert recursive_delete.match(parse_shell_command("rm -- -r")) == ()
    assert force_push.match(parse_shell_command("git push origin main -- --force")) == ()
    assert force_push.match(parse_shell_command("git -- push origin main --force"))


def test_parse_shell_command_preserves_literal_hash_arguments() -> None:
    parsed = parse_shell_command("printf '%s' value#fragment")

    assert parsed.segments[0].arguments == ("%s", "value#fragment")


def test_composite_matchers_have_explicit_any_and_all_semantics() -> None:
    parsed = parse_shell_command("docker system prune --force")
    docker = ExecutableMatcher(executables=frozenset({"docker"}))
    force = ExecutableMatcher(executables=frozenset({"docker"}), required_flags=frozenset({"--force"}))
    git = ExecutableMatcher(executables=frozenset({"git"}))

    assert AnyMatcher((git, docker)).match(parsed)
    assert AllMatcher((docker, force)).match(parsed)
    assert AllMatcher((docker, git)).match(parsed) == ()


def test_argument_and_pipeline_matchers_expand_short_flags_and_require_order() -> None:
    parsed = parse_shell_command("rm -rf ./build && base64 -d payload.txt | sh")
    recursive_delete = ArgumentMatcher(
        executables=frozenset({"rm"}),
        required_arguments=frozenset({"-r", "-f"}),
    )
    decode_and_execute = PipelineMatcher(
        producer=ArgumentMatcher(
            executables=frozenset({"base64"}),
            required_arguments=frozenset({"-d"}),
        ),
        consumer=ExecutableMatcher(executables=frozenset({"sh"})),
    )

    assert recursive_delete.match(parsed)
    assert len(decode_and_execute.match(parsed)) == 2
    assert decode_and_execute.match(parse_shell_command("sh | base64 -d")) == ()
    assert decode_and_execute.match(parse_shell_command("base64 -d payload.txt && sh script.sh")) == ()

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.launch_identity_binding import (
    LaunchBindingDimension,
    RuleVersionBinding,
    changed_launch_binding_dimensions,
    observe_launch_identity_binding,
)
from codex_plugin_scanner.guard.runtime.launch_identity_environment import (
    _script_command_payloads,
    _script_payload_has_list_operators,
    plan_launch_environment,
)

_ECHO = shutil.which("echo") or sys.executable
_SH = shutil.which("sh")
_RULES = (RuleVersionBinding("command.test.launch-environment", "1.0.0"),)


def test_env_ignore_environment_clears_inherited_values() -> None:
    inherited = {"PATH": "/inherited", "TOKEN": "private"}
    plan = plan_launch_environment(("env", "-i", "tool"), inherited)

    assert plan.complete
    assert plan.executable_environment == {}
    assert plan.wrapper_environments[0].environment == inherited


def test_env_ignore_environment_applies_following_assignments() -> None:
    plan = plan_launch_environment(
        ("env", "--ignore-environment", "PATH=/reviewed", "MODE=safe", "tool"),
        {"PATH": "/inherited", "TOKEN": "private"},
    )

    assert plan.complete
    assert plan.executable_environment == {"PATH": "/reviewed", "MODE": "safe"}


@pytest.mark.parametrize("unset_args", (("-u", "TOKEN"), ("--unset", "TOKEN"), ("--unset=TOKEN",)))
def test_env_unset_removes_inherited_value(unset_args: tuple[str, ...]) -> None:
    plan = plan_launch_environment(("env", *unset_args, "tool"), {"PATH": "/bin", "TOKEN": "private"})

    assert plan.complete
    assert plan.executable_environment == {"PATH": "/bin"}


@pytest.mark.parametrize("option", ("--bad", "-Z", "-S", "--debug"))
def test_unsupported_env_option_is_incomplete(option: str) -> None:
    plan = plan_launch_environment(("env", option, "tool"), {"PATH": "/bin"})

    assert not plan.complete


@pytest.mark.skipif(os.name == "nt", reason="the synthetic PATH launcher probe is POSIX-specific")
def test_cleared_environment_assignment_binds_actual_executable(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "tool"
    _ = executable.write_bytes(b"first")
    executable.chmod(0o755)
    command = parse_shell_command(
        f"env --ignore-environment PATH={bin_dir} tool",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    def observe():
        return observe_launch_identity_binding(
            command=command,
            workspace=tmp_path,
            repository=tmp_path,
            working_directory=tmp_path,
            policy_version="policy-v1",
            rules=_RULES,
            launch_env={"PATH": os.defpath, "TOKEN": "private"},
        )

    baseline = observe()
    _ = executable.write_bytes(b"second")
    changed = observe()
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(baseline, changed)
    assert not changed.can_issue_positive_proof


@pytest.mark.skipif(os.name == "nt", reason="the synthetic PATH launcher probe is POSIX-specific")
@pytest.mark.parametrize("prefix", ("env -i", "env PATH=/missing"))
def test_leading_env_wrapper_does_not_leak_into_shell_sibling(tmp_path: Path, prefix: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "tool"
    _ = executable.write_bytes(b"first")
    executable.chmod(0o755)
    command = parse_shell_command(
        f"{prefix} {_ECHO} first && tool",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    def observe():
        return observe_launch_identity_binding(
            command=command,
            workspace=tmp_path,
            repository=tmp_path,
            working_directory=tmp_path,
            policy_version="policy-v1",
            rules=_RULES,
            launch_env={"PATH": str(bin_dir)},
        )

    baseline = observe()
    assert baseline == observe()
    _ = executable.write_bytes(b"second")
    changed = observe()
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(baseline, changed)


@pytest.mark.skipif(_SH is None or os.name == "nt", reason="the shell-scope probe is POSIX-specific")
@pytest.mark.parametrize(
    "command_text",
    (
        "env -i {shell} -c '{echo} inside && tool'",
        "env -i {shell} -c '{echo} inside' && tool",
    ),
)
def test_normalized_multi_segment_shell_scope_is_nonreusable(tmp_path: Path, command_text: str) -> None:
    assert _SH is not None
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "tool"
    _ = executable.write_bytes(b"first")
    executable.chmod(0o755)
    command = parse_shell_command(
        command_text.format(shell=_SH, echo=_ECHO),
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    def observe():
        return observe_launch_identity_binding(
            command=command,
            workspace=tmp_path,
            repository=tmp_path,
            working_directory=tmp_path,
            policy_version="policy-v1",
            rules=_RULES,
            launch_env={"PATH": str(bin_dir)},
        )

    baseline = observe()
    repeated = observe()
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(baseline, repeated)
    assert not baseline.can_issue_positive_proof
    assert baseline.required_requirements == baseline.unresolved_requirements


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell path spellings")
@pytest.mark.parametrize(
    "shell_path,echo_path",
    (
        ("/bin/sh", "/bin/echo"),
        ("/usr/bin/sh", "/usr/bin/echo"),
    ),
)
@pytest.mark.parametrize("operator", ("&&", "||", ";", "|", "&"))
def test_script_scope_list_operators_are_nonreusable_across_path_spellings(
    tmp_path: Path,
    shell_path: str,
    echo_path: str,
    operator: str,
) -> None:
    """A -c payload with a list operator must be scope-ambiguous regardless of how the
    parser segments it: /usr/bin/sh spellings previously yielded one segment
    and silently lost the ambiguity nonce (CI flake on Ubuntu runners)."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    executable = bin_dir / "tool"
    _ = executable.write_bytes(b"first")
    executable.chmod(0o755)
    command = parse_shell_command(
        f"env -i {shell_path} -c '{echo_path} inside{operator}tool'",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    def observe():
        return observe_launch_identity_binding(
            command=command,
            workspace=tmp_path,
            repository=tmp_path,
            working_directory=tmp_path,
            policy_version="policy-v1",
            rules=_RULES,
            launch_env={"PATH": str(bin_dir)},
        )

    baseline = observe()
    repeated = observe()
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(baseline, repeated)
    assert not baseline.can_issue_positive_proof


def test_script_payload_scanner_ignores_non_list_operators() -> None:
    """The -c payload scanner must not flag payloads lacking list operators;
    overall non-reusability may still arise from wrapper-chain conservatism
    (e.g. env -i), which is out of scope for this unit."""

    assert _script_command_payloads(("env", "-i", "/usr/bin/sh", "-c", "echo inside")) == ("echo inside",)
    assert not any(
        _script_payload_has_list_operators(payload)
        for payload in _script_command_payloads(("env", "-i", "/usr/bin/sh", "-c", "echo inside"))
    )
    assert _script_command_payloads(("python", "-c", "print(1)")) == ()
    assert _script_command_payloads(("bash", "-lc", "echo one&&tool")) == ("echo one&&tool",)
    # Backward scan stops at list operators: the && belongs to the outer chain.
    assert _script_command_payloads(("sh", "-c", "echo one", "&&", "sh", "-c", "echo two")) == (
        "echo one",
        "echo two",
    )


@pytest.mark.parametrize("operator", ("&&", "||", ";", "|", "&"))
def test_script_payload_scanner_detects_adjacent_list_operators(operator: str) -> None:
    assert _script_payload_has_list_operators(f"echo one{operator}tool")


@pytest.mark.parametrize("separator", ("\n", "\r"))
def test_script_payload_scanner_detects_line_separators(separator: str) -> None:
    assert _script_payload_has_list_operators(f"echo one{separator}tool")


@pytest.mark.parametrize(
    "payload",
    (
        "echo 'one&&tool'",
        'echo "one|tool"',
        r"echo one\;tool",
    ),
)
def test_script_payload_scanner_preserves_quoted_and_escaped_literals(payload: str) -> None:
    assert not _script_payload_has_list_operators(payload)


@pytest.mark.parametrize("payload", ('echo "$(echo one&&tool)"', "echo `echo one`"))
def test_script_payload_scanner_rejects_dynamic_substitutions(payload: str) -> None:
    assert _script_payload_has_list_operators(payload)


def test_env_clear_command_remains_unproven(tmp_path: Path) -> None:
    command = parse_shell_command(f"env -i {_ECHO} baseline", cwd=tmp_path, home_dir=tmp_path)
    observation = observe_launch_identity_binding(
        command=command,
        workspace=tmp_path,
        repository=tmp_path,
        working_directory=tmp_path,
        policy_version="policy-v1",
        rules=_RULES,
        launch_env={"PATH": os.defpath, "TOKEN": "private"},
    )
    assert not observation.can_issue_positive_proof
    assert observation.required_requirements == observation.unresolved_requirements


def test_inconsistent_wrapper_evidence_is_nonreusable_instead_of_crashing(tmp_path: Path) -> None:
    parsed = parse_shell_command(f"{_ECHO} baseline", cwd=tmp_path, home_dir=tmp_path)
    forged_segment = replace(parsed.segments[0], wrapper_chain=("sudo",))
    forged = replace(parsed, segments=(forged_segment,), wrapper_chain=())

    def observe():
        return observe_launch_identity_binding(
            command=forged,
            workspace=tmp_path,
            repository=tmp_path,
            working_directory=tmp_path,
            policy_version="policy-v1",
            rules=_RULES,
        )

    first = observe()
    second = observe()
    assert LaunchBindingDimension.EXECUTABLE_OBSERVATION in changed_launch_binding_dimensions(first, second)
    assert not first.can_issue_positive_proof


def test_malformed_inherited_environment_is_incomplete_and_nonreusable(tmp_path: Path) -> None:
    malformed = cast(Mapping[str, str], cast(object, {"PATH": 7, 8: "invalid"}))
    command = parse_shell_command("echo baseline", cwd=tmp_path, home_dir=tmp_path)

    def observe():
        return observe_launch_identity_binding(
            command=command,
            workspace=tmp_path,
            repository=tmp_path,
            working_directory=tmp_path,
            policy_version="policy-v1",
            rules=_RULES,
            launch_env=malformed,
        )

    first = observe()
    second = observe()
    assert LaunchBindingDimension.LAUNCH_ENVIRONMENT_OBSERVATION in changed_launch_binding_dimensions(first, second)
    assert not first.can_issue_positive_proof

"""P24 regressions for semantic, fail-closed pytest configuration parsing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import pytest_config as pytest_config_module
from codex_plugin_scanner.guard.runtime.pytest_config import (
    MAX_PYTEST_CONFIG_FILE_BYTES,
    PYTEST_CONFIG_DECODE_ERROR,
    PYTEST_CONFIG_DUPLICATE_KEY,
    PYTEST_CONFIG_FILE_CHANGED,
    PYTEST_CONFIG_IO_ERROR,
    PYTEST_CONFIG_MISSING,
    PYTEST_CONFIG_NOT_REGULAR,
    PYTEST_CONFIG_OVERSIZE,
    PYTEST_CONFIG_SYMLINK,
    PYTEST_CONFIG_SYNTAX_ERROR,
    PYTEST_CONFIG_VALUE_TYPE_INVALID,
    parse_pytest_config,
)
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    _pytest_args_from_segment,
    build_tool_action_request_artifact,
    extract_sensitive_tool_action_request,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-p evil"\n'),
        ("pyproject.toml", '[tool.pytest.ini_options]\n"addopts" = "-p evil"\n'),
        ("pyproject.toml", 'tool.pytest.ini_options.addopts = "-p evil"\n'),
        ("pyproject.toml", '[tool.pytest]\naddopts = ["-p", "evil"]\n'),
        ("pytest.toml", '[pytest]\naddopts = ["-p", "evil"]\n'),
        (".pytest.toml", '[pytest]\naddopts = ["-p", "evil"]\n'),
        (".pytest.ini", "[pytest]\naddopts = -p evil\n"),
        ("setup.cfg", "[tool:pytest]\naddopts = -p evil\n"),
        ("tox.ini", "[pytest]\naddopts = -p evil\n"),
    ),
)
def test_semantic_pytest_config_blocks_plugin_loading(tmp_path: Path, path: str, content: str) -> None:
    _write(tmp_path / path, content)

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"


def test_setup_cfg_ignores_addopts_outside_tool_pytest_section(tmp_path: Path) -> None:
    _write(tmp_path / "setup.cfg", "[metadata]\naddopts = -p unrelated\n[tool:pytest]\naddopts = -q\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "pytest repository-code execution"


def test_malformed_pytest_config_fails_closed(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", "[tool.pytest.ini_options\naddopts = '-q'\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"
    assert match.pytest_config_reason_codes == (PYTEST_CONFIG_SYNTAX_ERROR,)


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("pytest.ini", "[pytest]\naddopts =\n  -q\n  -p evil\n"),
        ("tox.ini", "[pytest]\naddopts = -pno:cacheprovider\n"),
        ("pytest.ini", "[pytest]\naddopts = --override-ini log_file=pytest.log\n"),
        ("pytest.ini", "[pytest]\naddopts = -o pythonpath=../outside\n"),
        ("pytest.ini", "[pytest]\naddopts = --rootdir ../outside\n"),
        ("pytest.ini", "[pytest]\naddopts = --confcutdir ../outside\n"),
        ("setup.cfg", "[tool:pytest]\nlog_file = pytest.log\n"),
        (
            "pyproject.toml",
            '[tool."pytest".ini_options]\naddopts = """\n-q\n-p evil\n"""\n',
        ),
        (
            "pyproject.toml",
            "[tool.pytest.ini_options]\naddopts = '''\n-q\n-p evil\n'''\n",
        ),
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = ["-q", "-c", "other.ini"]\n'),
    ),
)
def test_parser_handles_format_specific_multiline_and_option_forms(
    tmp_path: Path,
    path: str,
    content: str,
) -> None:
    _write(tmp_path / path, content)

    result = parse_pytest_config(tmp_path, path)

    assert result.complete is True
    assert result.value is not None
    assert result.value.unsafe is True
    assert result.content_sha256 is not None


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("pytest.ini", "[pytest]\naddopts = -q\naddopts = -v\n"),
        ("setup.cfg", "[tool:pytest]\naddopts = -q\n[tool:pytest]\naddopts = -v\n"),
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\naddopts = "-v"\n'),
    ),
)
def test_duplicate_config_keys_fail_closed(tmp_path: Path, path: str, content: str) -> None:
    _write(tmp_path / path, content)

    result = parse_pytest_config(tmp_path, path)

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_DUPLICATE_KEY


def test_wrong_pyproject_value_type_fails_closed(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", "[tool.pytest.ini_options]\naddopts = 7\n")

    result = parse_pytest_config(tmp_path, "pyproject.toml")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_VALUE_TYPE_INVALID


def test_toml_option_names_remain_case_sensitive(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", '[tool.pytest.ini_options]\n"ADDOPTS" = "-p evil"\n')

    result = parse_pytest_config(tmp_path, "pyproject.toml")

    assert result.complete is True
    assert result.value is not None
    assert result.value.unsafe is False


def test_native_toml_scalar_options_do_not_make_inventory_incomplete(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", "[tool.pytest]\nxfail_strict = true\nverbosity_test_cases = 2\n")

    result = parse_pytest_config(tmp_path, "pyproject.toml")

    assert result.complete is True
    assert result.value is not None
    assert result.value.unsafe is False


def test_first_applicable_config_wins_without_inspecting_lower_precedence_files(tmp_path: Path) -> None:
    _write(tmp_path / "pytest.ini", "[pytest]\naddopts = -q\n")
    _write(tmp_path / "tox.ini", "[pytest\naddopts = -p ignored\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "pytest repository-code execution"
    assert match.pytest_config_sources == ("pytest.ini",)


def test_selected_test_root_config_precedes_invocation_directory_config(tmp_path: Path) -> None:
    _write(tmp_path / "pytest.ini", "[pytest]\naddopts = -q\n")
    _write(tmp_path / "sub" / "pytest.ini", "[pytest]\naddopts = -p evil\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest sub -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"
    assert match.pytest_config_sources == ("sub/pytest.ini",)


def test_multiple_test_roots_search_from_their_common_ancestor(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "pytest.ini", "[pytest]\naddopts = -p evil\n")
    _write(tmp_path / "tests" / "a" / "pytest.ini", "[pytest]\naddopts = -q\n")
    (tmp_path / "tests" / "b").mkdir(parents=True)

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests/a tests/b -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"
    assert match.pytest_config_sources == ("tests/pytest.ini",)


def test_selected_test_file_searches_for_config_from_parent_directory(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_sample.py", "def test_sample():\n    pass\n")
    _write(tmp_path / "tests" / "pytest.ini", "[pytest]\naddopts = -p evil\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests/test_sample.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"
    assert match.pytest_config_sources == ("tests/pytest.ini",)


def test_selected_test_file_without_config_does_not_fail_as_not_a_directory(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_sample.py", "def test_sample():\n    pass\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests/test_sample.py -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "pytest repository-code execution"
    assert match.pytest_config_sources == ()


@pytest.mark.parametrize(
    "command",
    (
        "uv run pytest -c selected.ini -q",
        "poetry run pytest --config-file=selected.ini -q",
    ),
)
def test_pytest_runner_preserves_explicit_config_arguments(tmp_path: Path, command: str) -> None:
    _write(tmp_path / "pytest.ini", "[pytest]\naddopts = -q\n")
    _write(tmp_path / "selected.ini", "[pytest]\naddopts = -p evil\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": command}, cwd=tmp_path)
    direct_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest -c selected.ini -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert direct_match is not None
    assert match.action_class == "pytest repository-code execution"
    assert match.pytest_config_sources == ("selected.ini",)
    assert match.pytest_config_identity_sha256 == direct_match.pytest_config_identity_sha256


def test_pytest_runner_skips_option_values_before_wrapped_command(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "pytest.ini", "[pytest]\npythonpath = helper_path\n")

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "uv run --with pytest pytest tests -q"},
        cwd=tmp_path,
    )
    direct_match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest tests -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert direct_match is not None
    assert match.pytest_config_sources == ("tests/pytest.ini",)
    assert match.pytest_config_identity_sha256 == direct_match.pytest_config_identity_sha256


def test_pytest_runner_does_not_treat_dependency_or_payload_argument_as_executable() -> None:
    assert _pytest_args_from_segment(
        ["uv", "run", "--with", "pytest", "echo", "pytest", "tests"],
        0,
    ) is None


def test_non_applicable_pyproject_does_not_hide_later_tox_config(tmp_path: Path) -> None:
    _write(tmp_path / "pyproject.toml", '[build-system]\nrequires = ["fixture"]\n')
    _write(tmp_path / "tox.ini", "[pytest]\naddopts = -p evil\n")

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "destructive shell command"
    assert match.pytest_config_sources == ("tox.ini",)


def test_oversized_pytest_config_fails_closed_without_partial_parse(tmp_path: Path) -> None:
    _write(
        tmp_path / "pytest.ini",
        "[pytest]\naddopts = -q\n" + ("# padding\n" * (MAX_PYTEST_CONFIG_FILE_BYTES // 5)),
    )

    result = parse_pytest_config(tmp_path, "pytest.ini")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_OVERSIZE
    assert result.content_sha256 is None


def test_pytest_config_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "real.ini"
    _write(target, "[pytest]\naddopts = -q\n")
    (tmp_path / "pytest.ini").symlink_to(target)

    result = parse_pytest_config(tmp_path, "pytest.ini")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_SYMLINK


def test_pytest_config_directory_is_not_treated_as_missing(tmp_path: Path) -> None:
    (tmp_path / "pytest.ini").mkdir()

    result = parse_pytest_config(tmp_path, "pytest.ini")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_NOT_REGULAR


def test_unreadable_pytest_config_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "pytest.ini"
    _write(config_path, "[pytest]\naddopts = -q\n")

    def denied_open(_path: object, _flags: int) -> int:
        raise PermissionError("fixture denies the config read")

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.pytest_config.os.open", denied_open)

    result = parse_pytest_config(tmp_path, "pytest.ini")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_IO_ERROR


def test_non_utf8_pytest_config_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "pytest.ini").write_bytes(b"[pytest]\naddopts = \xff\n")

    result = parse_pytest_config(tmp_path, "pytest.ini")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_DECODE_ERROR


def test_pytest_config_changed_during_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "pytest.ini"
    _write(config_path, "[pytest]\naddopts = -q\n")
    original_fstat = pytest_config_module.os.fstat
    calls = 0

    def racing_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 2:
            _write(config_path, "[pytest]\naddopts = -v\n")
        return original_fstat(descriptor)

    monkeypatch.setattr(pytest_config_module.os, "fstat", racing_fstat)

    result = parse_pytest_config(tmp_path, "pytest.ini")

    assert result.complete is False
    assert result.reason_code == PYTEST_CONFIG_FILE_CHANGED


def test_config_content_hash_changes_pytest_approval_identity(tmp_path: Path) -> None:
    config_path = tmp_path / "pyproject.toml"
    _write(config_path, '[tool.pytest.ini_options]\naddopts = "-q"\n')
    first_match = extract_sensitive_tool_action_request("Bash", {"command": "pytest tests -q"}, cwd=tmp_path)
    assert first_match is not None
    first_artifact = build_tool_action_request_artifact(
        "codex",
        first_match,
        config_path=str(config_path),
        source_scope="project",
    )

    _write(config_path, '[tool.pytest.ini_options]\naddopts = "-v"\n')
    second_match = extract_sensitive_tool_action_request("Bash", {"command": "pytest tests -q"}, cwd=tmp_path)
    assert second_match is not None
    second_artifact = build_tool_action_request_artifact(
        "codex",
        second_match,
        config_path=str(config_path),
        source_scope="project",
    )

    assert first_match.action_class == "pytest repository-code execution"
    assert second_match.action_class == "pytest repository-code execution"
    assert first_match.pytest_config_identity_sha256 != second_match.pytest_config_identity_sha256
    assert first_artifact.artifact_id != second_artifact.artifact_id
    assert first_artifact.metadata["pytest_config_sources"] == ["pyproject.toml"]


@pytest.mark.parametrize(
    ("path", "content"),
    (
        ("pytest.ini", "[pytest]\naddopts = -q\n"),
        ("tox.ini", "[pytest]\naddopts = -q\n"),
        ("setup.cfg", "[tool:pytest]\naddopts = -q\n"),
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n'),
    ),
)
def test_safe_config_remains_in_prompt_free_restricted_profile(tmp_path: Path, path: str, content: str) -> None:
    _write(tmp_path / path, content)

    match = extract_sensitive_tool_action_request("Bash", {"command": "pytest -q"}, cwd=tmp_path)

    assert match is not None
    assert match.action_class == "pytest repository-code execution"
    assert match.guard_default_action == "sandbox-required"
    assert match.pytest_config_reason_codes == ()


@pytest.mark.parametrize(
    "config_flag",
    ("-c selected.ini", "-cselected.ini", "--config-file=selected.ini", "-c selected.toml"),
)
def test_explicit_config_is_parsed_and_bound_to_identity(tmp_path: Path, config_flag: str) -> None:
    _write(tmp_path / "selected.ini", "[pytest]\naddopts = -p evil\n")
    _write(tmp_path / "selected.toml", '[tool.pytest.ini_options]\n"addopts" = "-p evil"\n')

    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": f"python -m pytest {config_flag} -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"
    expected_source = "selected.toml" if "selected.toml" in config_flag else "selected.ini"
    assert match.pytest_config_sources == (expected_source,)
    assert match.pytest_config_identity_sha256 is not None


def test_missing_explicit_config_fails_closed_with_stable_reason(tmp_path: Path) -> None:
    match = extract_sensitive_tool_action_request(
        "Bash",
        {"command": "pytest -c missing.ini -q"},
        cwd=tmp_path,
    )

    assert match is not None
    assert match.action_class == "destructive shell command"
    assert match.pytest_config_sources == ("missing.ini",)
    assert match.pytest_config_reason_codes == (PYTEST_CONFIG_MISSING,)
    assert "repair or remove malformed" in match.reason

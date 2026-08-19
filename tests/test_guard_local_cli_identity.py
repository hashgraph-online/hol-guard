from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.custom_extension_suggestion import is_suggestable_custom_tool
from codex_plugin_scanner.guard.runtime.local_cli_identity import (
    catalog_owned_executables,
    identify_unlisted_cli,
    is_local_cli_id,
    recognize_operator_cli,
)


def test_catalog_owns_git_and_not_arbitrary_binaries() -> None:
    owned = catalog_owned_executables()
    assert "git" in owned
    assert "cwv.py" not in owned


def test_python_script_is_an_unlisted_cli(tmp_path: Path) -> None:
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(
        f"python3 {script} --by url --days 7",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert identity is not None
    assert identity.kind == "script"
    assert identity.name == "cwv.py"
    assert identity.example_label == "python3 cwv.py"
    assert is_local_cli_id(identity.cli_id)
    again = identify_unlisted_cli(
        f"python3 {script} --by deviceType",
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert again is not None
    assert again.cli_id == identity.cli_id
    assert again.identity_hash == identity.identity_hash


def test_script_content_change_changes_identity(tmp_path: Path) -> None:
    script = tmp_path / "cwv.py"
    script.write_text("print('one')\n", encoding="utf-8")
    first = identify_unlisted_cli(f"python3 {script}", cwd=tmp_path, home_dir=tmp_path)
    assert first is not None
    script.write_text("print('two')\n", encoding="utf-8")
    second = identify_unlisted_cli(f"python3 {script}", cwd=tmp_path, home_dir=tmp_path)
    assert second is not None
    assert second.cli_id == first.cli_id
    assert second.identity_hash != first.identity_hash


def test_catalog_git_is_not_unlisted(tmp_path: Path) -> None:
    assert identify_unlisted_cli("git status", cwd=tmp_path, home_dir=tmp_path) is None


def test_bare_python_is_not_unlisted(tmp_path: Path) -> None:
    assert identify_unlisted_cli("python3", cwd=tmp_path, home_dir=tmp_path) is None


def test_compound_command_is_not_unlisted(tmp_path: Path) -> None:
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    assert identify_unlisted_cli(f"python3 {script} && echo done", cwd=tmp_path, home_dir=tmp_path) is None


def test_common_shell_utilities_are_not_unlisted(tmp_path: Path) -> None:
    for command in ("ls -la", "grep foo", "echo hi", "rg foo", "whoami", "script"):
        assert identify_unlisted_cli(command, cwd=tmp_path, home_dir=tmp_path) is None


def test_recognize_script_path_and_reject_grep(tmp_path: Path) -> None:
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity, code, _message = recognize_operator_cli(str(script), cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    assert identity.name == "cwv.py"
    assert code == ""
    rejected, reject_code, reject_message = recognize_operator_cli("grep foo", cwd=tmp_path, home_dir=tmp_path)
    assert rejected is None
    assert reject_code == "common_shell_utility"
    assert "grep" in reject_message
    assert is_suggestable_custom_tool(name="cwv.py", kind="script")
    assert not is_suggestable_custom_tool(name="ls", kind="executable")
    for junk in ("rg", "whoami", "script"):
        rejected_junk, junk_code, junk_message = recognize_operator_cli(
            junk,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        assert rejected_junk is None
        assert junk_code == "common_shell_utility"
        assert junk in junk_message
        assert "custom extension" in junk_message


def test_recognize_script_path_with_spaces(tmp_path: Path) -> None:
    tools_dir = tmp_path / "my tools"
    tools_dir.mkdir()
    script = tools_dir / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity, code, message = recognize_operator_cli(str(script), cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    assert identity.name == "cwv.py"
    assert identity.kind == "script"
    assert code == ""
    assert message == ""


def test_recognize_binary_path_with_spaces(tmp_path: Path) -> None:
    tools_dir = tmp_path / "my tools"
    tools_dir.mkdir()
    tool = tools_dir / "internal-deploy"
    tool.write_text("#!/bin/sh\necho deploy\n", encoding="utf-8")
    tool.chmod(0o755)
    identity, code, message = recognize_operator_cli(str(tool), cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    assert identity.name == "internal-deploy"
    assert identity.kind == "executable"
    assert code == ""
    assert message == ""


def test_standalone_binary_is_unlisted(tmp_path: Path) -> None:
    tool = tmp_path / "internal-deploy"
    tool.write_text("#!/bin/sh\necho deploy\n", encoding="utf-8")
    tool.chmod(0o755)
    identity = identify_unlisted_cli(str(tool) + " status", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    assert identity.kind == "executable"
    assert identity.name == "internal-deploy"
    assert identity.example_label == "internal-deploy"

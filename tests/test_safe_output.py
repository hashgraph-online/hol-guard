from pathlib import Path

from codex_plugin_scanner.action_runner import _write_outputs
from codex_plugin_scanner.safe_output import write_text_atomic_no_follow


def test_atomic_output_replaces_symlink_without_overwriting_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    output = tmp_path / "report.json"
    output.symlink_to(outside)

    write_text_atomic_no_follow(output, "safe")

    assert outside.read_text(encoding="utf-8") == "preserve"
    assert output.is_symlink() is False
    assert output.read_text(encoding="utf-8") == "safe"


def test_atomic_output_rejects_absolute_symlinked_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(outside, target_is_directory=True)

    try:
        write_text_atomic_no_follow(linked_parent / "report.json", "unsafe")
    except OSError as error:
        assert "symlinked output directory" in str(error)
    else:
        raise AssertionError("absolute symlinked output parent was accepted")

    assert not (outside / "report.json").exists()


def test_github_outputs_use_multiline_protocol_for_untrusted_newlines(tmp_path: Path) -> None:
    output = tmp_path / "github-output.txt"

    _write_outputs(str(output), {"report_path": "report.json\npolicy_pass=false"})

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("report_path<<HOL_GUARD_")
    assert lines[1:3] == ["report.json", "policy_pass=false"]
    assert lines[-1] == lines[0].split("<<", 1)[1]

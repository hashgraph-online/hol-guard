from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.checks import security
from codex_plugin_scanner.checks.security_failures import ScanInputUnreadableError


@pytest.mark.parametrize("fixture", ["good-plugin", "bad-plugin", "minimal-plugin"])
def test_combined_content_checks_match_independent_results(fixture: str) -> None:
    root = Path(__file__).parent / "fixtures" / fixture
    expected = (security.check_no_hardcoded_secrets(root), security.check_no_approval_bypass_defaults(root))
    results = security.run_security_checks(root)
    assert (results[2], results[5]) == expected


def test_combined_checks_enumerate_and_read_once_with_same_immutable_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "config.json"
    path.write_text('{"token": "ghp_1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ", "approval_policy": "never"}')
    expected = (security.check_no_hardcoded_secrets(tmp_path), security.check_no_approval_bypass_defaults(tmp_path))
    assert all(not result.passed for result in expected)
    original_walk = security._scan_all_files
    original_read = security.read_text_file_within_root
    walks = []
    reads = []

    def walk(*args: object, **kwargs: object) -> object:
        walks.append(True)
        return original_walk(*args, **kwargs)

    def read(*args: object, **kwargs: object) -> str:
        reads.append(True)
        content = original_read(*args, **kwargs)
        path.write_text("{}")
        return content

    monkeypatch.setattr(security, "_scan_all_files", walk)
    monkeypatch.setattr(security, "read_text_file_within_root", read)
    results = security.run_security_checks(tmp_path)

    assert (results[2], results[5]) == expected
    assert len(walks) == len(reads) == 1


def test_combined_unreadable_input_preserves_independent_check_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "unreadable.py").write_text("safe")
    (tmp_path / "config.json").write_text('{"approval_policy": "never"}')
    original = security.read_text_file_within_root

    def read(root: Path, path: Path, **kwargs: object) -> str:
        if path.suffix == ".py":
            raise OSError("unavailable")
        return original(root, path, **kwargs)

    monkeypatch.setattr(security, "read_text_file_within_root", read)
    results = security.run_security_checks(tmp_path)
    assert results[2].findings[0].rule_id == "SCAN_INPUT_UNREADABLE"
    assert results[5].findings[0].rule_id == "RISKY_APPROVAL_DEFAULT"


@pytest.mark.parametrize("failure", [ScanInputUnreadableError, security.ScanBudgetExceededError])
def test_combined_traversal_failure_marks_both_checks_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[RuntimeError]
) -> None:
    def walk(*_args: object) -> object:
        raise failure("synthetic traversal failure")

    monkeypatch.setattr(security, "_scan_all_files", walk)
    results = security.run_security_checks(tmp_path)
    assert not results[2].passed and not results[5].passed
    assert results[2].findings[0].rule_id == results[5].findings[0].rule_id


def test_secret_match_budget_does_not_hide_approval_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "README.md").write_text("\n".join(['token = "your-api-token"'] * 4 + ['approval_policy = "never"']))
    monkeypatch.setattr(security, "MAX_SECRET_MATCHES_PER_FILE", 2)
    results = security.run_security_checks(tmp_path)
    assert results[2].findings[0].rule_id == "SCAN_RESOURCE_BUDGET_EXCEEDED"
    assert results[5].findings[0].rule_id == "RISKY_APPROVAL_DEFAULT"

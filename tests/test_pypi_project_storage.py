from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "pypi_project_storage.py"
SPEC = importlib.util.spec_from_file_location("pypi_project_storage", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
pypi_project_storage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pypi_project_storage
SPEC.loader.exec_module(pypi_project_storage)


@pytest.fixture(autouse=True)
def _isolate_actions_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv(pypi_project_storage.LIMIT_ENV, raising=False)


def test_reclaimable_extras_keep_pure_wheels() -> None:
    payload = {
        "releases": {
            "3.0.0a10": [
                {"filename": "hol_guard-3.0.0a10-py3-none-any.whl", "size": 10},
                {"filename": "hol_guard-3.0.0a10.tar.gz", "size": 20},
                {"filename": "hol_guard-3.0.0a10-py3-none-macosx_11_0_arm64.whl", "size": 30},
            ],
            "2.2.107": [
                {"filename": "hol_guard-2.2.107.tar.gz", "size": 99},
            ],
        }
    }

    extras = pypi_project_storage.reclaimable_extras(payload)

    assert extras == [
        ("3.0.0a10", "hol_guard-3.0.0a10-py3-none-macosx_11_0_arm64.whl", 30),
        ("3.0.0a10", "hol_guard-3.0.0a10.tar.gz", 20),
    ]
    assert pypi_project_storage.project_size_bytes(payload) == 159


def test_storage_report_fails_when_over_limit(tmp_path: Path) -> None:
    payload_path = tmp_path / "pypi.json"
    payload_path.write_text(
        json.dumps(
            {
                "releases": {
                    "3.0.0a10": [
                        {
                            "filename": "hol_guard-3.0.0a10.tar.gz",
                            "size": pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    assert pypi_project_storage.main(["--payload", str(payload_path)]) == 0
    assert pypi_project_storage.main(["--payload", str(payload_path), "--fail-if-over-limit"]) == 1


def test_storage_limit_uses_binary_gib_and_rejects_exact_boundary() -> None:
    limit = 10 * 1024**3

    assert limit == pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES
    assert pypi_project_storage.over_project_limit(limit - 1, 1) is True
    assert pypi_project_storage.over_project_limit(limit - 2, 1) is False


def test_pending_upload_near_decimal_limit_fits_binary_limit() -> None:
    used_bytes = 9_964_936_050
    pending_bytes = 38_802_982

    assert used_bytes + pending_bytes == 10_003_739_032
    assert pypi_project_storage.over_project_limit(used_bytes, pending_bytes) is False


def test_over_limit_without_reclaimable_files_has_safe_message(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload_path = tmp_path / "pypi.json"
    payload_path.write_text(
        json.dumps(
            {
                "releases": {
                    "3.0.6": [
                        {
                            "filename": "hol_guard-3.0.6.tar.gz",
                            "size": pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    assert pypi_project_storage.main(["--payload", str(payload_path), "--fail-if-over-limit"]) == 1
    error = capsys.readouterr().err
    assert "at or over the 10 GiB project limit" in error
    assert "No reclaimable 3.0.0a native wheels or sdists were found" in error
    assert "Remove old" not in error


def test_storage_report_counts_pending_upload_bytes(tmp_path: Path) -> None:
    payload_path = tmp_path / "pypi.json"
    payload_path.write_text(
        json.dumps({"releases": {"3.0.6": [{"filename": "hol_guard-3.0.6.tar.gz", "size": 10}]}}),
        encoding="utf-8",
    )
    pending = tmp_path / "dist-hol-guard"
    pending.mkdir()
    (pending / "hol_guard-3.0.7.tar.gz").write_bytes(b"x" * 20)

    assert pypi_project_storage.pending_dir_size_bytes(pending) == 20
    assert pypi_project_storage.over_project_limit(10, 20) is False
    assert (
        pypi_project_storage.main(
            ["--payload", str(payload_path), "--fail-if-over-limit", "--pending-dir", str(pending)]
        )
        == 0
    )

    tight = tmp_path / "tight.json"
    tight.write_text(
        json.dumps(
            {
                "releases": {
                    "3.0.6": [
                        {
                            "filename": "hol_guard-3.0.6.tar.gz",
                            "size": pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES - 5,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    assert (
        pypi_project_storage.main(["--payload", str(tight), "--fail-if-over-limit", "--pending-dir", str(pending)]) == 1
    )


def test_already_current_message_explains_unpublished_reserved_alpha() -> None:
    from codex_plugin_scanner.guard.cli.update_commands import (
        already_current_update_message,
        select_reserved_alpha_version,
    )

    assert already_current_update_message(None) == "HOL Guard is already current."
    assert already_current_update_message(
        {
            "latest_version": "3.0.0a171",
            "reserved_alpha_version": "3.0.0a184",
        }
    ) == (
        "HOL Guard is already current on PyPI (3.0.0a171). "
        "GitHub reserved 3.0.0a184, but that alpha is not published yet."
    )
    refs = [
        {"ref": "refs/tags/alpha/v3.0.0a171"},
        {"ref": "refs/tags/alpha/v3.0.0a184"},
        {"ref": "refs/tags/alpha/v3.1.0a13"},
    ]
    assert select_reserved_alpha_version(refs, latest_pypi="3.0.0a171") == "3.0.0a184"
    assert select_reserved_alpha_version(refs, latest_pypi="3.0.0a184") is None


def _release_file(size: int, uploaded: datetime) -> dict[str, object]:
    return {
        "filename": "hol_guard-3.38.0.tar.gz",
        "size": size,
        "upload_time_iso_8601": uploaded.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def test_growth_rate_counts_only_trailing_window() -> None:
    now = datetime(2026, 10, 9, tzinfo=timezone.utc)
    payload = {
        "releases": {
            "3.38.0": [_release_file(14 * 100, now - timedelta(days=1))],
            "3.0.1": [_release_file(10**9, now - timedelta(days=30))],
            "3.0.0": [{"filename": "hol_guard-3.0.0.tar.gz", "size": 10**9}],
        }
    }

    assert pypi_project_storage.recent_growth_bytes_per_day(payload, now) == 100


def test_outlook_warns_on_usage_ratio_or_short_runway() -> None:
    limit = 1000

    quiet = pypi_project_storage.quota_outlook(500, limit, growth_bytes_per_day=10)
    assert quiet["near_limit"] is False
    assert quiet["days_until_full"] == 50.0

    full = pypi_project_storage.quota_outlook(800, limit, growth_bytes_per_day=0)
    assert full["near_limit"] is True
    assert full["days_until_full"] is None
    assert full["near_limit_reasons"] == ["usage is 80% of the project limit"]

    runway = pypi_project_storage.quota_outlook(500, limit, growth_bytes_per_day=25)
    assert runway["near_limit"] is True
    assert runway["near_limit_reasons"] == ["about 20 days until full at the 14-day upload rate"]


def test_near_limit_report_annotates_actions_without_touching_stdout_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.delenv(pypi_project_storage.LIMIT_ENV, raising=False)
    payload_path = tmp_path / "pypi.json"
    used = int(pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES * 0.9)
    payload_path.write_text(
        json.dumps({"releases": {"3.0.6": [{"filename": "hol_guard-3.0.6.tar.gz", "size": used}]}}),
        encoding="utf-8",
    )

    assert pypi_project_storage.main(["--payload", str(payload_path), "--fail-if-over-limit"]) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["near_limit"] is True
    assert report["over_limit"] is False
    assert "::warning title=PyPI project quota::" in captured.err
    assert "usage is 90% of the project limit" in summary.read_text(encoding="utf-8")


def test_configured_limit_overrides_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    payload_path = tmp_path / "pypi.json"
    payload_path.write_text(
        json.dumps(
            {
                "releases": {
                    "3.0.6": [
                        {"filename": "hol_guard-3.0.6.tar.gz", "size": pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES}
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    raised = str(20 * 1024**3)

    monkeypatch.setenv(pypi_project_storage.LIMIT_ENV, raised)
    assert pypi_project_storage.main(["--payload", str(payload_path), "--fail-if-over-limit"]) == 0
    assert json.loads(capsys.readouterr().out)["limit_bytes"] == int(raised)

    monkeypatch.setenv(pypi_project_storage.LIMIT_ENV, "")
    assert pypi_project_storage.main(["--payload", str(payload_path), "--fail-if-over-limit"]) == 1
    capsys.readouterr()

    assert pypi_project_storage.main(["--payload", str(payload_path), "--limit-bytes", "0"]) == 1
    assert "positive integer" in capsys.readouterr().err


def test_outlook_thresholds_use_unrounded_values() -> None:
    limit = 100_000
    just_under_runway = pypi_project_storage.quota_outlook(50_000, limit, growth_bytes_per_day=2_386)
    assert just_under_runway["days_until_full"] == 21.0
    assert just_under_runway["near_limit"] is True

    just_under_ratio = pypi_project_storage.quota_outlook(79_996, limit, growth_bytes_per_day=0)
    assert just_under_ratio["near_limit"] is False


def test_pending_upload_crossing_warning_threshold_warns(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    payload = tmp_path / "pypi.json"
    payload.write_text(
        json.dumps({"releases": {"1.0.0": [{"filename": "a.whl", "size": 790}]}}),
        encoding="utf-8",
    )
    pending = tmp_path / "dist"
    pending.mkdir()
    (pending / "b.whl").write_bytes(b"x" * 20)

    args = ["--payload", str(payload), "--pending-dir", str(pending), "--limit-bytes", "1000"]
    assert pypi_project_storage.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["used_bytes"] == 790
    assert report["near_limit"] is True


def test_unwritable_step_summary_keeps_quota_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "missing" / "summary.md"))
    payload = tmp_path / "pypi.json"
    limit = pypi_project_storage.PYPI_PROJECT_LIMIT_BYTES
    payload.write_text(
        json.dumps({"releases": {"1.0.0": [{"filename": "a.whl", "size": int(limit * 0.9)}]}}),
        encoding="utf-8",
    )

    assert pypi_project_storage.main(["--payload", str(payload), "--fail-if-over-limit"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["over_limit"] is False
    assert "Could not write the PyPI quota warning" in captured.err

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "pypi_project_storage.py"
SPEC = importlib.util.spec_from_file_location("pypi_project_storage", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
pypi_project_storage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pypi_project_storage
SPEC.loader.exec_module(pypi_project_storage)


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
        pypi_project_storage.main(
            ["--payload", str(tight), "--fail-if-over-limit", "--pending-dir", str(pending)]
        )
        == 1
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

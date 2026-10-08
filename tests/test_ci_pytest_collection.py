"""Collection keeps pytest selection and import assertions without rewriting tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _collect(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, sys; from pathlib import Path; "
            "from scripts.ci.pytest_shard import discover_test_nodes; "
            "print(json.dumps(discover_test_nodes(Path(sys.argv[1]))))",
            str(root),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_collection_preserves_pytest_filename_and_marker_policy(tmp_path: Path) -> None:
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = spec_*.py\naddopts = -m selected\nmarkers =\n    selected\n",
        encoding="utf-8",
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "spec_collection.py").write_text(
        "import pytest\n"
        "@pytest.mark.parametrize('value', [\n"
        "    pytest.param('kept', marks=pytest.mark.selected), 'filtered'\n"
        "])\n"
        "def test_parameter(value):\n"
        "    assert value\n",
        encoding="utf-8",
    )
    (tests / "test_not_selected_by_filename.py").write_text(
        "raise AssertionError('filename policy was bypassed')\n", encoding="utf-8"
    )

    result = _collect(tmp_path)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == ["tests/spec_collection.py::test_parameter[kept]"]


def test_collection_still_fails_on_import_time_assertions(tmp_path: Path) -> None:
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_broken.py").write_text(
        "assert False, 'collection must execute Python assertions'\ndef test_unreachable():\n    pass\n",
        encoding="utf-8",
    )

    result = _collect(tmp_path)

    assert result.returncode != 0
    assert "pytest collection failed" in result.stderr

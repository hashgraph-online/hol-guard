from __future__ import annotations

import hashlib
from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts.ci import python_runtime_retirement as retirement


@pytest.fixture
def retired_records(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        {
            "path": "src/deleted.py",
            "module": "deleted",
            "forbidden_symbols": ["deleted_implementation"],
            "source_sha256": hashlib.sha256(b"old implementation").hexdigest(),
        }
    ]
    monkeypatch.setattr(retirement, "_records", lambda _contract: records)


def test_valid_artifact_is_streamed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired_records: None
) -> None:
    wheel = tmp_path / "clean.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("active.py", "value = 42\n")
    calls: list[Path] = []
    original = retirement._artifact_members

    def members(path: Path):
        calls.append(path)
        yield from original(path)

    monkeypatch.setattr(retirement, "_artifact_members", members)
    retirement.validate_retired_artifacts({}, [wheel])
    assert calls == [wheel]


@pytest.mark.parametrize(
    "name,content",
    [
        ("deleted.py", ""),
        ("__pycache__/deleted.cpython-312.pyc", ""),
        ("renamed.py", "old implementation"),
        ("renamed.py", "import deleted\n"),
        ("renamed.py", "def deleted_implementation(): pass\n"),
    ],
)
def test_preflight_keeps_path_digest_import_and_symbol_checks(
    tmp_path: Path, retired_records: None, name: str, content: str
) -> None:
    wheel = tmp_path / "invalid.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr(name, content)
    with pytest.raises(RuntimeError):
        retirement.validate_retired_artifacts({}, [wheel])

from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest

from scripts.ci.python_capability_cleanup_analysis import _analyze_import_graph
from scripts.ci.python_runtime_retirement import validate_retired_modules


@pytest.fixture
def retired_repository(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    (tmp_path / "src/example").mkdir(parents=True)
    (tmp_path / "rust/src").mkdir(parents=True)
    (tmp_path / "rust/src/native.rs").write_text("// Native implementation fixture.\n", encoding="utf-8")
    contract: dict[str, object] = {
        "retired_modules": [
            {
                "path": "src/example/old_runtime.py",
                "module": "example.old_runtime",
                "source_sha256": hashlib.sha256(b"class OldRuntime:\n    pass\n").hexdigest(),
                "forbidden_symbols": ["OldRuntime"],
                "native_replacements": ["rust/src/native.rs"],
            }
        ],
        "retired_test_paths": ["tests/test_old_runtime.py"],
    }
    return tmp_path, contract


def check(repository: tuple[Path, dict[str, object]], artifacts: tuple[Path, ...] = ()) -> list[dict[str, object]]:
    root, contract = repository
    return validate_retired_modules(root, contract, analysis=_analyze_import_graph(root), artifacts=artifacts)


def test_retirement_proves_absence_and_native_replacement(retired_repository: tuple[Path, dict[str, object]]) -> None:
    evidence = check(retired_repository)
    assert len(evidence) == 1
    assert evidence[0]["source_present"] is False
    assert evidence[0]["source_importers"] == []


@pytest.mark.parametrize("relative", ["src/example/old_runtime.py", "tests/test_old_runtime.py"])
def test_retirement_rejects_original_paths(retired_repository: tuple[Path, dict[str, object]], relative: str) -> None:
    root, _ = retired_repository
    path = root / relative
    path.parent.mkdir(exist_ok=True)
    path.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="still exists"):
        check(retired_repository)


@pytest.mark.parametrize(
    ("relative", "source"),
    [
        ("src/example/replacement.py", "class OldRuntime:\n    pass\n"),
        ("tests/support.py", "class OldRuntime:\n    def changed(self): return 1\n"),
        ("src/example/consumer.py", "from .old_runtime import OldRuntime\n"),
        ("tests/consumer.py", "import example.old_runtime\n"),
        ("ci/consumer.py", "from example import old_runtime\n"),
        ("scripts/consumer.py", "import importlib as loader\nloader.import_module('example.old_runtime')\n"),
        ("tests/consumer.py", "from importlib import import_module as load\nload('example.' + 'old_runtime')\n"),
        ("tests/split.py", "import importlib\nimportlib.import_module('example.old_' + 'runtime')\n"),
        ("tests/builtin.py", "__import__('example.old_' + 'runtime')\n"),
    ],
)
def test_retirement_rejects_renamed_implementations_and_consumers(
    retired_repository: tuple[Path, dict[str, object]], relative: str, source: str
) -> None:
    root, _ = retired_repository
    path = root / relative
    path.parent.mkdir(exist_ok=True)
    path.write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"retired|reachability"):
        check(retired_repository)


@pytest.mark.parametrize("extension", ["whl", "tar.gz"])
@pytest.mark.parametrize(
    ("member", "content"),
    [
        ("example/old_runtime.py", b"# no implementation required to reject the retired path"),
        ("example/__pycache__/old_runtime.cpython-312.pyc", b"bytecode"),
        ("example/renamed.py", b"class OldRuntime:\n    pass\n"),
        ("example/renamed.py", b"class OldRuntime:\n    def different(self): return 2\n"),
    ],
)
def test_retirement_rejects_distribution_remnants(
    retired_repository: tuple[Path, dict[str, object]], extension: str, member: str, content: bytes
) -> None:
    root, _ = retired_repository
    artifact = root / f"package.{extension}"
    if extension == "whl":
        with ZipFile(artifact, "w") as archive:
            archive.writestr(member, content)
    else:
        with tarfile.open(artifact, "w:gz") as archive:
            item = tarfile.TarInfo("package/src/" + member)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
    with pytest.raises(RuntimeError, match="retired"):
        check(retired_repository, (artifact,))


def test_retirement_requires_native_replacement(retired_repository: tuple[Path, dict[str, object]]) -> None:
    root, _ = retired_repository
    (root / "rust/src/native.rs").unlink()
    with pytest.raises(RuntimeError, match="native replacement is missing"):
        check(retired_repository)


def test_retirement_allows_documentation_and_negative_fixtures(
    retired_repository: tuple[Path, dict[str, object]],
) -> None:
    root, _ = retired_repository
    (root / "src/example/check.py").write_text(
        '# OldRuntime has been removed.\nsource = "class OldRuntime: pass"\n', encoding="utf-8"
    )
    assert check(retired_repository)[0]["source_present"] is False


@pytest.mark.parametrize(
    "prefix, call",
    [
        ("import builtins\n", "builtins.__import__"),
        ("import builtins as loader\n", "loader.__import__"),
        ("from builtins import __import__ as load\n", "load"),
        ("", "__import__"),
    ],
)
def test_retirement_rejects_builtin_import_forms(
    retired_repository: tuple[Path, dict[str, object]],
    prefix: str,
    call: str,
) -> None:
    root, _ = retired_repository
    (root / "tests").mkdir()
    (root / "tests/loader.py").write_text(prefix + call + "('example.old_runtime')\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="dynamically imports retired module"):
        check(retired_repository)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
@pytest.mark.parametrize(
    "name, target",
    [
        ("package/src/example/old_runtime.py", "active.py"),
        ("package/src/example/alias.py", "old_runtime.py"),
        ("package/src/example/old_runtime.cpython-312.pyc", "active.py"),
        ("package/src/example/alias.py", "old_runtime.cpython-312.pyc"),
    ],
)
def test_retirement_checks_tar_link_name_and_target(
    retired_repository: tuple[Path, dict[str, object]],
    kind: bytes,
    name: str,
    target: str,
) -> None:
    root, _ = retired_repository
    artifact = root / "linked.tar.gz"
    with tarfile.open(artifact, "w:gz") as archive:
        entry = tarfile.TarInfo(name)
        entry.type = kind
        entry.linkname = target
        archive.addfile(entry)
    with pytest.raises(RuntimeError, match="package artifact contains retired module"):
        check(retired_repository, (artifact,))

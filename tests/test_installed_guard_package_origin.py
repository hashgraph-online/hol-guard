"""Focused contracts for the installed-package origin probe."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import base64
import hashlib
import importlib.util
import zipfile
from pathlib import Path
from types import ModuleType
from typing import ClassVar

import pytest
from typing_extensions import override

PROBE_PATH = Path(__file__).parents[1] / "scripts" / "dockerlabs" / "installed_guard_package_origin.py"


def _probe_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("installed_guard_package_origin", PROBE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_source_path_violations_detect_shadow_package(tmp_path: Path) -> None:
    probe = _probe_module()
    site_root = tmp_path / "site-packages"
    site_root.mkdir()
    shadow = tmp_path / "checkout"
    (shadow / "codex_plugin_scanner").mkdir(parents=True)

    assert probe.source_path_violations([str(shadow)], (site_root,)) == ("source-package-on-sys-path",)


def test_editable_pth_violations_reject_external_paths_but_not_distutils_hook(tmp_path: Path) -> None:
    probe = _probe_module()
    site_root = tmp_path / "site-packages"
    site_root.mkdir()
    external = tmp_path / "checkout" / "src"
    external.mkdir(parents=True)
    (site_root / "distutils-precedence.pth").write_text("import _distutils_hack\n", encoding="utf-8")
    assert probe.editable_pth_violations((site_root,)) == ()

    (site_root / "project.pth").write_text(f"{external}\n", encoding="utf-8")
    assert probe.editable_pth_violations((site_root,)) == ("external-pth-path",)


@pytest.mark.parametrize(
    ("payload", "expected"),
    (
        ('{"url":"file:///fixture/hol_guard.whl","archive_info":{}}', ()),
        ('{"url":"file:///fixture/source","dir_info":{"editable":true}}', ("editable-direct-url",)),
        ('{"url":"file:///fixture/source","dir_info":{"editable":false}}', ("non-wheel-direct-url",)),
        ("not-json", ("invalid-direct-url",)),
    ),
)
def test_direct_url_violations(payload: str, expected: tuple[str, ...]) -> None:
    probe = _probe_module()

    class Distribution:
        def read_text(self, filename: str) -> str:
            assert filename == "direct_url.json"
            return payload

    assert probe.direct_url_violations(Distribution()) == expected


def test_distribution_record_rejects_foreign_and_hash_drifted_files(tmp_path: Path) -> None:
    probe = _probe_module()
    owned = tmp_path / "owned.py"
    foreign = tmp_path / "foreign.py"
    owned.write_text("owned\n", encoding="utf-8")
    foreign.write_text("foreign\n", encoding="utf-8")

    class FileHash:
        mode: ClassVar[str] = "sha256"
        value: ClassVar[str] = (
            base64.urlsafe_b64encode(hashlib.sha256(owned.read_bytes()).digest()).rstrip(b"=").decode("ascii")
        )

    class Entry:
        hash: ClassVar[FileHash] = FileHash()

        @override
        def __str__(self) -> str:
            return "owned.py"

    class Distribution:
        files: ClassVar[tuple[Entry, ...]] = (Entry(),)

        def locate_file(self, entry: Entry) -> Path:
            assert str(entry) == "owned.py"
            return owned

    distribution = Distribution()
    assert probe.distribution_record_violations(distribution, {"module": foreign}) == (
        "module-not-owned-by-distribution",
    )

    owned.write_text("tampered\n", encoding="utf-8")
    assert probe.distribution_record_violations(distribution, {"module": owned}) == (
        "module-distribution-hash-mismatch",
    )


def test_wheel_package_inventory_reconciles_every_installed_file(tmp_path: Path) -> None:
    probe = _probe_module()
    root = tmp_path / "site-packages"
    package = root / "codex_plugin_scanner"
    package.mkdir(parents=True)
    payloads = {
        "codex_plugin_scanner/__init__.py": b"package\n",
        "codex_plugin_scanner/runtime.py": b"runtime\n",
    }
    for name, payload in payloads.items():
        (root / name).write_bytes(payload)
    wheel = tmp_path / "hol_guard-2.1.0a1-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in payloads.items():
            archive.writestr(name, payload)

    class FileHash:
        mode: str
        value: str

        def __init__(self, payload: bytes) -> None:
            self.mode = "sha256"
            self.value = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")

    class Entry:
        hash: FileHash
        name: str

        def __init__(self, name: str, payload: bytes) -> None:
            self.name = name
            self.hash = FileHash(payload)

        @override
        def __str__(self) -> str:
            return self.name

    class Distribution:
        files: tuple[Entry, ...]

        def __init__(self) -> None:
            self.files = tuple(Entry(name, payload) for name, payload in payloads.items())

        def locate_file(self, entry: Entry | str) -> Path:
            return root / str(entry)

    distribution = Distribution()
    assert probe.wheel_package_violations(distribution, wheel) == ()

    (package / "runtime.py").write_bytes(b"tampered\n")
    assert probe.wheel_package_violations(distribution, wheel) == ("package-file-wheel-hash-mismatch",)
    (package / "runtime.py").write_bytes(payloads["codex_plugin_scanner/runtime.py"])
    (package / "foreign.py").write_text("foreign\n", encoding="utf-8")
    assert probe.wheel_package_violations(distribution, wheel) == ("package-file-inventory-mismatch",)

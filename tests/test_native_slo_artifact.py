from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_slo_artifact import installed_package_digest, wheel_package_digest


def test_installed_content_digest_matches_wheel_and_detects_same_size_edit(tmp_path: Path) -> None:
    package = tmp_path / "site" / "codex_plugin_scanner"
    package.mkdir(parents=True)
    (package / "__init__.py").write_bytes(b"version = 1\n")
    (package / "scan.py").write_bytes(b"allow = True\n")
    paths = ["codex_plugin_scanner/__init__.py", "codex_plugin_scanner/scan.py"]
    wheel = tmp_path / "synthetic.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path in paths:
            archive.write(tmp_path / "site" / path, path)
        archive.writestr("hol_guard.dist-info/RECORD", "installer metadata may change")
    distribution = SimpleNamespace(files=paths, locate_file=lambda name: tmp_path / "site" / name)
    expected = wheel_package_digest(wheel)
    assert installed_package_digest(distribution) == expected
    (package / "scan.py").write_bytes(b"allow = None\n")
    assert installed_package_digest(distribution) != expected


def test_import_origin_rejects_checkout_modules_despite_installed_distribution_metadata(tmp_path, monkeypatch) -> None:
    import sys
    from types import SimpleNamespace

    import codex_plugin_scanner
    from scripts.native_slo_artifact import assert_installed_import_origin

    root = tmp_path / "installed" / "codex_plugin_scanner"
    root.mkdir(parents=True)
    (root / "__init__.py").write_text("")
    distribution = SimpleNamespace(locate_file=lambda name: root.parent / name)
    monkeypatch.setattr(codex_plugin_scanner, "__file__", str(root / "__init__.py"))
    # Other live project imports are irrelevant to this deliberately isolated
    # inventory. The rogue module must independently reject the comparison.
    monkeypatch.setattr(
        sys,
        "modules",
        {
            "codex_plugin_scanner": codex_plugin_scanner,
            "codex_plugin_scanner.rogue": SimpleNamespace(__file__=str(tmp_path / "another-checkout" / "rogue.py")),
        },
    )
    with pytest.raises(RuntimeError, match="mixed installed and checkout"):
        assert_installed_import_origin(distribution)
    monkeypatch.setattr(sys, "modules", {"codex_plugin_scanner": codex_plugin_scanner})
    assert_installed_import_origin(distribution)
    monkeypatch.setattr(codex_plugin_scanner, "__file__", str(tmp_path / "another-checkout" / "__init__.py"))
    with pytest.raises(RuntimeError, match="outside its installed wheel"):
        assert_installed_import_origin(distribution)

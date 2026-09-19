from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.verify_extension_builder_install import _verify_installed_origin


def test_installed_builder_can_live_in_a_virtualenv_under_the_checkout(tmp_path: Path) -> None:
    source = tmp_path / "source"
    python = source / ".venv" / "bin" / "python"
    package = source / ".venv" / "lib" / "python3.12" / "site-packages" / "codex_plugin_scanner" / "__init__.py"

    _verify_installed_origin(package, python, source)


@pytest.mark.parametrize("location", ["source", "external"])
def test_installed_builder_rejects_source_and_external_imports(tmp_path: Path, location: str) -> None:
    source = tmp_path / "source"
    python = source / ".venv" / "bin" / "python"
    if location == "source":
        package = source / "src" / "codex_plugin_scanner" / "__init__.py"
    else:
        package = tmp_path / "other-env" / "site-packages" / "codex_plugin_scanner" / "__init__.py"

    with pytest.raises(AssertionError, match="imported from source"):
        _verify_installed_origin(package, python, source)


def test_installed_builder_rejects_site_package_symlink_to_source(tmp_path: Path) -> None:
    source = tmp_path / "source"
    python = source / ".venv" / "bin" / "python"
    source_package = source / "src" / "codex_plugin_scanner"
    source_package.mkdir(parents=True)
    installed_package = source / ".venv" / "site-packages" / "codex_plugin_scanner"
    installed_package.parent.mkdir(parents=True)
    try:
        installed_package.symlink_to(source_package, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink is unavailable")

    with pytest.raises(AssertionError, match="imported from source"):
        _verify_installed_origin(installed_package / "__init__.py", python, source)

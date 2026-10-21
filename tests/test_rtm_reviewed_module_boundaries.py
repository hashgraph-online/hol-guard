"""The reviewed native ports remain modular without changing their facade paths."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("module", ["aibom_trust_metadata", "aibom_reporting", "supply_chain_package_eval"])
def test_reviewed_native_modules_stay_under_file_limit(module: str) -> None:
    source = ROOT / "rust" / "crates" / "guard-command" / "src"
    facade = source / f"{module}.rs"
    children = sorted((source / module).rglob("*.rs"))
    assert facade.is_file()
    assert children, f"{module} must retain responsibility-based submodules"
    oversized = {
        str(path.relative_to(ROOT)): len(path.read_text().splitlines())
        for path in [facade, *children]
        if len(path.read_text().splitlines()) > 500
    }
    assert not oversized, f"reviewed native modules exceed 500 lines: {oversized}"

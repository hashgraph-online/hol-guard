from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.ci.runtime_retirement_ledger import validate_retirement_ledger


@pytest.fixture
def ledger_repository(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    (tmp_path / "tests").mkdir()
    (tmp_path / "rust").mkdir()
    (tmp_path / "tests/test_native.py").write_text(
        "raise AssertionError('the integrity gate must not import tests')\n"
        "class TestNative:\n    def test_roundtrip(self):\n        pass\n"
        "async def test_preserved():\n    pass\n",
        encoding="utf-8",
    )
    (tmp_path / "rust/native.rs").write_text("#[test]\nfn roundtrip() {}\n", encoding="utf-8")
    contract: dict[str, object] = {
        "retirement_ledger": "ledger.json",
        "retired_modules": [{"path": "src/old.py"}],
        "retired_test_paths": ["tests/test_old.py"],
    }
    ledger: dict[str, object] = {
        "schema": "hol-guard.runtime-retirement-ledger.v1",
        "retired_source_paths": ["src/old.py"],
        "retired_tests": [
            {
                "old_node": "tests/test_old.py::test_old",
                "replacement_nodes": ["rust/native.rs::roundtrip", "tests/test_native.py::TestNative::test_roundtrip"],
            }
        ],
        "preserved_tests": [
            {
                "old_node": "tests/test_old.py::test_preserved",
                "new_node": "tests/test_native.py::test_preserved",
            }
        ],
        "unchanged_regression_suites": ["tests/test_native.py"],
    }
    return tmp_path, contract, ledger


def _check(repository: tuple[Path, dict[str, object], dict[str, object]]) -> dict[str, int]:
    root, contract, ledger = repository
    (root / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    return validate_retirement_ledger(root, contract)


def test_ledger_validates_native_python_class_and_async_nodes_without_importing(ledger_repository) -> None:
    assert _check(ledger_repository) == {"mapped_old_tests": 2, "replacement_tests": 3, "regression_suites": 1}


@pytest.mark.parametrize("filename", ["tests/test_native.py", "rust/native.rs"])
def test_ledger_rejects_missing_replacement_file(ledger_repository, filename: str) -> None:
    root, _, _ = ledger_repository
    (root / filename).unlink()
    with pytest.raises(RuntimeError, match="replacement test node is missing"):
        _check(ledger_repository)


@pytest.mark.parametrize(
    "reference",
    [
        "tests/test_native.py::test_renamed",
        "tests/test_native.py::TestNative::test_renamed",
        "rust/native.rs::renamed",
    ],
)
def test_ledger_rejects_stale_replacement_node(ledger_repository, reference: str) -> None:
    _, _, ledger = ledger_repository
    ledger["retired_tests"][0]["replacement_nodes"] = [reference]
    with pytest.raises(RuntimeError, match="replacement test node is missing"):
        _check(ledger_repository)


def test_ledger_rejects_stale_preserved_node(ledger_repository) -> None:
    _, _, ledger = ledger_repository
    ledger["preserved_tests"][0]["new_node"] = "tests/test_native.py::test_renamed"
    with pytest.raises(RuntimeError, match="replacement test node is missing"):
        _check(ledger_repository)


@pytest.mark.parametrize("value", [[], None, ["rust/native.rs::roundtrip", "rust/native.rs::roundtrip"]])
def test_ledger_rejects_empty_or_duplicate_replacements(ledger_repository, value: object) -> None:
    _, _, ledger = ledger_repository
    ledger["retired_tests"][0]["replacement_nodes"] = value
    with pytest.raises(RuntimeError, match="replacement_nodes"):
        _check(ledger_repository)


@pytest.mark.parametrize(
    "source",
    [
        "// #[test] fn roundtrip() {}\n",
        "/* outer /* nested */ #[test] fn roundtrip() {} */\n",
        'const EXAMPLE: &str = "#[test] fn roundtrip() {}";\n',
        'const EXAMPLE: &str = r###"#[test] fn roundtrip() {}"###;\n',
        "fn roundtrip() {}\n",
    ],
)
def test_ledger_does_not_accept_rust_comments_strings_or_non_test_helpers(ledger_repository, source: str) -> None:
    root, _, _ = ledger_repository
    (root / "rust/native.rs").write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match="replacement test node is missing"):
        _check(ledger_repository)


@pytest.mark.parametrize(
    "source",
    [
        "# def test_roundtrip(): pass\n",
        'example = "def test_roundtrip(): pass"\n',
        "def helper():\n    def test_roundtrip():\n        pass\n",
    ],
)
def test_ledger_does_not_accept_uncollected_python_nodes(ledger_repository, source: str) -> None:
    root, _, ledger = ledger_repository
    ledger["retired_tests"][0]["replacement_nodes"] = ["tests/test_native.py::test_roundtrip"]
    (root / "tests/test_native.py").write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match="replacement test node is missing"):
        _check(ledger_repository)


def test_ledger_rejects_reintroduced_old_node_in_retained_file(ledger_repository) -> None:
    root, _, _ = ledger_repository
    (root / "tests/test_old.py").write_text("def test_old(): pass\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="old test node still exists"):
        _check(ledger_repository)


def test_ledger_rejects_duplicate_old_node(ledger_repository) -> None:
    _, _, ledger = ledger_repository
    ledger["preserved_tests"][0]["old_node"] = "tests/test_old.py::test_old"
    with pytest.raises(RuntimeError, match="duplicates old test node"):
        _check(ledger_repository)


def test_ledger_requires_mapping_for_each_retired_test_file(ledger_repository) -> None:
    _, contract, _ = ledger_repository
    contract["retired_test_paths"].append("tests/test_another_old.py")
    with pytest.raises(RuntimeError, match="does not map every retired test path"):
        _check(ledger_repository)


def test_ledger_requires_matching_retired_source_paths(ledger_repository) -> None:
    _, _, ledger = ledger_repository
    ledger["retired_source_paths"] = ["src/another_old.py"]
    with pytest.raises(RuntimeError, match="source paths do not match"):
        _check(ledger_repository)


@pytest.mark.parametrize("source", [None, "# no test functions\n"])
def test_ledger_rejects_missing_or_empty_unchanged_regression_suite(ledger_repository, source: str | None) -> None:
    root, _, ledger = ledger_repository
    ledger["unchanged_regression_suites"] = ["tests/test_unchanged.py"]
    if source is not None:
        (root / "tests/test_unchanged.py").write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match="regression suite is missing or has no tests"):
        _check(ledger_repository)


@pytest.mark.parametrize("reference", ["../outside.py::test_case", "/outside.py::test_case", "tests//x.py::test_case"])
def test_ledger_rejects_noncanonical_or_escaping_references(ledger_repository, reference: str) -> None:
    _, _, ledger = ledger_repository
    ledger["retired_tests"][0]["replacement_nodes"] = [reference]
    with pytest.raises(RuntimeError, match="invalid repository path"):
        _check(ledger_repository)


def test_ledger_cannot_be_disabled_by_removing_contract_path(ledger_repository) -> None:
    _, contract, _ = ledger_repository
    del contract["retirement_ledger"]
    with pytest.raises(RuntimeError, match="path is required"):
        _check(ledger_repository)


def test_ledger_rejects_missing_file(ledger_repository) -> None:
    root, contract, _ = ledger_repository
    with pytest.raises(RuntimeError, match="ledger is missing"):
        validate_retirement_ledger(root, contract)


@pytest.mark.parametrize("field", ["retired_tests", "preserved_tests", "unchanged_regression_suites"])
def test_ledger_requires_all_mapping_sections(ledger_repository, field: str) -> None:
    _, _, ledger = ledger_repository
    del ledger[field]
    with pytest.raises(RuntimeError, match=field):
        _check(ledger_repository)


@pytest.mark.parametrize(
    "source",
    [
        "#[test] fn roundtrip() {}\n#[test] fn roundtrip() {}\n",
        "mod a { #[test] fn roundtrip() {} }\nmod b { #[test] fn roundtrip() {} }\n",
    ],
)
def test_ledger_rejects_ambiguous_rust_node(ledger_repository, source: str) -> None:
    root, _, _ = ledger_repository
    (root / "rust/native.rs").write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match="ambiguous Rust test nodes"):
        _check(ledger_repository)


@pytest.mark.parametrize(
    "source",
    [
        "class TestNative:\n    def test_roundtrip(self): pass\n    def test_roundtrip(self): pass\n",
        "class TestNative:\n    def test_roundtrip(self): pass\n"
        "class TestNative:\n    def test_roundtrip(self): pass\n",
    ],
)
def test_ledger_rejects_duplicate_python_node(ledger_repository, source: str) -> None:
    root, _, _ = ledger_repository
    (root / "tests/test_native.py").write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match="duplicate Python test node"):
        _check(ledger_repository)


@pytest.mark.parametrize("constructor", ["__init__", "__new__"])
def test_ledger_rejects_python_class_with_custom_constructor(ledger_repository, constructor: str) -> None:
    root, _, _ = ledger_repository
    (root / "tests/test_native.py").write_text(
        f"class TestNative:\n    def {constructor}(self): pass\n    def test_roundtrip(self): pass\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="replacement test node is missing"):
        _check(ledger_repository)


@pytest.mark.parametrize(
    "reference",
    [
        "tests/test_native.py::",
        "tests/test_native.py::TestNative::::test_roundtrip",
        "tests/test_native.py::TestNative::test_roundtrip[value]",
        "tests/test_native.py::not-a-node",
        "rust/native.rs::tests::roundtrip",
        "tests/absent.md::test_case",
    ],
)
def test_ledger_rejects_malformed_node_identity(ledger_repository, reference: str) -> None:
    _, _, ledger = ledger_repository
    ledger["retired_tests"][0]["replacement_nodes"] = [reference]
    with pytest.raises(RuntimeError, match="requires a non-parametrized test node"):
        _check(ledger_repository)


def test_ledger_resolves_current_repository_mappings() -> None:
    root = Path(__file__).resolve().parents[1]
    contract = json.loads((root / "docs/guard/contracts/python-capability-ownership.v1.json").read_text())
    result = validate_retirement_ledger(root, contract)
    assert result["mapped_old_tests"] > 0
    assert result["replacement_tests"] > 0
    assert result["regression_suites"] > 0

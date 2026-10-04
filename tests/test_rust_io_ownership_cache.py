"""The ownership analyzer may cache work, never authority or an earlier tree."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.ci import rust_io_ownership_cache as cache
from scripts.ci import rust_io_ownership_gate as gate
from scripts.ci import rust_io_ownership_resolver as resolver


def test_lookup_cache_is_scoped_and_includes_none() -> None:
    calls = []

    @cache.cached
    def lookup(name: str) -> None:
        calls.append(name)
        return None

    for _ in range(2):
        with cache.analysis_cache():
            assert lookup("missing") is None
            assert lookup("missing") is None
    lookup("missing")
    lookup("missing")
    assert calls == ["missing"] * 4


def test_nested_analysis_and_exception_restore_the_callers_cache() -> None:
    calls = []

    @cache.cached
    def lookup() -> int:
        calls.append(1)
        return len(calls)

    with cache.analysis_cache():
        assert lookup() == 1
        with pytest.raises(ValueError, match="invalid input"), cache.analysis_cache():
            assert lookup() == 2
            raise ValueError("invalid input")
        assert lookup() == 1
    with cache.analysis_cache():
        assert lookup() == 3
    assert lookup() == 4


def test_query_exceptions_are_not_cached() -> None:
    attempts = []

    @cache.cached
    def invalid() -> None:
        attempts.append(1)
        raise RuntimeError("unresolved repository helper")

    with cache.analysis_cache():
        for _ in range(2):
            with pytest.raises(RuntimeError, match="unresolved repository helper"):
                invalid()
    assert len(attempts) == 2


def test_unhashable_records_keep_normal_resolution() -> None:
    node = ast.parse("def f(value):\n    temporary = value\n    return temporary\n").body[0]
    record = SimpleNamespace(node=node)
    with cache.analysis_cache():
        assert resolver._local_binding_names(record) == {"value", "temporary"}


def test_gate_and_resolver_share_one_parse_per_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "module.py"
    source.write_text("def f():\n    return 1\n", encoding="utf-8")
    real_parse = cache.ast.parse
    parsed = []

    def parse(*args, **kwargs):
        parsed.append(1)
        return real_parse(*args, **kwargs)

    monkeypatch.setattr(cache.ast, "parse", parse)
    with cache.analysis_cache():
        first = gate._parsed_module(source)
        assert resolver._parsed_module(source) is first
    with cache.analysis_cache():
        second = resolver._parsed_module(source)
        assert second is not first
        assert gate._parsed_module(source) is second
    assert len(parsed) == 2


def test_missing_modules_are_rechecked_next_pass(tmp_path: Path) -> None:
    relative = Path("new_module.py")
    with cache.analysis_cache():
        assert resolver._module_file(tmp_path, relative) is None
    (tmp_path / relative).write_text("value = 1\n", encoding="utf-8")
    with cache.analysis_cache():
        assert resolver._module_file(tmp_path, relative) == relative.as_posix()


@pytest.mark.parametrize(
    ("imports", "body", "call"),
    [
        ("from .helper import read_source", "return read_source()", "read_source"),
        ("from .helper import read_source as read", "return read()", "read"),
        ("from . import helper", "return helper.read_source()", "helper.read_source"),
        ("from .helper import *", "return read_source()", "read_source"),
        ("", "return len([])", "len"),
        ("", "return unknown()", "unknown"),
        ("from . import helper", "return helper.unknown()", "helper.unknown"),
    ],
)
def test_indexed_and_uncached_resolution_agree(tmp_path: Path, imports: str, body: str, call: str) -> None:
    package = tmp_path / "src/codex_plugin_scanner/guard"
    package.mkdir(parents=True)
    (package / "helper.py").write_text("def read_source():\n    return 'fixture'\n", encoding="utf-8")
    (package / "caller.py").write_text(f"{imports}\n\ndef f():\n    {body}\n", encoding="utf-8")
    records = gate._function_map(tmp_path)
    record = records[("src/codex_plugin_scanner/guard/caller.py", "f")][0]

    def result(index):
        try:
            answer = resolver.resolve_call(tmp_path, record, call, index)
        except RuntimeError as error:
            return ("error", str(error))
        return None if answer is None else (answer.path, answer.qualname)

    expected = result(records)
    with cache.analysis_cache():
        index = resolver.FunctionIndex(records)
        assert result(index) == expected
        assert result(index) == expected


def test_index_preserves_all_ambiguous_candidates_and_their_order(tmp_path: Path) -> None:
    package = tmp_path / "src/codex_plugin_scanner/guard"
    package.mkdir(parents=True)
    for name in ("one", "two"):
        (package / f"{name}.py").write_text("def conflicting():\n    return 1\n", encoding="utf-8")
    (package / "caller.py").write_text("def f():\n    return conflicting()\n", encoding="utf-8")
    records = gate._function_map(tmp_path)
    caller = records[("src/codex_plugin_scanner/guard/caller.py", "f")][0]
    with pytest.raises(RuntimeError, match="ambiguous helper call") as before:
        resolver.resolve_call(tmp_path, caller, "conflicting", records)
    with cache.analysis_cache(), pytest.raises(RuntimeError, match="ambiguous helper call") as after:
        resolver.resolve_call(tmp_path, caller, "conflicting", resolver.FunctionIndex(records))
    assert str(before.value) == str(after.value)


def test_union_members_are_immutable_and_resolution_preserves_the_ast(tmp_path: Path) -> None:
    package = tmp_path / "src/codex_plugin_scanner/guard"
    package.mkdir(parents=True)
    (package / "one.py").write_text("def exposed():\n    return 1\n", encoding="utf-8")
    union = package / "union.py"
    union.write_text("from . import one as _one\n_SOURCE_MODULES = (_one,)\n", encoding="utf-8")
    path = union.relative_to(tmp_path).as_posix()
    with cache.analysis_cache():
        tree = cache.parsed_module(union)
        before = ast.dump(tree, include_attributes=True)
        members = resolver._union_source_modules(tmp_path, path, tree)
        assert members == ("src/codex_plugin_scanner/guard/one.py",)
        assert isinstance(members, tuple)
        assert resolver._resolve_exported_symbol(tmp_path, path, "exposed", set()) == members[0]
        assert ast.dump(tree, include_attributes=True) == before


def test_analysis_helpers_and_tests_have_protected_ownership_and_ci_coverage() -> None:
    import json

    import yaml

    root = Path(__file__).resolve().parents[1]
    contract = json.loads((root / "docs/guard/contracts/hook-data-plane-ownership.v2.json").read_text())
    owner = next(item for item in contract["nodes"] if item["id"] == "ownership_governance")
    paths = [
        "scripts/ci/rust_io_ownership_cache.py",
        "scripts/ci/rust_io_ownership_bindings.py",
        "scripts/ci/rust_io_ownership_policy.py",
        "tests/test_rust_io_ownership_cache.py",
    ]
    for path in paths:
        assert path in contract["protected_change_globs"]
        assert path in owner["paths"]
    workflow = yaml.safe_load((root / ".github/workflows/decision-critical-io.yml").read_text())
    step = next(
        item
        for item in workflow["jobs"]["io-ownership"]["steps"]
        if "tests/test_rust_io_ownership_gate.py" in item.get("run", "")
    )
    assert "tests/test_rust_io_ownership_cache.py" in step["run"]
    assert not step.get("continue-on-error")

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "rust_io_ownership_gate.py"
SPEC = importlib.util.spec_from_file_location("rust_io_ownership_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _copy_gate_sources(root: Path) -> None:
    paths = {spec.path for spec in MODULE.ROOTS} | {
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py"
    }
    for relative in paths:
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)


def test_gate_inventories_reachable_io_and_passes_current_sources() -> None:
    report = MODULE.validate(ROOT)

    assert report["schema"] == "hol-guard.decision-critical-io.v1"
    assert report["status"] == "passed"
    assert report["inventory_total"] >= len(report["inventory"])
    assert report["inventory"]
    assert all(item["reachable"] for item in report["inventory"])
    categories = {item["category"] for item in report["inventory"]}
    all_categories = set(report["inventory_by_category"])
    assert "transport_identity" in categories
    assert "asynchronous_policy" in categories
    config_reads = [
        item
        for item in report["inventory"]
        if item["path"] == "src/codex_plugin_scanner/guard/config_source_io.py" and item["kind"] == "filesystem"
    ]
    assert config_reads
    assert all(item["category"] == "synchronous_posture_config" for item in config_reads)
    parser_path = "src/codex_plugin_scanner/guard/config.py"
    parser = MODULE._function_map(ROOT)[parser_path, "_parse_toml"][0]
    scoped_decodes = [
        item
        for item in report["inventory"]
        if item["path"] == parser_path and parser.node.lineno <= item["line"] <= parser.node.end_lineno
    ]
    assert {item["operation"] for item in scoped_decodes} == {"loads", "decode"}
    assert all(item["category"] == "synchronous_posture_config" for item in scoped_decodes)
    assert "compatibility_only" in all_categories
    assert "unclassified_python_io" not in categories
    assert "unclassified_python_content_io" not in categories


def test_gate_rejects_python_content_read_on_native_edge(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    edge = tmp_path / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    source = edge.read_text(encoding="utf-8")
    marker = "    status = native_runtime_status()\n"
    assert marker in source
    edge.write_text(source.replace(marker, marker + '    open("source.rs")\n', 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match=r"reachable unclassified Python I/O"):
        MODULE.validate(tmp_path)


def test_gate_rejects_native_branch_semantic_fallback(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    worker = tmp_path / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    source = worker.read_text(encoding="utf-8")
    marker = "            return self._review_native_edge(\n"
    assert marker in source
    worker.write_text(source.replace(marker, "            return self.engine.review(\n", 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match="native edge return"):
        MODULE.validate(tmp_path)


def test_gate_rejects_synchronous_policy_compilation(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    publisher = tmp_path / "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py"
    source = publisher.read_text(encoding="utf-8")
    marker = "            self._started = True\n"
    assert marker in source
    publisher.write_text(
        source.replace(marker, marker + "        self._compiled_effective_policy()\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="decision-time config or secret I/O"):
        MODULE.validate(tmp_path)


def _write_guard_fixture(root: Path, name: str, source: str) -> str:
    relative = f"src/codex_plugin_scanner/guard/{name}.py"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return relative


def test_resolver_follows_qualified_repository_module_alias(tmp_path: Path) -> None:
    helper_path = _write_guard_fixture(
        tmp_path,
        "qualified_helper",
        "def read_source() -> str:\n    return 'source'\n",
    )
    caller_path = _write_guard_fixture(
        tmp_path,
        "qualified_caller",
        "from . import qualified_helper\n\ndef call() -> str:\n    return qualified_helper.read_source()\n",
    )
    records = MODULE._function_map(tmp_path)
    caller = records[(caller_path, "call")][0]

    assert "qualified_helper.read_source" in MODULE._calls(caller)
    resolved = MODULE.resolve_call(tmp_path, caller, "qualified_helper.read_source", records)
    assert resolved is not None
    assert resolved.path == helper_path


def test_resolver_uses_only_imports_in_the_caller_scope(tmp_path: Path) -> None:
    first_helper = _write_guard_fixture(
        tmp_path,
        "first_helper",
        "def read_source() -> str:\n    return 'first'\n",
    )
    second_helper = _write_guard_fixture(
        tmp_path,
        "second_helper",
        "def read_source() -> str:\n    return 'second'\n",
    )
    caller_path = _write_guard_fixture(
        tmp_path,
        "scoped_caller",
        "from .first_helper import read_source\n\n"
        "def call() -> str:\n    return read_source()\n\n"
        "def unrelated() -> str:\n"
        "    from .second_helper import read_source\n"
        "    return read_source()\n",
    )
    records = MODULE._function_map(tmp_path)

    call = records[(caller_path, "call")][0]
    unrelated = records[(caller_path, "unrelated")][0]
    resolved_call = MODULE.resolve_call(tmp_path, call, "read_source", records)
    resolved_unrelated = MODULE.resolve_call(tmp_path, unrelated, "read_source", records)

    assert resolved_call is not None and resolved_call.path == first_helper
    assert resolved_unrelated is not None and resolved_unrelated.path == second_helper


def test_resolver_fails_closed_for_unknown_symbol_on_repository_module(tmp_path: Path) -> None:
    _write_guard_fixture(
        tmp_path,
        "known_helper",
        "def other() -> str:\n    return 'other'\n",
    )
    caller_path = _write_guard_fixture(
        tmp_path,
        "unknown_symbol_caller",
        "from . import known_helper\n\ndef call() -> str:\n    return known_helper.read_source()\n",
    )
    records = MODULE._function_map(tmp_path)
    caller = records[(caller_path, "call")][0]

    with pytest.raises(RuntimeError, match="unresolved repository-qualified helper call"):
        MODULE.resolve_call(tmp_path, caller, "known_helper.read_source", records)


def test_config_reader_inventory_keeps_unreviewed_operations_closed(tmp_path: Path) -> None:
    path = _write_guard_fixture(
        tmp_path,
        "config_source_io",
        "def _read_descriptor(descriptor, before):\n"
        "    def unrelated():\n        return open('source.txt').read()\n"
        "    value = os.read(descriptor, 10)\n"
        "    return Path('source.txt').read_text()\n",
    )
    record = MODULE._function_map(tmp_path)[path, "_read_descriptor"][0]
    observed = list(MODULE._observations(record))
    nested = [item for item in observed if item.line == 3]
    reviewed = [item for item in observed if item.line == 4]
    new_operation = [item for item in observed if item.line == 5]
    assert len(nested) == 2 and len(reviewed) == len(new_operation) == 1
    assert all(item.category == "unclassified_python_io" for item in nested + new_operation)
    assert reviewed[0].category == "asynchronous_policy"
    for function in (
        "_posix_parent_chain",
        "_read_descriptor",
        "_capture_in_parent",
        "_capture_in_parent.metadata",
        "_verify_missing_parent",
        "capture_guard_config",
    ):
        for kind, operation in (("archive", "tarfile"), ("decode", "loads"), ("hash", "sha256")):
            assert MODULE._category(path, kind, function, operation).startswith("unclassified_")

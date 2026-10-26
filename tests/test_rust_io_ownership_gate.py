from __future__ import annotations

import ast
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


@pytest.mark.parametrize(
    ("path", "operation", "category"),
    [
        ("src/codex_plugin_scanner/guard/native_rich_command_model.py", "compress", "transport_encode"),
        ("src/codex_plugin_scanner/guard/native_rich_command_model.py", "open", "unclassified_python_content_io"),
        ("src/codex_plugin_scanner/guard/other_client.py", "compress", "unclassified_python_content_io"),
    ],
)
def test_request_codec_classification_does_not_allow_archive_io(path, operation, category):
    node = ast.parse(f"def request():\n    return gzip.{operation}(b'wire')\n").body[0]
    assert isinstance(node, ast.FunctionDef)
    record = MODULE.FunctionRecord(path, "request", "request", node)
    observations = list(MODULE._observations(record))
    assert len(observations) == 1
    assert observations[0].category == category


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
    assert "compatibility_only" in all_categories
    assert "unclassified_python_io" not in categories
    assert "unclassified_python_content_io" not in categories

    # The remaining unclassified I/O is Python control plane, not a gate backlog.
    remainder = report["control_plane_remainder"]
    assert remainder["reachable_count"] == 0
    assert remainder["operation_count"] == sum(
        count for category, count in report["inventory_by_category"].items() if category.startswith("unclassified_")
    )

    # The CLI hook command anchors the walk so that the two steps running ahead of any native
    # call are inside the gate. Asserting the root itself is reachable would prove nothing --
    # `_reachable_records` seeds itself from `ROOTS` -- so name the callees the root reaches.
    reachable = {
        (record.path, record.qualname) for record in MODULE._reachable_records(ROOT, MODULE._function_map(ROOT))
    }
    assert (
        "src/codex_plugin_scanner/guard/runtime/harness_attribution.py",
        "resolve_runtime_hook_harness",
    ) in reachable
    assert ("src/codex_plugin_scanner/guard/cli/commands_support_hook_payload.py", "_load_hook_payload") in reachable


def test_gate_rejects_python_content_read_on_native_edge(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    edge = tmp_path / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    source = edge.read_text(encoding="utf-8")
    marker = "    status = runtime_status if runtime_status is not None else native_runtime_status()\n"
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


@pytest.mark.parametrize("mutation", ["new_io", "syntax_error"])
def test_validation_reloads_sources_between_passes(tmp_path: Path, mutation: str) -> None:
    """A fast repeat must inspect changed source, not a previous pass's AST."""
    _copy_gate_sources(tmp_path)
    assert MODULE.validate(tmp_path)["status"] == "passed"
    edge = tmp_path / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    original = edge.read_text(encoding="utf-8")
    if mutation == "syntax_error":
        edge.write_text(original + "\ndef incomplete(\n", encoding="utf-8")
        with pytest.raises(SyntaxError):
            MODULE.validate(tmp_path)
    else:
        marker = "    status = runtime_status if runtime_status is not None else native_runtime_status()\n"
        assert marker in original
        edge.write_text(original.replace(marker, marker + '    open("new-secret.txt")\n', 1), encoding="utf-8")
        with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
            MODULE.validate(tmp_path)


def test_the_hook_worker_branch_check_ignores_root_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Adding an entry point ahead of the hook worker must not retarget the branch assertions."""
    _copy_gate_sources(tmp_path)
    records = MODULE._function_map(tmp_path)
    assert MODULE._branch_failures(tmp_path, records) == []

    reordered = tuple(reversed(MODULE.ROOTS))
    assert reordered[0] is not MODULE.HOOK_WORKER_ROOT
    monkeypatch.setattr(MODULE, "ROOTS", reordered)
    assert MODULE._branch_failures(tmp_path, records) == []


def test_the_remainder_block_says_the_unclassified_io_is_off_the_decision_path(tmp_path: Path) -> None:
    """The raw category totals read like a backlog; the remainder block says what they are."""
    _copy_gate_sources(tmp_path)
    # Control-plane I/O the walk never reaches: the gate reports it without failing.
    helper = tmp_path / "src/codex_plugin_scanner/guard/cli/unreached_control_plane.py"
    helper.write_text('def export() -> None:\n    open("report.csv")\n', encoding="utf-8")

    remainder = MODULE.validate(tmp_path)["control_plane_remainder"]

    assert remainder["reachable_count"] == 0
    assert remainder["operation_count"] >= 1
    assert remainder["by_subpackage"]["cli"] >= 1


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/codex_plugin_scanner/guard/store.py", "<top-level>"),
        ("src/codex_plugin_scanner/guard/cli/commands_hook.py", "cli"),
        ("src/codex_plugin_scanner/guard/daemon/hook_worker.py", "daemon"),
    ],
)
def test_the_remainder_groups_by_subpackage(path: str, expected: str) -> None:
    assert MODULE._subpackage(path) == expected


def _module_observations(root: Path, source: str) -> list[tuple[str, str]]:
    path = _write_guard_fixture(root, "subject", source)
    tree = ast.parse(source)
    return [
        (record.qualname, observation.operation)
        for record in MODULE._functions(tree, path)
        for observation in MODULE._observations(record, MODULE._shadowed_names(root, path, tree, record))
    ]


_REDACTION_HELPER = "def _redact_secrets(value):\n    return value[:4]\n"


def test_a_sibling_export_renamed_over_an_operation_is_not_that_operation(tmp_path: Path) -> None:
    # `resolve` here is this package's own redaction helper, not `Path.resolve`.
    _write_guard_fixture(tmp_path, "runtime_resolution", _REDACTION_HELPER)
    source = (
        "def redact(value):\n"
        "    from .runtime_resolution import _redact_secrets as resolve\n"
        "\n"
        "    return resolve(value)\n"
    )
    assert _module_observations(tmp_path, source) == []


def test_a_renamed_sibling_that_does_io_is_still_counted(tmp_path: Path) -> None:
    # The helper hashes executable bytes, so every call site that reaches it
    # under an operation's name keeps its entry.
    _write_guard_fixture(
        tmp_path,
        "executables",
        "import hashlib\n\ndef _executable_sha256(path):\n    return hashlib.sha256(path.read_bytes()).hexdigest()\n",
    )
    source = "from .executables import _executable_sha256 as sha256\n\ndef digest(path):\n    return sha256(path)\n"
    assert _module_observations(tmp_path, source) == [("digest", "sha256")]


def test_an_unresolved_renamed_sibling_is_still_counted(tmp_path: Path) -> None:
    source = "def redact(value):\n    from .missing import _redact_secrets as resolve\n\n    return resolve(value)\n"
    assert _module_observations(tmp_path, source) == [("redact", "resolve")]


def test_a_rename_in_one_function_does_not_hide_an_operation_in_another(tmp_path: Path) -> None:
    _write_guard_fixture(tmp_path, "runtime_resolution", _REDACTION_HELPER)
    source = (
        "def load(path):\n"
        "    return path.exists()\n"
        "\n"
        "def check(path):\n"
        "    return exists(path)\n"
        "\n"
        "def redact(value):\n"
        "    from .runtime_resolution import _redact_secrets as exists\n"
        "\n"
        "    return exists(value)\n"
    )
    assert _module_observations(tmp_path, source) == [("load", "exists"), ("check", "exists")]


def test_a_name_the_module_also_binds_absolutely_is_still_counted(tmp_path: Path) -> None:
    _write_guard_fixture(tmp_path, "runtime_resolution", _REDACTION_HELPER)
    source = (
        "from os.path import exists\n"
        "\n"
        "def redact(value):\n"
        "    from .runtime_resolution import _redact_secrets as exists\n"
        "\n"
        "    return exists(value)\n"
    )
    assert _module_observations(tmp_path, source) == [("redact", "exists")]


def test_a_local_wrapper_does_not_excuse_the_call_sites_that_reach_it(tmp_path: Path) -> None:
    # `sha256` names code in this package, but the gate still owes an entry for
    # every site that hashes through it.
    source = "from .io import sha256\n\ndef digest(value):\n    return sha256(value)\n"
    assert _module_observations(tmp_path, source) == [("digest", "sha256")]


def test_an_absolute_import_of_an_operation_is_still_counted(tmp_path: Path) -> None:
    # Only a relative import can be renamed into a false match; `hashlib` is
    # still the real thing under any spelling the gate can see.
    source = "from hashlib import sha256\n\ndef digest(value):\n    return sha256(value).hexdigest()\n"
    assert _module_observations(tmp_path, source) == [("digest", "sha256")]


def test_pending_authority_waivers_all_name_a_reachable_module() -> None:
    report = MODULE.validate(ROOT)
    waived = {item["path"] for item in report["inventory"] if item["category"] == "pending_authority_migration"}

    assert set(MODULE._PENDING_AUTHORITY_PATHS) == waived
    assert all((ROOT / path).is_file() for path in MODULE._PENDING_AUTHORITY_PATHS)


def test_gate_rejects_a_waiver_for_a_module_the_hook_graph_no_longer_reaches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retired = "src/codex_plugin_scanner/guard/runtime/bounded_json_depth.py"
    assert (ROOT / retired).is_file()
    assert retired not in MODULE._PENDING_AUTHORITY_PATHS
    monkeypatch.setattr(MODULE, "_PENDING_AUTHORITY_PATHS", MODULE._PENDING_AUTHORITY_PATHS | {retired})

    with pytest.raises(RuntimeError, match=rf"stale pending_authority_migration waiver: {retired}"):
        MODULE.validate(ROOT)


def test_gate_ignores_a_waiver_for_a_module_outside_the_analysed_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    absent = "src/codex_plugin_scanner/guard/runtime/not_in_this_tree.py"
    _copy_gate_sources(tmp_path)
    monkeypatch.setattr(MODULE, "_PENDING_AUTHORITY_PATHS", MODULE._PENDING_AUTHORITY_PATHS | {absent})

    assert not (tmp_path / absent).exists()
    assert MODULE.validate(tmp_path)["status"] == "passed"

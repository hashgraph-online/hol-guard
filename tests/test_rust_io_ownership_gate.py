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
    assert "synchronous_posture_config" in categories
    assert "synchronous_authority_fence" in categories
    assert "approval_identity" in categories
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
    assert {
        "continuation_transport_decode",
        "continuation_protocol_identity",
        "continuation_endpoint_identity",
        "continuation_process_identity",
        "synchronous_control_durability",
    } <= categories
    assert "unclassified_python_io" not in categories
    assert "unclassified_python_content_io" not in categories


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


def test_gate_rejects_python_content_read_on_native_edge(tmp_path: Path) -> None:
    _copy_gate_sources(tmp_path)
    edge = tmp_path / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    source = edge.read_text(encoding="utf-8")
    marker = "    status = native_runtime_status()\n"
    assert marker in source
    edge.write_text(source.replace(marker, marker + '    open("source.rs")\n', 1), encoding="utf-8")

    with pytest.raises(RuntimeError, match=r"reachable unclassified Python I/O"):
        MODULE.validate(tmp_path)


def test_floor_codec_exception_does_not_admit_program_or_source_io() -> None:
    path = "src/codex_plugin_scanner/guard/native_command_control_binding.py"
    assert MODULE._category(path, "decode", "native_command_control_floor_mac") == "transport_decode"
    assert MODULE._category(path, "decode", "native_command_control_floor_mac", "decode") == "transport_decode"
    assert MODULE._category(path, "decode", "native_command_control_floor_mac", "loads").startswith("unclassified_")
    assert MODULE._category(path, "filesystem", "native_command_control_floor_mac") == "unclassified_python_io"
    assert MODULE._category(path, "decode", "_metadata_from_bytes") == "unclassified_python_content_io"
    assert MODULE._category(path, "hash", "_metadata_from_bytes") == "unclassified_python_io"


def test_fence_exception_does_not_admit_control_content_or_program_compilation() -> None:
    path = "src/codex_plugin_scanner/guard/native_command_control_authority_io.py"
    assert MODULE._category(path, "filesystem", "hold_command_control_authority_lock") == "synchronous_authority_fence"
    assert MODULE._category(path, "decode", "hold_command_control_authority_lock") == "unclassified_python_content_io"
    assert MODULE._category(path, "hash", "hold_command_control_authority_lock") == "unclassified_python_io"
    assert MODULE._category(path, "filesystem", "read_private_state") == "unclassified_python_io"
    binding = "src/codex_plugin_scanner/guard/daemon/hook_native_review_binding.py"
    assert MODULE._category(binding, "hash", "native_review_action_identity") == "approval_identity"
    assert MODULE._category(binding, "hash", "native_review_policy_binding") == "unclassified_python_io"


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


def test_resolver_follows_exact_static_facade_without_accepting_computed_exports(tmp_path: Path) -> None:
    implementation = _write_guard_fixture(tmp_path, "platform_io", "def read_source():\n    return 'source'\n")
    facade_path = _write_guard_fixture(
        tmp_path, "io_facade", "from . import platform_io as backend\nread_source = backend.read_source\n"
    )
    caller_path = _write_guard_fixture(
        tmp_path, "facade_caller", "from . import io_facade as api\ndef call():\n    return api.read_source()\n"
    )
    records = MODULE._function_map(tmp_path)
    caller = records[caller_path, "call"][0]
    resolved = MODULE.resolve_call(tmp_path, caller, "api.read_source", records)
    assert resolved is not None and resolved.path == implementation
    (tmp_path / facade_path).write_text(
        "from . import platform_io as backend\nread_source = getattr(backend, 'read_source')\n"
    )
    with pytest.raises(RuntimeError, match="unresolved repository-qualified helper call"):
        MODULE.resolve_call(tmp_path, caller, "api.read_source", MODULE._function_map(tmp_path))


def test_resolver_follows_visible_direct_function_alias(tmp_path: Path) -> None:
    target = _write_guard_fixture(tmp_path, "actual_identity", "def mapping_value():\n    return {}\n")
    _write_guard_fixture(tmp_path, "unrelated_identity", "def _mapping():\n    return {}\n")
    caller = _write_guard_fixture(
        tmp_path,
        "alias_caller",
        "from .actual_identity import mapping_value as _mapping\ndef call():\n    return _mapping()\n",
    )
    records = MODULE._function_map(tmp_path)
    resolved = MODULE.resolve_call(tmp_path, records[caller, "call"][0], "_mapping", records)
    assert resolved is not None and resolved.path == target and resolved.name == "mapping_value"


def test_resolver_keeps_builtin_file_open_at_calling_function(tmp_path: Path) -> None:
    _write_guard_fixture(
        tmp_path, "network_handlers", "class First:\n def open(self): pass\nclass Second:\n def open(self): pass\n"
    )
    caller = _write_guard_fixture(tmp_path, "file_caller", 'def inspect():\n    return open("source.txt")\n')
    records = MODULE._function_map(tmp_path)
    record = records[caller, "inspect"][0]
    assert MODULE.resolve_call(tmp_path, record, "open", records) is None
    observations = list(MODULE._observations(record))
    assert any(value.kind == "filesystem" and value.category == "unclassified_python_io" for value in observations)


def test_resolver_follows_explicit_imported_class_method(tmp_path: Path) -> None:
    target = _write_guard_fixture(
        tmp_path, "envelope", "class Envelope:\n @classmethod\n def from_dict(cls, value): return cls()\n"
    )
    caller = _write_guard_fixture(
        tmp_path,
        "class_caller",
        "from .envelope import Envelope\ndef inspect(value):\n    return Envelope.from_dict(value)\n",
    )
    records = MODULE._function_map(tmp_path)
    result = MODULE.resolve_call(tmp_path, records[caller, "inspect"][0], "Envelope.from_dict", records)
    assert result is not None and result.path == target and result.qualname == "Envelope.from_dict"


@pytest.mark.parametrize(
    ("source", "call"),
    [
        ("from hashlib import sha256\ndef inspect(): return sha256(b'')\n", "sha256"),
        ("from hashlib import sha256 as digest\ndef inspect(): return digest(b'')\n", "digest"),
        ("import hashlib as digest\ndef inspect(): return digest.sha256(b'')\n", "digest.sha256"),
        (
            "from .unrelated_hash import sha256\ndef inspect():\n"
            "    from hashlib import sha256\n    return sha256(b'')\n",
            "sha256",
        ),
    ],
)
def test_external_import_cannot_resolve_unrelated_repository_helper(tmp_path: Path, source: str, call: str) -> None:
    _write_guard_fixture(tmp_path, "unrelated_hash", "def sha256(value): return open(value).read()\n")
    caller = _write_guard_fixture(tmp_path, "external_caller", source)
    records = MODULE._function_map(tmp_path)
    record = records[caller, "inspect"][0]
    assert MODULE.resolve_call(tmp_path, record, call, records) is None
    if call.endswith("sha256"):
        assert any(item.kind == "hash" and item.operation == "sha256" for item in MODULE._observations(record))


@pytest.mark.parametrize(
    ("module", "function", "kind", "operation", "category"),
    [
        ("daemon/codex_native_live_decision", "_decode_hook_input", "decode", "loads", "continuation_transport_decode"),
        ("continuation_payload", "offer_hash", "hash", "sha256", "continuation_protocol_identity"),
        ("continuation_runtime", "_opaque_target_id", "hash", "sha256", "continuation_protocol_identity"),
        ("codex_app_server", "_is_safe_local_socket_path", "filesystem", "resolve", "continuation_endpoint_identity"),
        ("codex_app_server", "_is_trusted_local_socket", "filesystem", "lstat", "continuation_endpoint_identity"),
        ("live_process_identity", "_linux_proc_stat", "filesystem", "read", "continuation_process_identity"),
        ("live_process_identity", "_trusted_posix_ps_path", "filesystem", "stat", "continuation_process_identity"),
        ("durable_io", "fsync_directory", "filesystem", "open", "synchronous_control_durability"),
    ],
)
def test_continuation_io_exceptions_are_function_and_primitive_scoped(
    module: str, function: str, kind: str, operation: str, category: str
) -> None:
    path = f"src/codex_plugin_scanner/guard/{module}.py"
    assert MODULE._category(path, kind, function, operation) == category
    for other_function in ("unrelated", f"{function}.nested", f"Owner.{function}"):
        assert MODULE._category(path, kind, other_function, operation).startswith("unclassified_")
    assert MODULE._category(path, kind, function, "read_bytes").startswith("unclassified_")
    assert MODULE._category(path, "archive", function, "tarfile").startswith("unclassified_")


def test_nested_operation_does_not_inherit_outer_continuation_exception(tmp_path: Path) -> None:
    path = _write_guard_fixture(
        tmp_path,
        "live_process_identity",
        "def _linux_proc_stat(pid):\n"
        "    def inspect_other_source():\n        return open('source.txt').read()\n"
        "    return open('/proc/123/stat').read()\n",
    )
    record = MODULE._function_map(tmp_path)[path, "_linux_proc_stat"][0]
    observed = list(MODULE._observations(record))
    nested = [item for item in observed if item.line == 3]
    outer = [item for item in observed if item.line == 4]
    assert len(nested) == len(outer) == 2
    assert all(item.category == "unclassified_python_io" for item in nested)
    assert all(item.category == "continuation_process_identity" for item in outer)


def test_continuation_contract_retains_rust_action_identity_and_explicit_control_io() -> None:
    contract = next(
        item for item in MODULE._capability_contract() if item["id"] == "native_codex_browser_continuation_control"
    )
    assert contract["python_decision_time_disk_io"] is True
    assert contract["python_semantic_fallback"] is False
    assert contract["action_source_identity"] == "verified_rust_request_digest"
    assert contract["failure"] == "continuation_not_completed"

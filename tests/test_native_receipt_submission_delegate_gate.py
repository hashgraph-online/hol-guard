"""Mutation controls keep the moved admission body inside the receipt I/O gate."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scripts.ci.native_receipt_persistence_gate import (
    _submit_method_has_no_decision_io,
    _validate_submit_delegate,
)

ROOT = Path(__file__).resolve().parents[1]
WRITER = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py"
HELPER = "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_operations.py"


def _check(root: Path) -> None:
    writer = (root / WRITER).read_text(encoding="utf-8")
    _submit_method_has_no_decision_io(writer)
    _validate_submit_delegate(root, writer)


def test_gate_follows_actual_original_signature_admission_delegate() -> None:
    _check(ROOT)


def test_gate_preserves_unchanged_direct_body_route(tmp_path: Path) -> None:
    source = (
        "class RuntimeHookEvidenceWriter:\n"
        "    def submit_native_decision_receipt(self, receipt):\n"
        "        self._records.append(receipt)\n"
        "        return True\n"
    )
    destination = tmp_path / WRITER
    destination.parent.mkdir(parents=True)
    destination.write_text(source, encoding="utf-8")
    _check(tmp_path)
    destination.write_text(source.replace("self._records.append(receipt)", "self._connect()"), encoding="utf-8")
    with pytest.raises(RuntimeError, match="decision-time I/O"):
        _check(tmp_path)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_helper",
        "helper_sqlite",
        "helper_connect",
        "helper_persist",
        "helper_nested",
        "helper_decorated",
        "helper_argument",
        "helper_facade_import",
        "facade_import",
        "facade_false",
        "facade_argument",
        "facade_nested",
        "facade_io",
    ],
)
def test_gate_refuses_io_or_disconnected_admission_body(tmp_path: Path, mutation: str) -> None:
    for relative in (WRITER, HELPER):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative).read_bytes())
    helper = tmp_path / HELPER
    writer = tmp_path / WRITER
    if mutation == "missing_helper":
        helper.unlink()
    elif mutation.startswith("helper_"):
        source = helper.read_text(encoding="utf-8")
        node = next(
            item
            for item in ast.parse(source).body
            if isinstance(item, ast.FunctionDef) and item.name == "submit_native_decision_receipt"
        )
        lines = source.splitlines(keepends=True)
        if mutation in {"helper_sqlite", "helper_connect", "helper_persist"}:
            call = {
                "helper_sqlite": '_writer.sqlite3.connect("unused.db")',
                "helper_connect": "self._connect()",
                "helper_persist": "_writer.persist_native_decision_receipt(store=self._store, receipt=receipt)",
            }[mutation]
            position = node.body[0].lineno - 1
            lines.insert(position, "    " + call + "\n")
        elif mutation == "helper_nested":
            assert node.end_lineno is not None
            block = lines[node.lineno - 1 : node.end_lineno]
            lines[node.lineno - 1 : node.end_lineno] = ["if False:\n", *["    " + line for line in block]]
        elif mutation == "helper_decorated":
            lines.insert(node.lineno - 1, "@staticmethod\n")
        elif mutation == "helper_argument":
            argument = node.args.args[0]
            signature = lines[argument.lineno - 1]
            offset = argument.col_offset
            assert signature[offset : offset + 4] == "self"
            lines[argument.lineno - 1] = signature[:offset] + "different" + signature[offset + 4 :]
        else:
            marker = "from . import runtime_hook_evidence_writer as _writer"
            assert marker in source
            lines = source.replace(marker, "# disconnected " + marker, 1).splitlines(keepends=True)
        helper.write_text("".join(lines), encoding="utf-8")
    else:
        source = writer.read_text(encoding="utf-8")
        delegate = "return _evidence_operations.submit_native_decision_receipt(self, receipt)"
        assert delegate in source
        if mutation == "facade_import":
            marker = "from . import runtime_hook_evidence_operations as _evidence_operations"
            assert marker in source
            source = source.replace(marker, "# disconnected " + marker, 1)
        else:
            replacement = {
                "facade_false": "return False",
                "facade_argument": "return _evidence_operations.submit_native_decision_receipt(self, dict(receipt))",
                "facade_nested": "if False:\n            " + delegate + "\n        return False",
                "facade_io": "self._connect()\n        " + delegate,
            }[mutation]
            source = source.replace(delegate, replacement, 1)
        writer.write_text(source, encoding="utf-8")
    with pytest.raises(RuntimeError, match=r"receipt|admission"):
        _check(tmp_path)

"""Public method and live-facade seams for the evidence operations split."""

from __future__ import annotations

import inspect
import json
import subprocess
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import FunctionType
from typing import get_type_hints
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_operations as operations
from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer_module
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_queue_observation import EvidenceQueueObservation
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from tests.test_guard_runtime_hook_evidence_queue_observation import _command, _paused_writer
from tests.test_native_decision_receipt import _receipt

_METHODS = {
    "submit_command_activity": (
        (
            "self",
            "harness",
            "event",
            "payload",
            "succeeded",
            "policy_action",
            "receipt_id",
            "prompted",
            "approval_reuse_status",
        ),
        {
            "harness": "str",
            "event": "str",
            "payload": "Mapping[str, object]",
            "succeeded": "bool",
            "policy_action": "str | None",
            "receipt_id": "str | None",
            "prompted": "bool",
            "approval_reuse_status": "str",
            "return": "bool",
        },
        {"policy_action": None, "receipt_id": None, "prompted": False, "approval_reuse_status": "not-applicable"},
    ),
    "submit_native_decision_receipt": (
        ("self", "receipt"),
        {"receipt": "Mapping[str, object]", "return": "bool"},
        {},
    ),
    "_derive_correlation": (
        ("self", "harness", "event", "payload"),
        {"harness": "str", "event": "str", "payload": "Mapping[str, object]", "return": "CorrelationHandle | None"},
        {},
    ),
    "_persist_command_activity": (
        ("self", "record"),
        {"record": "_CommandActivityRecord", "return": "None"},
        {},
    ),
}


@pytest.mark.parametrize("name", list(_METHODS))
def test_existing_writer_methods_keep_class_ownership_and_signature(name: str) -> None:
    parameters, annotations, defaults = _METHODS[name]
    method = RuntimeHookEvidenceWriter.__dict__[name]
    assert type(method) is FunctionType
    assert method.__module__ == writer_module.__name__
    assert method.__qualname__ == "RuntimeHookEvidenceWriter." + name
    assert method.__annotations__ == annotations
    assert method.__defaults__ is None
    assert (method.__kwdefaults__ or {}) == defaults
    signature = inspect.signature(method)
    assert tuple(signature.parameters) == parameters
    keyword_only = name in {"submit_command_activity", "_derive_correlation"}
    for index, parameter in enumerate(signature.parameters.values()):
        expected = inspect.Parameter.KEYWORD_ONLY if keyword_only and index else inspect.Parameter.POSITIONAL_OR_KEYWORD
        assert parameter.kind is expected
    assert RuntimeHookEvidenceWriter.__bases__ == (writer_module.RuntimeHookEvidenceWriterJournalMixin,)
    assert operations._writer is writer_module


def test_constructor_annotations_resolve_to_original_live_types_and_observer() -> None:
    assert get_type_hints(RuntimeHookEvidenceWriter.__init__) == {
        "store": writer_module.GuardStore,
        "max_records": int,
        "max_bytes": int,
        "max_batch": int,
        "batch_wait_seconds": float,
        "journal_path": Path | None,
        "queue_observation": EvidenceQueueObservation | None,
        "return": type(None),
    }
    assert writer_module.EvidenceQueueObservation is EvidenceQueueObservation
    parameter = inspect.signature(RuntimeHookEvidenceWriter.__init__).parameters["queue_observation"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY and parameter.default is None


def test_native_admission_reads_current_facade_validator(tmp_path: Path) -> None:
    writer = _paused_writer(tmp_path)
    with patch.object(writer_module, "validate_native_decision_receipt", return_value=None) as validator:
        assert not writer.submit_native_decision_receipt(_receipt())
    validator.assert_called_once()
    assert writer.stats()["receipt_dropped"] == writer.stats()["dropped"] == 1
    assert writer.stats()["queued"] == 0


def test_command_persistence_reads_rebound_facade_provider(tmp_path: Path) -> None:
    writer = _paused_writer(tmp_path)
    assert _command(writer)
    record = writer._next_batch()[0]
    observed: list[str] = []
    with patch.object(
        writer_module,
        "persist_deferred_post_hook_command_activity",
        side_effect=lambda **_kwargs: observed.append("first"),
    ):
        writer._persist_command_activity(record)
    with patch.object(
        writer_module,
        "persist_deferred_post_hook_command_activity",
        side_effect=lambda **_kwargs: observed.append("second"),
    ):
        writer._persist_command_activity(record)
    assert observed == ["first", "second"]


def test_correlation_helpers_read_current_facade_bindings(tmp_path: Path) -> None:
    writer = _paused_writer(tmp_path)
    original_key = writer._correlation_key
    assert original_key is not None
    observed: list[str] = []
    writer._correlation_key = None
    with (
        patch.object(writer_module, "load_or_create_installation_correlation_key", return_value=original_key) as loader,
        patch.object(
            writer_module,
            "derive_proven_request_correlation",
            side_effect=lambda **_kwargs: observed.append("first"),
        ),
    ):
        assert writer._derive_correlation(harness="pi", event="PostToolUse", payload={}) is None
    loader.assert_called_once_with(writer._guard_home)
    with patch.object(
        writer_module,
        "derive_proven_request_correlation",
        side_effect=lambda **_kwargs: observed.append("second"),
    ):
        assert writer._derive_correlation(harness="pi", event="PostToolUse", payload={}) is None
    assert observed == ["first", "second"]


def test_saturated_admission_still_refuses_before_touching_payload(tmp_path: Path) -> None:
    class ForbiddenPayload(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            raise AssertionError("saturated writer inspected a payload value")

        def __iter__(self) -> Iterator[str]:
            raise AssertionError("saturated writer iterated a payload")

        def __len__(self) -> int:
            raise AssertionError("saturated writer measured a payload")

    writer = _paused_writer(tmp_path, max_records=1)
    assert writer.submit_native_decision_receipt(_receipt())
    assert not writer.submit_command_activity(
        harness="pi",
        event="PostToolUse",
        payload=ForbiddenPayload(),
        succeeded=True,
    )
    assert writer.stats()["accepted"] == 1 and writer.stats()["dropped"] == 1


@pytest.mark.parametrize(
    "first",
    [
        "runtime_hook_evidence_operations",
        "runtime_hook_evidence_writer",
        "runtime_hook_evidence_queue_observation",
        "runtime_hook_evidence_writer_journal",
    ],
)
def test_fresh_process_import_orders_bind_the_actual_writer(tmp_path: Path, first: str) -> None:
    root = Path(__file__).resolve().parents[1]
    script = """
import importlib
import json
from pathlib import Path
import sys
from typing import get_type_hints
root = Path(sys.argv[1]).resolve(strict=True)
sys.path[:0] = [str(root / "src"), str(root)]
import codex_plugin_scanner.guard.daemon
prefix = "codex_plugin_scanner.guard.daemon."
names = [prefix + name for name in (
    "runtime_hook_evidence_operations", "runtime_hook_evidence_writer", "runtime_hook_evidence_queue_observation",
    "runtime_hook_evidence_writer_journal",
)]
assert all(name not in sys.modules for name in names), "Parent imports preloaded the target"
importlib.import_module(prefix + sys.argv[2])
operations = importlib.import_module(names[0])
writer = importlib.import_module(names[1])
assert operations._writer is writer
assert writer._evidence_operations is operations
observation = importlib.import_module(names[2])
assert writer.EvidenceQueueObservation is observation.EvidenceQueueObservation
journal = importlib.import_module(names[3])
assert journal._writer is writer
assert writer.RuntimeHookEvidenceWriterJournalMixin is journal.RuntimeHookEvidenceWriterJournalMixin
storage = importlib.import_module(prefix + "runtime_hook_evidence_journal")
for helper in ("append_journal", "recover_journal_records", "rewrite_journal"):
    assert getattr(writer, helper) is getattr(storage, helper)
hints = get_type_hints(writer.RuntimeHookEvidenceWriter.__init__)
assert hints["store"] is writer.GuardStore
assert hints["queue_observation"] == observation.EvidenceQueueObservation | None
assert Path(writer.__file__).resolve() == root / "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py"
assert writer.RuntimeHookEvidenceWriter.__bases__ == (writer.RuntimeHookEvidenceWriterJournalMixin,)
print(json.dumps({"first": sys.argv[2], "parent_imports_did_not_preload": True, "bound": True}))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(root), first],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(completed.stdout) == {
        "first": first,
        "parent_imports_did_not_preload": True,
        "bound": True,
    }

"""Keep allocation-observer records bounded and free of request contents."""

from __future__ import annotations

import json
from types import SimpleNamespace

from scripts import bench_guard_cigar_allocation_diagnostic as diagnostic


def frame(name, label="source compiler", filename=None):
    return SimpleNamespace(
        f_code=SimpleNamespace(co_name=name, co_filename=filename or "/installed" + diagnostic.COMPILER_SUFFIX),
        f_locals={"label": label, "subcommand": "bundle-metadata", "request": {"secret": "never-record-this"}},
    )


def test_large_reads_count_nested_overlap_without_retaining_returned_contents(monkeypatch):
    monkeypatch.setattr(diagnostic, "tracemalloc", SimpleNamespace(get_traced_memory=lambda: (12, 34)))
    observer = diagnostic.CompilerObserver()
    first, second = frame("_read_regular"), frame("_read_regular")
    observer.profile(first, "call", None)
    observer.profile(second, "call", None)
    large = b"never-record-this" + b"x" * (1024 * 1024)
    observer.profile(second, "return", large)
    observer.profile(first, "return", large)
    report = observer.report()
    row = report["counts"]["_read_regular:source compiler"]
    assert row["calls"] == row["returns"] == row["large_returns"] == row["max_concurrent"] == 2
    assert row["returned_bytes"] == len(large) * 2
    assert row["active"] == report["unreturned_calls"] == 0
    assert "never-record-this" not in json.dumps(report)


def test_unknown_labels_are_redacted_and_unrelated_files_are_ignored(monkeypatch):
    monkeypatch.setattr(diagnostic, "tracemalloc", SimpleNamespace(get_traced_memory=lambda: (0, 0)))
    observer = diagnostic.CompilerObserver()
    unrelated = frame("_read_regular", filename="/unrelated/native_source_compiler.py")
    observer.profile(unrelated, "call", None)
    observer.profile(unrelated, "return", b"never-record-this")
    other = frame("_read_regular", label="never-record-this")
    observer.profile(other, "call", None)
    observer.profile(other, "return", None)
    report = observer.report()
    assert set(report["counts"]) == {"_read_regular:other"}
    assert report["counts"]["_read_regular:other"]["returned_none"] == 1
    assert "never-record-this" not in json.dumps(report)


def test_timeline_is_bounded_while_totals_still_include_all_operations(monkeypatch):
    monkeypatch.setattr(diagnostic, "tracemalloc", SimpleNamespace(get_traced_memory=lambda: (0, 0)))
    observer = diagnostic.CompilerObserver()
    operation = frame("run_source_compiler")
    for _ in range(1025):
        observer.profile(operation, "call", None)
        observer.profile(operation, "return", {})
    report = observer.report()
    assert len(report["timeline"]) == 1024
    assert report["dropped_timeline_events"] == 1
    assert report["counts"]["run_source_compiler:bundle-metadata"]["calls"] == 1025

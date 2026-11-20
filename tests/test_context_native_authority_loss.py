"""Fail before signalling when a disposable native owner's identity changes."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import context_native_authority_loss as loss
from tests.context_process_fault import Row


@pytest.fixture
def family(monkeypatch):
    rows = {
        101: Row(os.getpid(), 101, ("native-start",), "native", "S"),
        102: Row(101, 102, ("bridge-start",), "Python", "S"),
        103: Row(102, 102, ("worker-start",), "worker", "S"),
    }
    images = {101: Path("/qualified-native"), 102: Path("/qualified-python"), 103: Path("/qualified-worker")}
    owned = SimpleNamespace(native=101, lineage=dict(rows), images=dict(images))
    monkeypatch.setattr(loss, "kernel_image", images.get)
    monkeypatch.setattr(loss, "_snapshot", lambda: dict(rows))
    monkeypatch.setattr(loss, "_digest", lambda _path: "same-approved-bytes")
    return owned, rows, images


@pytest.mark.parametrize(
    "mismatch", ["ancestry", "pid-reuse", "group", "native-image", "worker-image", "missing", "artifact"]
)
def test_changed_native_ownership_is_refused(family, monkeypatch, mismatch):
    owned, rows, images = family
    if mismatch == "ancestry":
        rows[101] = replace(rows[101], parent=1)
    elif mismatch == "pid-reuse":
        rows[101] = replace(rows[101], start=("different-lifetime",))
    elif mismatch == "group":
        rows[101] = replace(rows[101], group=999)
    elif mismatch in {"native-image", "worker-image"}:
        images[101 if mismatch == "native-image" else 103] = Path("/changed-image")
    elif mismatch == "missing":
        rows.pop(101)
    else:
        monkeypatch.setattr(loss, "_digest", lambda path: str(path))
    with pytest.raises(AssertionError):
        loss.verify_authority(owned, Path("/selected-native"), rows)


def test_a_qualified_current_descendant_is_the_only_valid_target(family):
    owned, rows, _images = family
    assert loss.verify_authority(owned, Path("/selected-native"), rows) == 101
    owned.native = os.getpid()
    with pytest.raises(AssertionError):
        loss.verify_authority(owned, Path("/selected-native"), rows)


def test_an_exec_or_group_change_cannot_be_misreported_as_retirement(family):
    _owned, rows, images = family
    captured = {101: rows[101]}
    images[101] = Path("/new-exec")
    rows[101] = replace(rows[101], group=999)
    assert loss._live_captured(captured) == [101]
    rows[101] = replace(rows[101], start=("unrelated-reused-pid",))
    assert loss._live_captured(captured) == []

"""Delivery scripts judge release metadata with the runtime their workflow built."""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import lifecycle
from tests.test_extension_delivery_authority import SOURCE, root_value


@pytest.fixture
def pin(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    return importlib.import_module("extension_delivery_runtime").pinned_runtime


def test_the_named_runtime_is_the_session_executable(pin, tmp_path, monkeypatch):
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"synthetic")
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(runtime))
    assert lifecycle._SESSION.get() is None
    with pin(), lifecycle.session():
        session = lifecycle._SESSION.get()
        assert session is not None and session.executable() == runtime.resolve()
    assert lifecycle._SESSION.get() is None


def test_without_a_named_runtime_nothing_is_pinned(pin, monkeypatch):
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    with pin():
        assert lifecycle._SESSION.get() is None


def test_a_runtime_that_is_not_a_file_is_refused(pin, tmp_path, monkeypatch):
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(tmp_path / "absent"))
    with pytest.raises(FileNotFoundError), pin():
        pass
    monkeypatch.setenv("HOL_GUARD_NATIVE_BINARY", str(tmp_path))
    with pytest.raises(SystemExit), pin():
        pass


@pytest.mark.skipif(not os.environ.get("HOL_GUARD_NATIVE_BINARY"), reason="needs the built runtime")
def test_the_pinned_runtime_answers_a_distribution_request(pin):
    request = {"operation": "root", "data": json.dumps(root_value()), "source": SOURCE, "now": 1500}
    with pin():
        assert lifecycle._invoke("distribution", request, 60) == {"expires_at": 2000}

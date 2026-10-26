"""A data-free build must bind the exact requested source/trust stream."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def receipt():
    path = Path(__file__).resolve().parents[1] / "scripts/command_compiler_receipt.py"
    spec = importlib.util.spec_from_file_location("compiler_receipt_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("fault", [None, "digest", "length", "schema", "implementation", "mode"])
def test_bootstrap_receipt_binds_original_input(receipt, monkeypatch, tmp_path, fault):
    data = b"original source and reviewed trust bytes"
    calls = []
    info = {
        "schema": "guard.source-compiler-capabilities.v1",
        "implementation_digest": "1" * 64,
        "embedded_catalog": False,
    }
    proof = {
        "schema": "guard.command-source-input-receipt.v1",
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "input_bytes": len(data),
    }
    if fault == "implementation":
        info["implementation_digest"] = "2" * 64
    if fault == "mode":
        info["embedded_catalog"] = 0
    if fault == "digest":
        proof["input_sha256"] = "0" * 64
    if fault == "length":
        proof["input_bytes"] += 1
    if fault == "schema":
        proof["schema"] = "unrecognized"

    def run(command, **kwargs):
        calls.append(command)
        if command[-1] == "compiler-info":
            return subprocess.CompletedProcess(command, 0, json.dumps(info).encode())
        assert command[-1] == "compile-bootstrap-stream"
        assert kwargs["stdin"].read() == data
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {"schema": "guard.command-bootstrap-build.v1", "receipt": proof, "build": {"result": "native"}}
            ).encode(),
        )

    monkeypatch.setattr(
        receipt,
        "subprocess",
        SimpleNamespace(run=run, PIPE=subprocess.PIPE, CompletedProcess=subprocess.CompletedProcess),
    )
    if fault is not None:
        with pytest.raises(ValueError):
            receipt.compile_stream(
                ["compiler"], io.BytesIO(data), root=tmp_path, implementation="1" * 64, inspect_mode=True
            )
    else:
        completed, bootstrap = receipt.compile_stream(
            ["compiler"], io.BytesIO(data), root=tmp_path, implementation="1" * 64, inspect_mode=True
        )
        assert bootstrap and json.loads(completed.stdout) == {"result": "native"}
        assert len(calls) == 2


def test_older_compiler_keeps_legacy_build_and_export_checks(receipt, monkeypatch, tmp_path):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 2 if command[-1] == "compiler-info" else 0, b"{}")

    monkeypatch.setattr(receipt, "subprocess", SimpleNamespace(run=run, PIPE=subprocess.PIPE))
    completed, bootstrap = receipt.compile_stream(
        ["compiler"], io.BytesIO(b"input"), root=tmp_path, implementation="1" * 64, inspect_mode=True
    )
    assert not bootstrap and completed.returncode == 0
    assert calls == [["compiler", "compiler-info"], ["compiler", "compile-stream"]]

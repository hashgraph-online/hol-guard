"""Bind data-free compiler builds to their original source/trust input bytes."""

from __future__ import annotations

import hashlib
import json
import subprocess


def compile_stream(prefix, stream, *, root, implementation, inspect_mode):
    bootstrap = False
    if inspect_mode:
        info = subprocess.run([*prefix, "compiler-info"], cwd=root, capture_output=True, timeout=60, check=False)
        if info.returncode == 0:
            value = json.loads(info.stdout)
            if (
                not isinstance(value, dict)
                or set(value) != {"schema", "implementation_digest", "embedded_catalog"}
                or value["schema"] != "guard.source-compiler-capabilities.v1"
                or type(value["embedded_catalog"]) is not bool
                or value["implementation_digest"] != implementation
            ):
                raise ValueError("source compiler capabilities do not match the current native implementation")
            bootstrap = not value["embedded_catalog"]
    expected_hash = expected_bytes = None
    if bootstrap:
        digest = hashlib.sha256()
        expected_bytes = 0
        stream.seek(0)
        while data := stream.read(65536):
            digest.update(data)
            expected_bytes += len(data)
        expected_hash = digest.hexdigest()
        stream.seek(0)
    command = [*prefix, "compile-bootstrap-stream" if bootstrap else "compile-stream"]
    completed = subprocess.run(command, stdin=stream, stdout=subprocess.PIPE, cwd=root, timeout=600, check=False)
    if bootstrap and completed.returncode == 0:
        value = json.loads(completed.stdout)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "build", "receipt"}
            or value["schema"] != "guard.command-bootstrap-build.v1"
            or not isinstance(value["build"], dict)
        ):
            raise ValueError("source compiler bootstrap build contract invalid")
        receipt = value["receipt"]
        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"schema", "input_sha256", "input_bytes"}
            or receipt["schema"] != "guard.command-source-input-receipt.v1"
            or receipt["input_sha256"] != expected_hash
            or type(receipt["input_bytes"]) is not int
            or receipt["input_bytes"] != expected_bytes
        ):
            raise ValueError("source compiler receipt does not bind the requested source and trust bytes")
        completed = subprocess.CompletedProcess(command, 0, json.dumps(value["build"]).encode())
    return completed, bootstrap

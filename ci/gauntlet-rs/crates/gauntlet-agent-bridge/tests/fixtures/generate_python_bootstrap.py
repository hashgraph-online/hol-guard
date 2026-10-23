"""Freeze synthetic private bootstrap identities from pinned Python code."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(REPO))

from ci.gauntlet.benchmark.json_data import canonical_json  # noqa: E402, I001
from ci.gauntlet.benchmark.vm_bridge_control import source_hashes  # noqa: E402


SESSION = "11111111-1111-1111-1111-111111111111"
CONTROLLER = "22222222-2222-2222-2222-222222222222"
PRODUCT = "33333333-3333-3333-3333-333333333333"
VM_KEY = b"B" * 32
CELL_KEY = b"C" * 32

vm = {
    "schema": "gauntlet-vm-bridge-private-bootstrap.v1",
    "session": SESSION,
    "key_hex": VM_KEY.hex(),
    "controller_boot": CONTROLLER,
    "product_boot": PRODUCT,
    "hashes": source_hashes(),
}
cell = {
    "schema": "product-cell-private-bootstrap.v1",
    "session": SESSION,
    "key_hex": CELL_KEY.hex(),
    "boot_id": CONTROLLER,
}
source = REPO / "ci/gauntlet/benchmark"
fixture = {
    "schema": "hol-gauntlet-python-private-bootstrap-fixtures.v1",
    "source_sha256": {
        name: hashlib.sha256((source / name).read_bytes()).hexdigest()
        for name in ("vm_bridge_control.py", "product_cell_protocol.py")
    },
    "vm": {
        "body": vm,
        "bytes_hex": canonical_json(vm).encode().hex(),
        "auth_fingerprint": hashlib.sha256(b"vm-bridge-control-auth.v1\0" + VM_KEY).hexdigest(),
    },
    "cell": {"body": cell, "bytes_hex": canonical_json(cell).encode().hex()},
}
Path(__file__).with_name("python_bootstrap_v1.json").write_text(
    json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8"
)

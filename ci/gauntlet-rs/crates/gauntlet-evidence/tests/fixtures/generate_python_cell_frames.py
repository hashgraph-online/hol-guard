"""Freeze the product-cell HMAC dialect from the pinned Python codec."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(REPO))

from ci.gauntlet.benchmark.product_cell_protocol import CellCodec  # noqa: E402, I001


KEY = b"C" * 32
SESSION = "11111111-1111-1111-1111-111111111111"
BOOT = "22222222-2222-2222-2222-222222222222"
REQUEST_ID = "123e4567-e89b-12d3-a456-426614174000"

supervisor = CellCodec(
    KEY, session=SESSION, local_role="cell-supervisor", local_boot=BOOT, peer_boot=BOOT
)
actor = CellCodec(
    KEY, session=SESSION, local_role="cell-actor", local_boot=BOOT, peer_boot=BOOT
)
steps = (
    (supervisor, actor, "request", {"request_id": REQUEST_ID, "operation": "hello", "payload": {}}),
    (
        actor,
        supervisor,
        "response",
        {"request_id": REQUEST_ID, "operation": "hello", "result": {"ready": True}, "error": None},
    ),
    (supervisor, actor, "request", {"request_id": REQUEST_ID, "operation": "close", "payload": {}}),
)
frames = []
for sender, receiver, kind, body in steps:
    frame = sender.encode(kind, body)
    assert receiver.decode(frame[4:], expected_kind=kind) == body
    frames.append({"kind": kind, "body": body, "hex": frame.hex()})

source = REPO / "ci/gauntlet/benchmark"
fixture = {
    "schema": "hol-gauntlet-python-cell-frames.v1",
    "session": SESSION,
    "boot": BOOT,
    "source_sha256": {
        name: hashlib.sha256((source / name).read_bytes()).hexdigest()
        for name in ("product_cell_protocol.py", "vm_bridge_frames.py")
    },
    "frames": frames,
}
Path(__file__).with_name("python_cell_frames_v1.json").write_text(
    json.dumps(fixture, sort_keys=True, indent=2) + "\n", encoding="utf-8"
)

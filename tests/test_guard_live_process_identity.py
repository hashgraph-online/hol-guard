"""Process-bound proof for suspended hook continuation."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import cast

from codex_plugin_scanner.guard.live_process_identity import current_process_identity, process_identity_matches


def test_current_process_identity_matches_only_the_exact_live_process() -> None:
    identity = current_process_identity()

    assert identity is not None
    assert process_identity_matches(identity) is True
    assert process_identity_matches({**identity, "startToken": "reused-process"}) is False


def test_process_identity_rejects_unbound_or_extended_payloads() -> None:
    assert process_identity_matches(None) is False
    assert process_identity_matches({"pid": 1}) is False
    assert process_identity_matches({"pid": True, "startToken": "invalid"}) is False
    assert process_identity_matches({"pid": 1, "startToken": "invalid", "extra": True}) is False


def test_process_identity_stops_matching_after_the_process_exits() -> None:
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import json,time; "
                "from codex_plugin_scanner.guard.live_process_identity import current_process_identity; "
                "print(json.dumps(current_process_identity()), flush=True); time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        serialized_identity = cast(str, child.stdout.readline())
        identity = cast(object, json.loads(serialized_identity))
        assert process_identity_matches(identity) is True
    finally:
        child.terminate()
        _ = child.wait(timeout=5)

    assert process_identity_matches(identity) is False

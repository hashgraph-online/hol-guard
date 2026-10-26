"""Pack-mode markers remain distinguishable to an actual frozen v1 reader."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_command_control_authority import (
    PACK_AUTHORITY_SCHEMA,
    decode_authority,
    encode_authority,
)
from codex_plugin_scanner.guard.native_policy_snapshot_codec import _canonical_json_bytes_v3
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError


def old_decoder():
    # The fixture is compiled under its real path so coverage, which traces it as
    # part of ``codex_plugin_scanner`` because of the scope's ``__name__``, can
    # still read the source when it writes the XML report.
    fixture = Path(__file__).parent / "fixtures/native-command-authority-v1.py.txt"
    scope = {
        "__name__": "codex_plugin_scanner.guard._v1_authority_fixture",
        "__package__": "codex_plugin_scanner.guard",
    }
    exec(compile(fixture.read_text(), str(fixture), "exec"), scope)
    return scope["decode_authority"]


def test_pack_marker_binds_program_and_rejects_a_legacy_reader_or_domain():
    key = b"unit-marker-vector".ljust(32, b"x")
    record = {
        "schema": PACK_AUTHORITY_SCHEMA,
        "epoch": 1,
        "mutation_revision": 1,
        "authority_key_id": "a" * 64,
        "phase": "committed",
        "effective_digest": "b" * 64,
        "recovery": None,
        "pack_program_digest": "c" * 64,
    }
    encoded = encode_authority(record, key)
    decoded = decode_authority(encoded, key)
    assert decoded["pack_program_digest"] == record["pack_program_digest"]
    with pytest.raises(NativePolicySnapshotError):
        old_decoder()(encoded, key)
    # Stripping the field/schema cannot turn a v2 MAC into a valid v1 marker.
    downgraded = {name: value for name, value in decoded.items() if name != "pack_program_digest"}
    downgraded["schema"] = "guard.native-command-control-authority.v1"
    with pytest.raises(NativePolicySnapshotError):
        old_decoder()(_canonical_json_bytes_v3(downgraded), key)
    decoded["pack_program_digest"] = "d" * 64
    with pytest.raises(NativePolicySnapshotError):
        decode_authority(_canonical_json_bytes_v3(decoded), key)

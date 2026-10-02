"""Private namespace plans must be bounded, immutable and exact before execution."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_linux_entry import load_plan


def _payload(root):
    executable = str(Path(sys.executable).resolve())
    metadata = root.stat()
    return {
        "schema": "guard-linux-readonly-plan.v2",
        "mapping_records": [],
        "command": [executable, "-V"],
        "read_roots": [],
        "read_files": [],
        "list_roots": [],
        "write_roots": [str(root)],
        "executables": [executable],
        "device_files": [],
        "read_identities": [],
        "write_identities": [[str(root), metadata.st_dev, metadata.st_ino]],
    }


def _write(root, payload):
    path = root / "plan.json"
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_valid_private_plan_preserves_command_and_identity(tmp_path):
    path, digest = _write(tmp_path, _payload(tmp_path))
    plan = load_plan(path, digest)
    assert plan["command"] == [str(Path(sys.executable).resolve()), "-V"]
    assert set(plan["write_identities"]) == {tmp_path}


@pytest.mark.parametrize(
    "mutation", ["schema", "extra", "missing-inode", "wrong-image", "relative-path", "bad-argv", "boolean-inode"]
)
def test_malformed_or_unbound_plan_is_not_execution_consent(tmp_path, mutation):
    payload = _payload(tmp_path)
    if mutation == "schema":
        payload["schema"] = "unknown"
    elif mutation == "extra":
        payload["override"] = True
    elif mutation == "missing-inode":
        payload["write_identities"] = []
    elif mutation == "wrong-image":
        payload["executables"] = []
    elif mutation == "relative-path":
        payload["read_roots"] = ["relative"]
    elif mutation == "bad-argv":
        payload["command"] = [True]
    else:
        payload["write_identities"][0][1] = True
    path, digest = _write(tmp_path, payload)
    with pytest.raises(ValueError):
        load_plan(path, digest)


def test_changed_private_bytes_do_not_keep_old_execution_hash(tmp_path):
    path, digest = _write(tmp_path, _payload(tmp_path))
    path.write_text("{}")
    with pytest.raises(ValueError, match="changed"):
        load_plan(path, digest)


def test_legacy_plan_cannot_skip_executable_mapping_boundary(tmp_path):
    payload = _payload(tmp_path)
    payload["schema"] = "guard-linux-readonly-plan.v1"
    payload.pop("mapping_records")
    path, digest = _write(tmp_path, payload)
    with pytest.raises(ValueError, match="Unsupported"):
        load_plan(path, digest)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "readable"])
def test_untrusted_snapshot_file_cannot_be_loaded(tmp_path, kind):
    path, digest = _write(tmp_path, _payload(tmp_path))
    if kind == "symlink":
        alias = tmp_path / "alias.json"
        alias.symlink_to(path)
        path = alias
    elif kind == "hardlink":
        (tmp_path / "alias.json").hardlink_to(path)
    else:
        path.chmod(0o644)
    with pytest.raises((ValueError, OSError)):
        load_plan(path, digest)


def test_duplicate_json_fields_are_rejected_even_with_matching_hash(tmp_path):
    path, _ = _write(tmp_path, _payload(tmp_path))
    path.write_text('{"schema":"one","schema":"two"}')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="Duplicate"):
        load_plan(path, digest)

"""Recorded parity for the native OCI bundle owner.

``fixtures/oci_bundle/vectors.json.gz`` was recorded from the retired Python
``oci_isolation_provider`` evidence reader, verdict and plan digest; the same
file is replayed by the Rust unit tests. Each vector names the bundle
directory layout it needs and uses ``{ROOT}`` for the per-run bundle root.
"""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError, native_runner_authority
from codex_plugin_scanner.guard.runtime.execution_assurance_contract import framed_digest

_VECTORS = Path(__file__).parent / "fixtures" / "oci_bundle" / "vectors.json.gz"
_PLACEHOLDER = "{ROOT}"
_PLAN_DOMAIN = "guard.oci-plan.v1"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the recorded layouts use POSIX symlinks")


def _substitute(value: Any, root: str) -> Any:
    if isinstance(value, str):
        return value.replace(_PLACEHOLDER, root)
    if isinstance(value, list):
        return [_substitute(item, root) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item, root) for key, item in value.items()}
    return value


def _build_layout(root: Path, layout: list[list[str]]) -> None:
    for entry in layout:
        path = root / entry[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        if entry[1] == "dir":
            path.mkdir(parents=True, exist_ok=True)
        elif entry[1] == "file":
            path.write_bytes(b"x")
        else:
            path.symlink_to(entry[2])


def _plan_matches(vector: dict[str, Any], actual: dict[str, Any], want: dict[str, Any]) -> bool:
    fields = want.get("plan_fields")
    if not isinstance(fields, dict):
        return actual == want
    root_is_per_run = bool(fields["bundle_root"]) or _PLACEHOLDER in json.dumps(vector["args"]["bundle"])
    if not root_is_per_run:
        return actual == want
    got = dict(actual)
    # The root is part of the digest and differs per run: re-derive the digest
    # from the answer's own fields and compare every other field.
    if got.pop("plan_digest") != framed_digest(_PLAN_DOMAIN, got["plan_fields"]):
        return False
    expected = {key: value for key, value in want.items() if key != "plan_digest"}
    if _PLACEHOLDER in json.dumps(vector["args"]["bundle"]):
        got["plan_fields"] = {**got["plan_fields"], "bundle_digest": None}
        expected["plan_fields"] = {**expected["plan_fields"], "bundle_digest": None}
    return got == expected


@pytest.mark.usefixtures("native_approval_reuse_runtime")
def test_recorded_python_oci_bundles_match_the_resident(tmp_path: Path) -> None:
    document = json.loads(gzip.decompress(_VECTORS.read_bytes()))
    assert document["version"] == 1
    mismatches: list[str] = []
    for index, vector in enumerate(document["vectors"]):
        root = tmp_path / str(index)
        root.mkdir()
        canonical = root.resolve()
        _build_layout(canonical, vector["fs"])
        root_text = canonical.as_posix()
        args = _substitute(vector["args"], root_text)
        if "expected_error" in vector:
            try:
                native_runner_authority(vector["kind"], args)
            except NativeRunnerAuthorityError as error:
                if str(error) != vector["expected_error"]:
                    mismatches.append(vector["name"])
            else:
                mismatches.append(vector["name"])
            continue
        actual = native_runner_authority(vector["kind"], args)
        want = _substitute(vector["expected"], root_text)
        matched = _plan_matches(vector, actual, want) if vector["kind"] == "oci_bundle_plan" else actual == want
        if not matched:
            mismatches.append(vector["name"])
    assert mismatches == []

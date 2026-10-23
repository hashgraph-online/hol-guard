"""Read-only Python differential over one externally pinned Rust staging suite.

The result is a diagnostic, never benchmark admission or a Rust verdict.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

CONTROLLER = Path("/opt/hol-gauntlet/controller-2932d5a8ce25ac91")
BUILD = "b70d59e2681c4a3f"
SOURCE = "76c31929833b5571d25a56d9783e24a0997d5422"
CONFIG = "8ef7a22ac7a4d01bd79e15fd9ed891d1328c86d62a3848a0e6e48d94594b9492"
MANIFEST_SHA = "c6ac2fa675e254c4017fba79078ec9eb804be02d1c143c5ff0776484bfda7551"
ROLES = ("success", "input-binding", "injection", "boundary", "timeout", "cancel")


def main() -> None:
    if sys.platform != "linux" or sys.flags.isolated != 1:
        raise ValueError("isolated Linux Python required")
    manifest_path = (Path("/opt/hol-gauntlet/rust-shadow-candidates") / BUILD /
                     f"suite-pins-{MANIFEST_SHA[:16]}.json")
    raw_manifest = manifest_path.read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != MANIFEST_SHA:
        raise ValueError("outside manifest digest differs")
    manifest = json.loads(raw_manifest)
    if (manifest["schema"] != "hol-gauntlet-staging-suite-pins.v5"
            or manifest["build_job_id"] != BUILD
            or manifest["source_sha"] != SOURCE
            or manifest["config_digest"] != CONFIG
            or set(manifest["roles"]) != set(ROLES)):
        raise ValueError("outside suite identity differs")

    records = {}
    for role in ROLES:
        row = manifest["roles"][role]
        run = row["run_id"]
        raw = (Path("/home") / f"hx-{run}" / role / "control.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["record_sha256"]:
            raise ValueError(f"{role} record differs from host pin")
        value = json.loads(raw)
        if value["controller_public_key_hex"] != row["controller_public_key_hex"]:
            raise ValueError(f"{role} key differs from prelaunch host pin")
        records[role] = value

    # This is the Python stage adapter's same-record expected tuple, supplied
    # only after the outside manifest/record/key pins above. It is not an
    # independently reviewed product source or installer anchor.
    settings = records["success"]["developer_runtime"]["record"]["settings"]
    expected = {key: settings[key] for key in (
        "package_version", "source_sha", "prefix_digest", "bwrap_sha256",
        "executor_image_id", "mcp_image_id")}
    expected["private_cell"] = {key: settings["private_cell"][key] for key in (
        "artifact_manifest_sha256", "initializer_sha256", "native_sha256",
        "runtime_tree_digest", "idmap_runtime", "cpu_profile")}

    sys.path.insert(0, str(CONTROLLER))
    from ci.gauntlet.benchmark.deterministic import evaluate_control
    from ci.gauntlet.benchmark.local_executor_controls import verify_control

    results = []
    for role in ROLES:
        record = records[role]
        verify_control("success" if role == "injection" else role, record,
                       public_key=manifest["roles"][role]["controller_public_key_hex"],
                       expected=expected)
        row = evaluate_control(role, record, expected)
        if row["status"] != "passed" or row["model_tokens"] != 0:
            raise ValueError(f"{role} Python diagnostic failed")
        results.append({"role": role, "status": row["status"]})
    print(json.dumps({"schema": "gauntlet-retained-v5-python-differential.v1",
                      "source_sha": SOURCE, "manifest_sha256": MANIFEST_SHA,
                      "roles": results, "model_requests": 0, "model_tokens": 0,
                      "execution_eligible": False}, sort_keys=True))


if __name__ == "__main__":
    main()

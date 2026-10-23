"""Read-only Python/Rust differential test over a pinned v7 VM deployment.

Only test configs under the guest Root home are written. No deployed asset changes.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

CONFIG = Path("/opt/hol-gauntlet/candidates/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/config.json")
CONFIG_DIGEST = "97dcf0337f2f98539212390d969a30c2290d3123ce99d8a3aeba7725d54f7568"
CONTROLLER = Path("/opt/hol-gauntlet/controller-01abe774177c980b")
VERIFIER = Path("/root/gauntlet-inputs-verify-4748c7a8")
VERIFIER_SHA256 = "4748c7a8fdf65c2e6eefde95bc96599b7bfeb1a871b3f15ce5a9387d5479a1ed"
ASSET_ROOT = Path("/opt")
OUTPUT = Path("/root/gauntlet-rust-asset-negative-20261020")


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("root is needed to read the pinned private asset tree")
    if sha256(VERIFIER) != VERIFIER_SHA256:
        raise SystemExit("Rust verifier differs from its outside SHA-256 pin")
    sys.path.insert(0, str(CONTROLLER))
    from ci.gauntlet.benchmark.ci_runner_config import load_config, verify_assets
    from ci.gauntlet.benchmark.contracts import digest

    original = json.loads(CONFIG.read_bytes())
    if digest(original) != CONFIG_DIGEST:
        raise SystemExit("deployed config differs from its outside digest")
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    failures = []
    for role in sorted(original["assets"]):
        if role == "native":
            python_stage = "private-cell native digest must match the pinned native file"
            rust_stage = "invalid caller-pinned runner declaration"
        elif role == "private_cell":
            python_stage = "private-cell artifact manifest differs from caller pin"
            rust_stage = "private-cell manifest differs from outside pin"
        elif role in {"guard_prefix", "sdk", "zod_cache"}:
            python_stage = f"{role} differs from its frozen artifact digest"
            rust_stage = "runner asset differs from its frozen digest"
        else:
            python_stage = f"{role} differs from its frozen artifact digest"
            rust_stage = "file asset differs from its pin"
        case = json.loads(json.dumps(original))
        case["assets"][role]["sha256"] = "0" * 64
        if case["assets"][role]["sha256"] == original["assets"][role]["sha256"]:
            raise SystemExit(f"{role} cannot be changed to a distinct digest")
        config = OUTPUT / f"wrong-{role}.json"
        config.write_text(json.dumps(case, separators=(",", ":")), encoding="utf-8")
        os.chmod(config, 0o600)
        outside_digest = digest(case)
        try:
            loaded = load_config(config, expected_digest=outside_digest, asset_root=ASSET_ROOT)
            verify_assets(loaded)
        except Exception as error:
            python_result = f"refuse:{type(error).__name__}:{error}"
        else:
            python_result = "accept"
        rust = subprocess.run(
            [str(VERIFIER), str(config), outside_digest, str(ASSET_ROOT), "--full-inert-assets"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        rust_result = (
            "accept" if rust.returncode == 0 else f"refuse:{rust.returncode}:{rust.stderr.strip()}"
        )
        print(f"{role}\t{python_result}\t{rust_result}", flush=True)
        if (
            not python_result.startswith("refuse:ValueError:")
            or python_stage not in python_result
            or rust.returncode != 1
            or rust_stage not in rust_result
        ):
            failures.append(role)
    print(f"cases={len(original['assets'])} reason_stage_mismatches={len(failures)}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

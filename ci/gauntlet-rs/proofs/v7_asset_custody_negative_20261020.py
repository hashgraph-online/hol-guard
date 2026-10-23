"""Compare pinned Python and inert Rust refusals without changing deployed assets.

Run only in the idle ARM64 VM. The temporary proof roots are removed on exit.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

CONFIG = Path("/opt/hol-gauntlet/candidates/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/config.json")
CONFIG_DIGEST = "97dcf0337f2f98539212390d969a30c2290d3123ce99d8a3aeba7725d54f7568"
CONTROLLER = Path("/opt/hol-gauntlet/controller-01abe774177c980b")
VERIFIER = Path("/root/gauntlet-inputs-verify-b6dc2a54")
VERIFIER_SHA256 = "b6dc2a54fe59f9947e39f2f2cf577a14b49563a0b976f1f6eb9cc03e046cc250"
ASSET_ROOT = Path("/opt")
SOURCE_PINS = {
    "ci_runner_config.py": "90e632c95ee511e048b0803c0a713b11f4ff282aad1c146e1f5ec9e4806e4bc6",
    "business_agent_container.py": "5ef2796c44ee97d3774dd00863686ceedf3d79b5f8b491e3b934288abf75fae9",
    "native_product_container.py": "16aeb017e858385a9cb8c02b1ae62de6fe117e1cf7e2b0a38eaeee142a17459e",
    "product_version.py": "3d919f1ad5ec4a6e24240d096af1226316927e53750856db577950808298ec19",
}
REASONS = {
    "absolute-path": ("asset paths must be canonical relative paths", "invalid caller-pinned runner declaration"),
    "traversal-path": ("asset paths must be canonical relative paths", "invalid caller-pinned runner declaration"),
    "dot-path": ("asset paths must be canonical relative paths", "invalid caller-pinned runner declaration"),
    "wrong-kind": ("incompatible artifact kind", "invalid caller-pinned runner declaration"),
    "wrong-node-name": ("Node asset must retain the node executable name", "invalid caller-pinned runner declaration"),
    "invalid-version": ("runtime/guard_package_version", "invalid caller-pinned runner declaration"),
    "wrong-source": ("installed runtime manifest differs", "installed metadata differs"),
    "file-symlink": ("pinned file must be ordinary", "bundle I/O error"),
    "sdk-symlink": ("ordinary public directory", "bundle I/O error"),
    "no-execute-bit": ("bun is not executable", "pinned executable has no execute bit"),
    "wrong-file-bytes": ("bun differs from its frozen artifact digest", "file asset differs from its pin"),
    "unsafe-sdk-mode": ("public asset ownership/mode", "unsafe public SDK ownership or mode"),
    "unsafe-prefix-mode": ("installed prefix itself must be canonical", "installed prefix root is not root-owned"),
}


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(path: Path) -> str:
    return path.relative_to(ASSET_ROOT).as_posix()


def compare(name: str, config: dict, output: Path, digest, load_config, verify_assets, *, refuse: bool) -> bool:
    target = output / f"{name}.json"
    target.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")
    target.chmod(0o600)
    expected = digest(config)
    try:
        verify_assets(load_config(target, expected_digest=expected, asset_root=ASSET_ROOT))
    except Exception as error:
        python_result = f"{type(error).__name__}: {error}"
    else:
        python_result = "accept"
    rust = subprocess.run(
        [str(VERIFIER), str(target), expected, str(ASSET_ROOT), "--full-inert-assets"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    rust_result = "accept" if rust.returncode == 0 else f"{rust.returncode}: {rust.stderr.strip()}"
    print(f"{name}\tpython={python_result}\trust={rust_result}", flush=True)
    if not refuse:
        return python_result == "accept" and rust.returncode == 0
    python_reason, rust_reason = REASONS[name]
    return (
        python_result.startswith(("ValueError:", "ContractError:"))
        and python_reason in python_result
        and rust.returncode == 1
        and rust_reason in rust_result
    )


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("Root is needed to read the pinned private assets")
    if sha256(VERIFIER) != VERIFIER_SHA256:
        raise SystemExit("Rust verifier differs from the outside SHA-256 pin")
    source = CONTROLLER / "ci/gauntlet/benchmark"
    for name, pin in SOURCE_PINS.items():
        if sha256(source / name) != pin:
            raise SystemExit(f"installed Python reader source differs from pinned {name}")
    sys.path.insert(0, str(CONTROLLER))
    from ci.gauntlet.benchmark.ci_runner_config import load_config, verify_assets
    from ci.gauntlet.benchmark.contracts import digest

    original = json.loads(CONFIG.read_bytes())
    if digest(original) != CONFIG_DIGEST:
        raise SystemExit("deployed config differs from outside digest")
    failures = []
    with (
        tempfile.TemporaryDirectory(prefix="hol-gauntlet-rust-custody-", dir="/root") as output_name,
        tempfile.TemporaryDirectory(prefix="hol-gauntlet-rust-custody-", dir="/opt") as assets_name,
    ):
        output = Path(output_name)
        assets = Path(assets_name)
        if not compare("positive", original, output, digest, load_config, verify_assets, refuse=False):
            raise SystemExit("positive control failed in one or both readers")
        cases = {}

        def add(name: str, change) -> None:
            config = copy.deepcopy(original)
            change(config)
            cases[name] = config

        add("absolute-path", lambda cfg: cfg["assets"]["bun"].update(path="/etc/passwd"))
        add("traversal-path", lambda cfg: cfg["assets"]["bun"].update(path="../etc/passwd"))
        add("dot-path", lambda cfg: cfg["assets"]["bun"].update(path="./bun"))
        add("wrong-kind", lambda cfg: cfg["assets"]["bun"].update(kind="sdk-tree"))
        add("wrong-node-name", lambda cfg: cfg["assets"]["node"].update(path="node-other"))
        add("invalid-version", lambda cfg: cfg["runtime"].update(guard_package_version="../3.49"))
        add("wrong-source", lambda cfg: cfg["runtime"].update(guard_source_sha="0" * 40))

        linked_file = assets / "bun-link"
        linked_file.symlink_to(ASSET_ROOT / original["assets"]["bun"]["path"])
        add("file-symlink", lambda cfg: cfg["assets"]["bun"].update(path=relative(linked_file)))
        linked_sdk = assets / "sdk-link"
        linked_sdk.symlink_to(ASSET_ROOT / original["assets"]["sdk"]["path"])
        add("sdk-symlink", lambda cfg: cfg["assets"]["sdk"].update(path=relative(linked_sdk)))

        no_exec = assets / "bun-no-exec"
        no_exec.write_bytes(b"inert fixture\n")
        no_exec.chmod(0o644)
        add("no-execute-bit", lambda cfg: cfg["assets"]["bun"].update(path=relative(no_exec), sha256=sha256(no_exec)))
        changed = assets / "bun-changed"
        changed.write_bytes(b"different inert bytes\n")
        changed.chmod(0o755)
        add("wrong-file-bytes", lambda cfg: cfg["assets"]["bun"].update(path=relative(changed)))

        unsafe_sdk = assets / "unsafe-sdk"
        unsafe_sdk.mkdir(mode=0o755)
        sdk_file = unsafe_sdk / "data"
        sdk_file.write_bytes(b"inert fixture\n")
        sdk_file.chmod(0o666)
        add("unsafe-sdk-mode", lambda cfg: cfg["assets"]["sdk"].update(path=relative(unsafe_sdk), sha256="0" * 64))

        unsafe_prefix = assets / "unsafe-prefix"
        manifest = unsafe_prefix / "lib/python3.12/site-packages/codex_plugin_scanner/_native/runtime-manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps(
                {
                    "package_version": original["runtime"]["guard_package_version"],
                    "source_sha": original["runtime"]["guard_source_sha"],
                    "runtime_sha256": original["assets"]["native"]["sha256"],
                }
            ),
            encoding="utf-8",
        )
        unsafe_prefix.chmod(0o777)
        add(
            "unsafe-prefix-mode",
            lambda cfg: cfg["assets"]["guard_prefix"].update(path=relative(unsafe_prefix), sha256="0" * 64),
        )

        for name, case in cases.items():
            if not compare(name, case, output, digest, load_config, verify_assets, refuse=True):
                failures.append(name)
    print(f"cases={len(cases)} both_refused={len(cases) - len(failures)} mismatches={failures}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

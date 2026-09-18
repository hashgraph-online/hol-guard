"""Select a pinned historical wheel, never a mutable latest build or rebuild."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

PRIOR_PR_HEAD_SHA = "ae33987d0c8675c36a77375e03419aee920825f6"
PRIOR_BUILD_SHA = "a224cc2e01e1eb8d74182fa32d78f46e9b417348"
PRIOR_RUN_ID = 35217841356
PRIOR_REPOSITORY = "hashgraph-online/hol-guard"
PRIOR_ARTIFACTS = {
    "x86_64-unknown-linux-musl": {
        "artifact_id": 10495348403,
        "archive_sha256": "55f6058da8d589132ea2428fd1b55677fb7074bbdf7fcaf03b66853c4b11e28a",
        "wheel_name": "hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl",
        "wheel_sha256": "7404839d6a0d8d1c0954af7f95fe6d48663944cffb421325e8ec0006a4200602",
    },
    "x86_64-apple-darwin": {
        "artifact_id": 10496030613,
        "archive_sha256": "a880f0a08a9cd4c23d9e935c2861472dd7e2bf58ea24c5f2b8725f030176ddaf",
        "wheel_name": "hol_guard-3.0.1-py3-none-macosx_13_0_x86_64.whl",
        "wheel_sha256": "079e2c0261bcc8925c9a9b5484237792d1ff5119297cf4359d0c5ebe70b700bc",
    },
    "aarch64-apple-darwin": {
        "artifact_id": 10496485020,
        "archive_sha256": "d0b9983d5c7c2b6985eecaef3150134aeca6ba3fc967afa4274907cbb572badf",
        "wheel_name": "hol_guard-3.0.1-py3-none-macosx_11_0_arm64.whl",
        "wheel_sha256": "3efb6ebbc029554ed109eb5b9823fcc39a1df7ad4c947ab6d36d88d17f2060a6",
    },
    "x86_64-pc-windows-msvc": {
        "artifact_id": 10495748426,
        "archive_sha256": "ec65e2d9448c1a6c37202518e71e9fdc6ca338d8731f3d99d7d172e91bc64e5f",
        "wheel_name": "hol_guard-3.0.1-py3-none-win_amd64.whl",
        "wheel_sha256": "cb378e13d354c123de3761b0197b4b63c884fe368b65135bf576e7e42c26e089",
    },
}


def prior_artifact(root: Path, target: str) -> tuple[Path, dict]:
    pin = PRIOR_ARTIFACTS[target]
    root = root.resolve(strict=True)
    matches = list(root.rglob(pin["wheel_name"]))
    if len(matches) != 1 or not matches[0].resolve(strict=True).is_relative_to(root) or matches[0].is_symlink():
        raise ValueError("qualification_transition_prior_wheel_ambiguous")
    wheel = matches[0].resolve(strict=True)
    if not wheel.is_file() or not 0 < wheel.stat().st_size <= 128 * 1024 * 1024:
        raise ValueError("qualification_transition_prior_wheel_size_invalid")
    digest = hashlib.sha256()
    with wheel.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != pin["wheel_sha256"]:
        raise ValueError("qualification_transition_prior_wheel_digest_mismatch")
    manifest_name = "codex_plugin_scanner/_native/runtime-manifest.json"
    with ZipFile(wheel) as archive:
        if archive.namelist().count(manifest_name) != 1 or archive.getinfo(manifest_name).file_size > 65536:
            raise ValueError("qualification_transition_prior_manifest_invalid")
        manifest = json.loads(archive.read(manifest_name))
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") != "hol-guard-native-runtime.v1"
            or manifest.get("source_sha") != PRIOR_BUILD_SHA
            or manifest.get("target") != target
        ):
            raise ValueError("qualification_transition_prior_embedded_identity_mismatch")
    return wheel, {
        "schema": "hol-guard.installed-prior-artifact.v1",
        "build_sha": PRIOR_BUILD_SHA,
        "pr_head_sha": PRIOR_PR_HEAD_SHA,
        "workflow_run_id": PRIOR_RUN_ID,
        "artifact_id": pin["artifact_id"],
        "archive_sha256": pin["archive_sha256"],
        "wheel_sha256": pin["wheel_sha256"],
        "wheel_bytes_verified": True,
        "archive_digest_scope": "recorded_original_download",
        "embedded_build_verification": "required_after_isolated_install",
        "target": target,
        "rebuilt": False,
    }


def main() -> int:
    """Private selector protocol, invoked only inside a bounded child process."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    try:
        wheel, evidence = prior_artifact(args.root, args.target)
        result = {"passed": True, "selected_wheel": str(wheel), "evidence": evidence}
    except Exception as error:
        reasons = {
            "qualification_transition_prior_wheel_ambiguous",
            "qualification_transition_prior_wheel_size_invalid",
            "qualification_transition_prior_wheel_digest_mismatch",
            "qualification_transition_prior_manifest_invalid",
            "qualification_transition_prior_embedded_identity_mismatch",
        }
        if isinstance(error, FileNotFoundError):
            reason = "qualification_transition_prior_artifact_missing"
        elif isinstance(error, KeyError):
            reason = "qualification_transition_prior_target_unknown"
        else:
            reason = str(error) if str(error) in reasons else "qualification_transition_prior_validation_failed"
        result = {"passed": False, "reason": reason, "category": type(error).__name__}
    # The selected local path is a private parent/child protocol field. The
    # transition driver exports only the bounded evidence or stable failure.
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

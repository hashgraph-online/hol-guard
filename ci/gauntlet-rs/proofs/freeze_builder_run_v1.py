"""Freeze Python's actual Podman run argv without invoking Podman."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ci.gauntlet.control_plane import vm_build


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ci/gauntlet/control_plane/vm_build.py"
SOURCE_SHA256 = "48f5525cc04cfd0dc3ba14cee03849d4a2870e24ba23e118be2142a525ed3a98"
JOB = "0123456789abcdef"
SHA = "a" * 40
IMAGE = "sha256:" + "b" * 64
ARCHIVE = "c" * 64
RETEST_JOB = "fedcba9876543210"


def main() -> None:
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError("pinned Python VM builder source changed")
    root = Path("/var/lib/hol-gauntlet/builds") / JOB
    profile = "hol-gauntlet-build-" + JOB
    cases = [
        ("v348_12g", "v3.48.0", 12, None, False),
        ("v349_16g", "v3.49.0", 16, None, False),
        ("local_alpha", "local-" + SHA, 12, "3.50.0a1", False),
        ("local_retest", "local-" + SHA, 12, "3.50.0a1", True),
    ]
    rows = []
    for name, tag, memory, version, retest in cases:
        argv = vm_build.container_command(
            IMAGE, JOB, SHA, tag, root, memory,
            local_version=version, profile=profile, retest=retest,
        )
        rows.append({"name": name, "image_id": IMAGE, "job_id": JOB,
                     "source_sha": SHA, "source_archive_sha256": ARCHIVE,
                     "tag": tag, "memory_gib": memory,
                     "local_version": version,
                     "retest_build_job_id": RETEST_JOB if retest else None,
                     "argv": argv})
    for name, memory in [("zero_memory", 0), ("too_much_memory", 129),
                         ("boolean_memory", True), ("fractional_memory", 12.5)]:
        try:
            vm_build.container_command(IMAGE, JOB, SHA, "v3.48.0", root, memory,
                                       profile=profile)
        except ValueError as error:
            rows.append({"name": name, "memory": memory, "refusal": str(error)})
        else:
            raise AssertionError(name)
    print(json.dumps({"schema": "gauntlet-builder-run-fixtures.v1",
                      "source_sha256": SOURCE_SHA256, "cases": rows},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

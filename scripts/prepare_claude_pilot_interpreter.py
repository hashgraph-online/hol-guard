"""Create an owned source-conformance interpreter without changing shared Python.

Run under the shared measurement lock. This prepares test infrastructure only;
it neither installs a release artifact nor establishes installed qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import sysconfig
import venv
from pathlib import Path


def identity(path: Path) -> dict[str, object]:
    target = path.resolve(strict=True)
    current = target.stat()
    return {
        "invocation_digest": hashlib.sha256(str(path).encode()).hexdigest(),
        "resolved_digest": hashlib.sha256(str(target).encode()).hexdigest(),
        "invocation_symlink": path.is_symlink(),
        "owner_uid": current.st_uid,
        "owner_class": "current" if current.st_uid == os.getuid() else "root" if current.st_uid == 0 else "other",
        "mode": current.st_mode & 0o777,
        "bytes": current.st_size,
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.directory.exists() or not arguments.directory.is_absolute():
        raise ValueError("claude_pilot_interpreter_requires_new_absolute_directory")
    original = Path(sys.executable)
    before = identity(original)
    venv.EnvBuilder(with_pip=False, symlinks=False, system_site_packages=True).create(arguments.directory)
    copied = arguments.directory / "bin" / "python"
    after = identity(copied)
    # Preserve dependencies of the original test environment. The actual
    # candidate helper still imports its own bound package root under Python-I.
    purelib = arguments.directory / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    (purelib / "claude-conformance-dependencies.pth").write_text(sysconfig.get_path("purelib") + "\n")
    if before["sha256"] != after["sha256"] or identity(original) != before or after["owner_class"] != "current":
        raise RuntimeError("claude_pilot_interpreter_copy_identity_failed")
    report = {
        "schema": "guard-claude-interpreter-fixture.v1",
        "qualification_complete": False,
        "installed_artifact": False,
        "scope": "source_conformance_only",
        "process_uid": os.getuid(),
        "original": before,
        "copied": after,
        "original_unchanged": True,
        "exact_binary_bytes": True,
    }
    arguments.json.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()

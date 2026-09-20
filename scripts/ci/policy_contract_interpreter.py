"""Prepare and verify the owned interpreter used by source contract fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import venv


def prepare() -> None:
    environment = pathlib.Path(".venv")
    assert not environment.exists() and not environment.is_symlink()
    venv.EnvBuilder(with_pip=False, symlinks=False).create(environment)


def verify() -> None:
    selected = pathlib.Path(sys.executable).resolve(strict=True)
    expected = hashlib.sha256(selected.read_bytes()).hexdigest()
    environment = pathlib.Path(".venv").resolve(strict=True)
    interpreters = ("python", "python3", f"python{sys.version_info.major}.{sys.version_info.minor}")
    for name in interpreters:
        interpreter = environment / "bin" / name
        metadata = interpreter.lstat()
        assert stat.S_ISREG(metadata.st_mode) and not interpreter.is_symlink()
        assert metadata.st_uid == os.getuid()
        assert metadata.st_mode & 0o022 == 0 and metadata.st_mode & stat.S_IXUSR
        assert hashlib.sha256(interpreter.read_bytes()).hexdigest() == expected
    probe = subprocess.check_output(
        [
            str(environment / "bin/python"),
            "-I",
            "-c",
            "import json,sys; print(json.dumps([sys.prefix, list(sys.version_info[:3])]))",
        ],
        text=True,
    )
    prefix, version = json.loads(probe)
    assert pathlib.Path(prefix).resolve(strict=True) == environment
    assert version == list(sys.version_info[:3])
    print(json.dumps({"ownedInterpreterVerified": True, "version": version, "sha256": expected}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify"))
    arguments = parser.parse_args()
    if arguments.action == "prepare":
        prepare()
    else:
        verify()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

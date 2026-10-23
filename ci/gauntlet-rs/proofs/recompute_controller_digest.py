"""Independently recompute the Python bootstrap's planned controller digest."""

from __future__ import annotations

import hashlib
import json

from build_controller_install_fixture import selected, source_hashes


def main() -> None:
    files = {path: digest for path, digest in source_hashes().items() if selected(path)}
    directories = {
        "/".join(parts[:depth])
        for path in files
        for parts in [path.split("/")]
        for depth in range(1, len(parts))
    }
    rows = {".": {"mode": 0o755, "uid": 0}}
    rows.update({path: {"mode": 0o755, "uid": 0} for path in directories})
    rows.update({path: {"mode": 0o444, "uid": 0, "sha256": digest}
                 for path, digest in files.items()})
    if len(rows) != 1 + len(directories) + len(files):
        raise ValueError("controller source file conflicts with a directory")
    canonical = json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    print(json.dumps({
        "files": len(files),
        "directories": len(directories),
        "entries": len(rows) - 1,
        "tree_digest": hashlib.sha256(canonical).hexdigest(),
    }, sort_keys=True))


if __name__ == "__main__":
    main()

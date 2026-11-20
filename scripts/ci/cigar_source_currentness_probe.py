"""Disposable macOS probe: kqueue/metadata do not attest mutable file bytes.

This is diagnostic tooling, never runtime authority. It creates only its named
new scratch directory and keeps the observed result for inspection.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import sys
from contextlib import closing
from pathlib import Path


def stamp(path: Path) -> tuple[int, ...]:
    value = path.stat()
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_nlink,
    )


def run(scratch: Path) -> dict[str, object]:
    if sys.platform != "darwin" or not hasattr(select, "kqueue"):
        raise RuntimeError("macOS kqueue probe requires a native macOS interpreter")
    if not scratch.is_absolute() or scratch.parent.resolve() != scratch.parent:
        raise ValueError("scratch parent must be an existing canonical absolute path")
    scratch.mkdir(mode=0o700)
    document = scratch / "public-doc.md"
    document.write_bytes(b"Reviewed public project note.\n")
    code = (
        "import mmap,sys,signal\nsignal.alarm(10)\n"
        "with open(sys.argv[1], 'r+b') as f:\n"
        " m=mmap.mmap(f.fileno(),0)\n"
        " print('mapped',flush=True)\n"
        " sys.stdin.readline()\n"
        " m[0:1]=b'X'\n"
        " print('changed',flush=True)\n"
        " sys.stdin.readline()\n"
        " m.close()\n"
    )
    with subprocess.Popen(
        [sys.executable, "-I", "-S", "-c", code, str(document)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as child:
        assert child.stdin is not None and child.stdout is not None
        try:
            if child.stdout.readline().strip() != "mapped":
                raise RuntimeError("probe child failed to map fixture")
            with document.open("rb") as file, closing(select.kqueue()) as queue:
                before = stamp(document)
                flags = (
                    select.KQ_NOTE_WRITE
                    | select.KQ_NOTE_EXTEND
                    | select.KQ_NOTE_ATTRIB
                    | select.KQ_NOTE_RENAME
                    | select.KQ_NOTE_DELETE
                    | select.KQ_NOTE_LINK
                    | select.KQ_NOTE_REVOKE
                )
                queue.control(
                    [
                        select.kevent(
                            file.fileno(),
                            filter=select.KQ_FILTER_VNODE,
                            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                            fflags=flags,
                        )
                    ],
                    0,
                    0,
                )
                child.stdin.write("write\n")
                child.stdin.flush()
                if child.stdout.readline().strip() != "changed":
                    raise RuntimeError("probe child failed to mutate fixture")
                # Check observations before reading bytes or allowing msync/close.
                after = stamp(document)
                pinned = os.fstat(file.fileno())
                events = queue.control([], 1, 0)
                changed = document.read_bytes() != b"Reviewed public project note.\n"
                result = {
                    "schema": "guard-cigar-source-currentness-probe.v1",
                    "platform": sys.platform,
                    "mutation": "shared_mmap_write_before_flush_or_mapping_close",
                    "bytes_changed": changed,
                    "metadata_changed": before != after,
                    "pinned_mtime_changed": pinned.st_mtime_ns != before[3],
                    "kernel_event_observed": bool(events),
                    "observations_prove_current_bytes": False,
                    "runtime_source_witness_shipped": False,
                }
            child.stdin.write("close\n")
            child.stdin.flush()
            if child.wait(timeout=5) != 0:
                raise RuntimeError("probe child failed to exit")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    (scratch / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-dir", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.scratch_dir), indent=2))


if __name__ == "__main__":
    main()

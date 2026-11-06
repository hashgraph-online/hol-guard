"""Turn raw SFRS recorder output into the committed parity vector files.

Usage: ``sfrs_vector_finalize.py RAW.jsonl OUT_DIR ROOT [--failed FAILED_IDS.txt]
[--extra RAW:ROOT:FAILED]...``. Each ``--extra`` adds a recording made below its own root
with its own failed-test list.

* Drops calls recorded by failed tests and calls that leak host identity.
* Verifies every captured SHA-256 pre-image reproduces its digest.
* Renames each test directory to ``<SFRS_ROOT>/v<N>`` and keeps, per vector, only
  the digests whose pre-image changes with that prefix so replay can recompute
  them below its own root.
* Deduplicates identical calls and writes one file per entry point.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

TOKEN = "<SFRS_ROOT>"
HOST_MARKERS = ("michaelkantor", "runner2-port", "hol-guard/.venv", "/home/runner", "/var/folders")
MAX_VECTORS_PER_ENTRY = 4000
MAX_RESULT_BYTES = 60000


def _load_failed(path: str | None) -> set[str]:
    if path is None:
        return set()
    failed: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.startswith("FAILED ") or line.startswith("ERROR "):
            failed.add(line.split(" ", 1)[1].split(" - ")[0].strip())
    return failed


def _check_digests(sha: dict[str, list[object]]) -> bool:
    for digest, (_order, preimage) in sha.items():
        # A ``None`` pre-image is a digest the recorder could not capture in full.
        if preimage is None or hashlib.sha256(str(preimage).encode("utf-8")).hexdigest() != digest:
            return False
    return True


NATIVE_KEY_PATTERN = re.compile(r'"shell_execution_context_hash": "(?:sha256:)?([0-9a-f]{64})"')


def _strip_native(value: object) -> object:
    """Drop resident binding payloads; their hashes are late-bound at replay."""

    if isinstance(value, dict):
        return {
            key: _strip_native(item)
            for key, item in value.items()
            if not (key == "native" and isinstance(item, dict) and item.get("$type") == "_NativeBinding")
        }
    if isinstance(value, list):
        return [_strip_native(item) for item in value]
    return value


def _changing_digests(
    sha: dict[str, list[object]], root: str, native: set[str]
) -> list[tuple[str, str]]:
    changing: dict[str, str] = {}
    ordered = sorted(sha.items(), key=lambda item: int(item[1][0]))  # type: ignore[call-overload]
    for digest, (_order, preimage) in ordered:
        text = str(preimage)
        depends_on_earlier = any(_mentions_digest(text, earlier) for earlier in changing)
        if root in text or depends_on_earlier or any(value in text for value in native):
            changing[digest] = text
    return list(changing.items())


def _mentions_digest(text: str, digest: str) -> bool:
    """Whether ``text`` carries ``digest`` in full or as a shortened hex prefix."""

    return any(digest.startswith(run) for run in re.findall(r"[0-9a-f]{8,64}", text))


def _prefix_lengths(text: str, digest: str) -> list[int]:
    lengths: set[int] = set()
    for run in re.findall(r"[0-9a-f]{8,64}", text):
        if digest.startswith(run):
            lengths.add(len(run))
    return sorted(lengths)


def main(argv: list[str]) -> int:
    out_dir = Path(argv[2])
    sources = [(argv[1], argv[3], argv[argv.index("--failed") + 1] if "--failed" in argv else None)]
    for index, value in enumerate(argv):
        if value == "--extra":
            raw_path, extra_root, failed_path = argv[index + 1].split(":")
            sources.append((raw_path, extra_root, failed_path))
    out_dir.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    per_entry: dict[str, list[dict[str, object]]] = defaultdict(list)
    counters: dict[str, int] = defaultdict(int)
    dropped: dict[str, int] = defaultdict(int)
    lines = []
    for raw_path, source_root, failed_path in sources:
        failed_ids = _load_failed(failed_path)
        lines += [(source_root, failed_ids, raw) for raw in Path(raw_path).read_text(encoding="utf-8").splitlines()]
    for root, failed, raw in lines:
        record = json.loads(raw)
        entry = str(record["entry"])
        if str(record["test"]) in failed:
            dropped["failed-test"] += 1
            continue
        if not _check_digests(record["sha"]):
            dropped["digest-preimage-mismatch"] += 1
            continue
        for field in ("args", "result", "evaluation"):
            record[field] = _strip_native(record[field])
        native = set(NATIVE_KEY_PATTERN.findall(json.dumps([record["args"], record["result"], record["evaluation"]])))
        changing = _changing_digests(record["sha"], root, native)
        snapshot = record["snapshot"]
        test_dir = None
        if snapshot is not None:
            test_dir = f"{root}/{snapshot['dir']}"
        else:
            match = re.search(re.escape(root) + r"/([^/\"\\]+)", json.dumps(record["args"]))
            test_dir = f"{root}/{match.group(1)}" if match else None
        body = {
            "args": record["args"],
            "result": record["result"],
            "env": record["env"],
            "snapshot": snapshot,
            "evaluation": record["evaluation"],
            "digests": [{"digest": d, "preimage": p} for d, p in changing],
        }
        text = json.dumps(body, sort_keys=True)
        if test_dir is not None:
            text = text.replace(test_dir, TOKEN + "/@@DIR@@")
        text = re.sub(re.escape(root) + r"(?![A-Za-z0-9_.-])", lambda _match: TOKEN, text)
        for position, value in enumerate(sorted(native)):
            text = text.replace(value, f"<NATIVE_HASH:{position}>")
        if any(marker in text for marker in HOST_MARKERS):
            dropped["host-identity"] += 1
            continue
        key_text = text
        for position, (digest, _preimage) in enumerate(changing):
            for length in sorted({64, *_prefix_lengths(text, digest)}, reverse=True):
                key_text = key_text.replace(digest[:length], f"<D{position}:{length}>")
        key = entry + "\n" + key_text
        if key in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(key)
        if len(json.dumps(body["result"])) > MAX_RESULT_BYTES:
            dropped["oversized"] += 1
            continue
        if len(per_entry[entry]) >= MAX_VECTORS_PER_ENTRY:
            dropped["entry-cap"] += 1
            continue
        index = counters[entry]
        counters[entry] += 1
        text = text.replace("@@DIR@@", f"v{index}")
        vector = json.loads(text)
        vector["id"] = f"{entry}-{index}"
        vector["host_dependent"] = bool(
            re.search(r"interpreter_executable_identities\"\s*:\s*\[\s*\{", json.dumps(record["result"]))
        )
        for item in vector["digests"]:
            item["prefix_lengths"] = _prefix_lengths(text, item["digest"])
        vector["dir"] = f"v{index}"
        per_entry[entry].append(vector)
    for entry, vectors in per_entry.items():
        payload = {"schema": "sfrs-vectors.v1", "entry": entry, "root_token": TOKEN, "vectors": vectors}
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        (out_dir / f"{entry.lstrip('_')}.json.gz").write_bytes(gzip.compress(encoded, compresslevel=9, mtime=0))
    summary = {entry: len(vectors) for entry, vectors in per_entry.items()}
    sys.stderr.write(f"vectors: {summary}\ndropped: {dict(dropped)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

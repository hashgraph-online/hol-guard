"""Read candidate Git blobs as data; privileged validation never checks out PR code."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from .source_identity import SHA

PREFIX = "ci/gauntlet/"
LOCK = "ci/pi-exact-continuation/package-lock.json"


def source_manifest(api: Any, source: str, candidate: str) -> dict[str, Any]:
    """Resolve immutable source bytes through GitHub without importing candidate files."""
    if SHA.fullmatch(source) is None or SHA.fullmatch(candidate) is None:
        raise ValueError("manifest inputs must be full commit identities")
    commit = api.request("/git/commits/" + source)
    if commit.get("sha") != source:
        raise ValueError("GitHub returned a different source commit")
    parents = [row.get("sha") for row in commit.get("parents", [])]
    if any(not isinstance(parent, str) or SHA.fullmatch(parent) is None for parent in parents):
        raise ValueError("GitHub returned malformed source parents")
    if source != candidate and (len(parents) != 2 or candidate not in parents):
        raise ValueError("source is not the candidate or its exact two-parent test merge")
    rows = api.request("/contents/ci/gauntlet?ref=" + source)
    if not isinstance(rows, list) or not 1 <= len(rows) <= 64:
        raise ValueError("candidate Gauntlet directory inventory is missing or exceeds its bound")
    runner = {}
    catalog_json = None
    for row in rows:
        name = row.get("name")
        if (
            row.get("type") != "file"
            or not isinstance(name, str)
            or "/" in name
            or "\\" in name
            or row.get("path") != PREFIX + name
            or name in runner
        ):
            raise ValueError("candidate Gauntlet entries must be unique ordinary files")
        raw = blob_bytes(api, row["sha"])
        runner[name] = hashlib.sha256(raw).hexdigest()
        if name == "scenarios.json":
            catalog_json = raw.decode("utf-8")
    if catalog_json is None:
        raise ValueError("candidate scenario catalog is missing")
    lock = api.request("/contents/" + LOCK + "?ref=" + source)
    if not isinstance(lock, dict) or lock.get("type") != "file" or lock.get("path") != LOCK:
        raise ValueError("candidate SDK lock is not an ordinary file")
    return {
        "schema": "hol.guard-gauntlet.github-source.v1",
        "candidate_sha": candidate,
        "tested_source_sha": source,
        "source_parents": parents,
        "tested_base_sha": next((p for p in parents if p != candidate), None) if source != candidate else None,
        "source_dirty": False,
        "runner_files": runner,
        "catalog_json": catalog_json,
        "sdk_lock_sha256": blob_digest(api, lock["sha"]),
    }


def blob_digest(api: Any, sha: str) -> str:
    """Hash a bounded immutable Git blob for evidence comparison."""
    return hashlib.sha256(blob_bytes(api, sha)).hexdigest()


def blob_bytes(api: Any, sha: str) -> bytes:
    """Read immutable candidate bytes as data, never executable imports."""
    if not isinstance(sha, str) or SHA.fullmatch(sha) is None:
        raise ValueError("invalid Git blob identity")
    blob = api.request("/git/blobs/" + sha)
    size = blob.get("size")
    content = blob.get("content")
    if (
        blob.get("sha") != sha
        or blob.get("encoding") != "base64"
        or type(size) is not int
        or not 0 <= size <= 2_000_000
        or not isinstance(content, str)
        or len(content) > 3_000_000
    ):
        raise ValueError("Git blob response has an invalid identity, encoding or size")
    raw = base64.b64decode("".join(content.split()), validate=True)
    if len(raw) != size:
        raise ValueError("Git blob length does not match its metadata")
    return raw

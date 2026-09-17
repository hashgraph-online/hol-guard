"""Bounded local test-runner options and Bun registry lock entries."""

from __future__ import annotations

import re

from .package_evidence_common import object_mapping, valid_sha512_integrity

_STDOUT_REPORTERS = frozenset({"default", "dot", "verbose", "basic"})


def vitest_result_arguments(tail: tuple[str, ...]) -> tuple[tuple[str, ...], bool]:
    if not tail or tail[0] != "run":
        return (), False
    files: list[str] = []
    seen: set[str] = set()
    index = 1
    while index < len(tail):
        token = tail[index]
        if token == "--no-coverage":
            if token in seen:
                return (), False
            seen.add(token)
        elif token == "--reporter" or token.startswith("--reporter="):
            if "reporter" in seen:
                return (), False
            seen.add("reporter")
            if token == "--reporter":
                index += 1
                if index >= len(tail):
                    return (), False
                reporter = tail[index]
            else:
                reporter = token.partition("=")[2]
            if reporter not in _STDOUT_REPORTERS:
                return (), False
        elif token.startswith("-"):
            return (), False
        else:
            files.append(token)
        index += 1
    return tuple(files), bool(files)


def bun_locked_version(payload: dict[str, object] | None, package: str) -> tuple[str | None, bool]:
    if payload is None or type(payload.get("lockfileVersion")) is not int or payload["lockfileVersion"] not in {0, 1}:
        return None, False
    packages = object_mapping(payload.get("packages"))
    item = packages.get(package) if packages is not None else None
    if not isinstance(item, list) or len(item) != 4:
        return None, False
    name_version, source, metadata, integrity = item
    if not isinstance(name_version, str) or not name_version.startswith(f"{package}@"):
        return None, False
    version = name_version[len(package) + 1 :]
    if re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
        return None, False
    # Empty registry source is Bun's canonical npm registry entry. Local,
    # Git, aliased and custom-registry resolutions retain normal review.
    return version, source == "" and object_mapping(metadata) is not None and valid_sha512_integrity(integrity)

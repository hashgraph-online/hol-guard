#!/usr/bin/env python3
"""Export the public extension directory from trusted canonical source, without network I/O."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import checked_path, object_value, parse_json, read_bytes
from codex_plugin_scanner.guard.extension_builder.listing import (
    DEFAULT_LIMITATIONS,
    MAX_TAGLINE_LENGTH,
    category_for_extension,
    validate_listing,
)
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_contribution import validate_contribution
from codex_plugin_scanner.guard.runtime.extension_directory_operations import public_operations
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import (
    catalog_id_for_mcp_id,
    validate_mcp_contribution,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_V1 = ROOT / "docs/guard/extensions/catalog.v1.json"
OUTPUT_V2 = ROOT / "docs/guard/extensions/catalog.v2.json"
# Retained for existing callers that intentionally address the v1 artifact.
OUTPUT = OUTPUT_V1
MAX_ENTRIES = 512
MAX_SOURCE_BYTES = 1_048_576
MAX_CATALOG_BYTES = 1_048_576
MIN_SUMMARY_LENGTH = 20
MAX_SUMMARY_LENGTH = 2_048


def _sources(root: Path) -> dict[str, tuple[str, dict[str, object], str]]:
    result: dict[str, tuple[str, dict[str, object], str]] = {}
    for directory, validate in (
        ("extensions", validate_contribution),
        ("mcp-servers", validate_mcp_contribution),
    ):
        parent = checked_path(root / "contributions" / directory)
        for path in sorted(parent.glob("*.json")):
            content = read_bytes(path, limit=MAX_SOURCE_BYTES)
            payload = object_value(parse_json(content))
            validate(payload, filename=path.name)
            extension_id = str(payload["id"])
            if path.name != f"{extension_id}.json" or extension_id in result:
                raise ValueError("Contribution identity is duplicated or does not match its filename")
            result[extension_id] = (
                path.relative_to(root).as_posix(),
                payload,
                "sha256:" + hashlib.sha256(content).hexdigest(),
            )
            if len(result) > MAX_ENTRIES:
                raise ValueError("Public directory source count exceeds its budget")
    return result


def _listings(
    root: Path, sources: dict[str, tuple[str, dict[str, object], str]]
) -> dict[str, tuple[str, dict[str, object], str]]:
    result: dict[str, tuple[str, dict[str, object], str]] = {}
    parent = checked_path(root / "contributions/extension-listings")
    if not parent.exists():
        return result
    paths = sorted(parent.glob("*.json"))
    if len(paths) > MAX_ENTRIES:
        raise ValueError("Listing count exceeds its budget")
    for path in paths:
        extension_id = path.stem
        if extension_id not in sources:
            raise ValueError("A listing must belong to an existing external native contribution")
        content = read_bytes(path, limit=MAX_SOURCE_BYTES)
        result[extension_id] = (
            path.relative_to(root).as_posix(),
            validate_listing(parse_json(content), expected_id=extension_id),
            "sha256:" + hashlib.sha256(content).hexdigest(),
        )
    return result


def _command_source_bytes(root: Path) -> dict[str, bytes]:
    parent = checked_path(root / "contributions/command-sources")
    result: dict[str, bytes] = {}
    for path in sorted(parent.glob("command.*.json")):
        relative_path = path.relative_to(root).as_posix()
        result[relative_path] = read_bytes(path, limit=MAX_SOURCE_BYTES)
    return result


def _snapshot(
    root: Path,
) -> tuple[
    dict[str, tuple[str, dict[str, object], str]],
    dict[str, tuple[str, dict[str, object], str]],
    dict[str, bytes],
]:
    sources = _sources(root)
    return sources, _listings(root, sources), _command_source_bytes(root)


def _authoring_source(
    extension_id: str, contribution: dict[str, object], command_sources: dict[str, bytes]
) -> dict[str, object]:
    native = contribution.get("nativeSource")
    if not isinstance(native, dict):
        raise ValueError("A command directory entry must have generated native source evidence")
    path = native.get("path")
    digest = native.get("digest")
    schema = native.get("schemaVersion")
    expected_path = f"contributions/command-sources/{extension_id}.json"
    if (
        schema != "guard.command-extension-source.v1"
        or path != expected_path
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("Generated native source evidence is invalid")
    content = command_sources.get(expected_path)
    if content is None:
        raise ValueError("Generated native source evidence is missing its command source")
    return {
        "schemaVersion": schema,
        "path": expected_path,
        "byteDigest": "sha256:" + hashlib.sha256(content).hexdigest(),
        "nativeDigest": digest,
    }


def _summary_for(listing: dict[str, object], entry: dict[str, object]) -> str:
    """Keep v2's required public summary valid when an older listing has none."""

    summary = listing.get("summary")
    if isinstance(summary, str):
        return summary
    description = entry["description"]
    if (
        isinstance(description, str)
        and MIN_SUMMARY_LENGTH <= len(description) <= MAX_SUMMARY_LENGTH
        and description == description.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in description)
    ):
        return description
    return f"Reviewed Guard coverage for {entry['id']}."


def _export_directory(
    sources: dict[str, tuple[str, dict[str, object], str]],
    listing_sources: dict[str, tuple[str, dict[str, object], str]],
) -> dict[str, object]:
    listings = {extension_id: item[1] for extension_id, item in listing_sources.items()}
    mcp_ids = {catalog_id_for_mcp_id(key): key for key in sources if key.startswith("mcp.")}
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for native in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions:
        extension_id = mcp_ids.get(native.extension_id, native.extension_id)
        source = sources.get(extension_id)
        payload: dict[str, object] = source[1] if source else {}
        listing = listings.get(extension_id, {})
        external = trust_class_for(native.extension_id) == "external"
        if external and source is None:
            raise ValueError("An external native extension must have a canonical contribution source")
        if native.required:
            model = "required"
        elif native.delegated_protection == "package-firewall":
            model = "package-firewall"
        elif external:
            model = "external-opt-in"
        else:
            model = "built-in"
        description = str(payload.get("description", native.description))
        entries.append(
            {
                "id": extension_id,
                "runtimeExtensionId": native.extension_id,
                "kind": "mcp" if extension_id.startswith("mcp.") else "command",
                "version": native.version,
                "name": str(payload.get("name", native.name)),
                "description": description,
                "tagline": listing.get("tagline", description[:MAX_TAGLINE_LENGTH].rstrip()),
                "category": listing.get("category", category_for_extension(extension_id)),
                "tags": listing.get("tags", []),
                "limitations": listing.get("limitations", list(DEFAULT_LIMITATIONS)),
                "documentationUrl": listing.get(
                    "documentationUrl",
                    "https://github.com/hashgraph-online/hol-guard/blob/main/docs/guard/extensions/README.md",
                ),
                "protectionModel": model,
                "trustClass": trust_class_for(native.extension_id),
                "claimPolicy": "provenance" if external else "project",
                "maintainerGithubIds": listing.get("maintainerGithubIds", []),
                "sourcePath": source[0]
                if source
                else "src/codex_plugin_scanner/guard/runtime/command_builtin_extension_registry.py",
                "contributionDigest": source[2] if source else None,
                "executables": list(native.executables),
                "actionClasses": list(native.action_classes),
                "ruleCount": len(native.rules),
                "permissionCount": len(native.permissions),
                "toolStates": payload.get("tools", []),
                "operations": public_operations(native),
            }
        )
        seen.add(extension_id)
    if set(sources) - seen:
        raise ValueError("A source contribution is absent from the canonical native registry")
    if len(entries) > MAX_ENTRIES or len(seen) != len(entries):
        raise ValueError("Public directory has duplicate or excessive entries")
    return {
        "schemaVersion": "guard.extension-directory.v1",
        "entries": sorted(entries, key=lambda item: str(item["id"])),
    }


def export_directory(root: Path = ROOT) -> dict[str, object]:
    sources, listing_sources, _ = _snapshot(root)
    return _export_directory(sources, listing_sources)


def _export_directory_v2(
    v1: dict[str, object],
    sources: dict[str, tuple[str, dict[str, object], str]],
    listings: dict[str, tuple[str, dict[str, object], str]],
    command_sources: dict[str, bytes],
) -> dict[str, object]:
    """Project v2 public metadata without changing the v1 claim source binding."""

    entries: list[dict[str, object]] = []
    for v1_entry in v1["entries"]:
        entry = dict(v1_entry)
        extension_id = str(entry["id"])
        source = sources.get(extension_id)
        listing_source = listings.get(extension_id)
        listing = listing_source[1] if listing_source else {}
        entry.update(
            {
                "summary": _summary_for(listing, entry),
                "contributors": listing.get("contributors", []),
                "originalContributions": listing.get("originalContributions", []),
                "upstream": listing.get("upstream", None),
                "listing": ({"path": listing_source[0], "digest": listing_source[2]} if listing_source else None),
                "authoringSource": (
                    _authoring_source(extension_id, source[1], command_sources)
                    if entry["kind"] == "command" and source is not None
                    else None
                ),
            }
        )
        if entry["kind"] == "command" and entry["authoringSource"] is None:
            raise ValueError("A command directory entry is missing native authoring evidence")
        entries.append(entry)
    return {
        "schemaVersion": "guard.extension-directory.v2",
        "entries": entries,
    }


def export_directory_v2(root: Path = ROOT) -> dict[str, object]:
    sources, listing_sources, command_sources = _snapshot(root)
    return _export_directory_v2(_export_directory(sources, listing_sources), sources, listing_sources, command_sources)


def _render(payload: dict[str, object]) -> str:
    rendered = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    if len(rendered.encode("utf-8")) > MAX_CATALOG_BYTES:
        raise ValueError("Public directory exceeds its byte budget")
    return rendered


def render_directories(root: Path = ROOT) -> dict[Path, str]:
    """Render both public versions from one validated source snapshot."""

    sources, listing_sources, command_sources = _snapshot(root)
    v1 = _export_directory(sources, listing_sources)
    v2 = _export_directory_v2(v1, sources, listing_sources, command_sources)
    return {OUTPUT_V1: _render(v1), OUTPUT_V2: _render(v2)}


def render_directory(root: Path = ROOT) -> str:
    return _render(export_directory(root))


def render_directory_v2(root: Path = ROOT) -> str:
    return _render(export_directory_v2(root))


def write_catalog(path: Path, rendered: str) -> None:
    """Stage complete bytes and replace a checked regular output, never truncate through a link."""
    target = checked_path(path)
    parent = checked_path(target.parent)
    if not parent.is_dir():
        raise ValueError("The catalog output parent must be an existing directory")
    if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
        raise ValueError("The catalog output must be a regular file")
    content = rendered.encode("utf-8")
    if len(content) > MAX_CATALOG_BYTES:
        raise ValueError("Public directory exceeds its byte budget")
    descriptor, name = tempfile.mkstemp(prefix=".guard-catalog-", dir=parent)
    staged = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(staged, 0o644)
        _ = checked_path(parent)
        _ = checked_path(staged)
        _ = checked_path(target)
        if target.exists() and not stat.S_ISREG(target.lstat().st_mode):
            raise ValueError("The catalog output changed to a non-regular file")
        os.replace(staged, target)
    finally:
        if staged.exists():
            checked_path(staged).unlink()


def claim_readiness(root: Path = ROOT) -> dict[str, object]:
    """Read-only invitation-readiness signal for the exported directory.

    A valid runtime contribution with an empty accepted claimant set is NOT
    invitation-eligible: the claim server requires accepted numeric GitHub IDs
    from a merged listing sidecar. This report never grants authority.
    """

    entries: list[dict[str, object]] = []
    for entry in export_directory(root)["entries"]:
        claim_policy = str(entry["claimPolicy"])
        accepted_ids = list(entry["maintainerGithubIds"])  # type: ignore[arg-type]
        if claim_policy != "provenance":
            reason = "project_policy"
        elif accepted_ids:
            reason = "eligible"
        else:
            reason = "empty_accepted_set"
        entries.append(
            {
                "id": entry["id"],
                "claimPolicy": claim_policy,
                "acceptedGithubIdCount": len(accepted_ids),
                "invitationEligible": claim_policy == "provenance" and bool(accepted_ids),
                "reason": reason,
            }
        )
    return {
        "schemaVersion": "guard.extension-claim-readiness.v1",
        "entries": entries,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--check", action="store_true")
    _ = parser.add_argument(
        "--readiness",
        action="store_true",
        help="Print a read-only claim-invitation readiness report instead of writing the catalog.",
    )
    args = parser.parse_args(argv)
    try:
        if args.readiness:
            print(json.dumps(claim_readiness(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
            return 0
        rendered = render_directories()
        if args.check:
            if any(
                read_bytes(path, limit=MAX_CATALOG_BYTES) != content.encode("utf-8")
                for path, content in rendered.items()
            ):
                parser.error("Extension catalog is stale; run python scripts/export_extension_directory.py")
        else:
            for path, content in rendered.items():
                write_catalog(path, content)
    except (BuilderError, OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

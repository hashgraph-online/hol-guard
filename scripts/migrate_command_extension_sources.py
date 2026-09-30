#!/usr/bin/env python3
"""One-time reviewed-baseline JSON migration; never imports detector/PR Python.

This is development tooling, not a production catalog producer. The Rust source
compiler validates every output. Use a fresh output directory, inspect the report,
and qualify native behavior before moving any generated file into production.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
SOURCE_SCHEMA = "guard.command-extension-source.v1"
MANIFEST = "migration-manifest.json"


def encode(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f"invalid bounded JSON input: {path.name}")
    value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def convert(inventory: dict, program: dict, schema: dict, descriptors: dict) -> list[dict]:
    """Recover canonical inline trees from reviewed content-addressed native data."""
    if program["program_digest"] != inventory["identity"]["program_digest"]:
        raise ValueError("baseline program identity mismatch")
    rules = {rule["rule_id"]: rule for rule in program["rules"]}
    if len(rules) != len(program["rules"]):
        raise ValueError("duplicate baseline rule IDs")
    mcp = {row["extension_id"] for row in program["extensions"] if row["mcp"] is not None}
    fields = schema["properties"]["extension"]["properties"]
    seen_extensions: set[str] = set()
    seen_rules: set[str] = set()
    expanded_nodes = 0

    def inline(identity: str, ancestors: tuple[str, ...] = ()) -> dict:
        nonlocal expanded_nodes
        expanded_nodes += 1
        if expanded_nodes > 16_384:
            raise ValueError("baseline inline expansion exceeds native node budget")
        if identity in ancestors or len(ancestors) > 32:
            raise ValueError(f"cyclic/out-of-depth baseline node: {identity}")
        node = program["nodes"][identity]
        result = {"op": node["op"], "config": node["config"]}
        for field, value in node["children"].items():
            if field not in {"matchers", "producer", "consumer"}:
                raise ValueError(f"unsupported native child: {identity}/{field}")
            ancestors_next = (*ancestors, identity)
            result[field] = (
                [inline(child, ancestors_next) for child in value]
                if isinstance(value, list)
                else inline(value, ancestors_next)
            )
        return result

    sources = []
    for row in inventory["catalog"]:
        identity = row["extension_id"]
        if identity in seen_extensions or not re.fullmatch(r"command\.[a-z0-9][a-z0-9.-]*", identity):
            raise ValueError(f"duplicate/invalid baseline extension ID: {identity}")
        seen_extensions.add(identity)
        if identity in mcp:
            continue
        extension = {
            key: row[key] for key in fields if key not in {"permissions", "rules", "publisher", "homepage", "license"}
        }
        descriptor = descriptors.get(identity, {})
        extension.update(homepage=descriptor.get("homepage"), license=descriptor.get("license"), publisher=None)
        if row["trust_class"] == "external":
            publisher = row["publisher"]
            extension["publisher"] = {
                "id": publisher["id"],
                "display_name": publisher["displayName"],
                "url": publisher.get("url"),
            }
        extension["permissions"] = [
            {key: permission[key] for key in fields["permissions"]["items"]["properties"]}
            for permission in row["permissions"]
        ]
        extension["rules"] = []
        for rule in row["rules"]:
            rule_id = rule["rule_id"]
            if rule_id in seen_rules or rules[rule_id]["extension_id"] != identity:
                raise ValueError(f"duplicate/misowned baseline rule: {rule_id}")
            seen_rules.add(rule_id)
            native = rules[rule_id]
            converted = {
                key: rule[key]
                for key in fields["rules"]["items"]["properties"]
                if key not in {"permission_id", "matcher", "native_capability", "safe_variants"}
            }
            converted.update(
                permission_id=native["permission_id"],
                matcher=inline(native["matcher"]) if native["matcher"] else None,
                native_capability=None if native["matcher"] else rule_id + ".v1",
            )
            variants = {variant["variant_id"]: variant for variant in native["safe_variants"]}
            if len(variants) != len(native["safe_variants"]):
                raise ValueError(f"duplicate baseline variant: {rule_id}")
            converted["safe_variants"] = [
                {
                    "variant_id": variant["variant_id"],
                    "title": variant["title"],
                    "matcher": inline(variants[variant["variant_id"]]["matcher"]),
                }
                for variant in rule["safe_variants"]
            ]
            extension["rules"].append(converted)
        sources.append({"schema": SOURCE_SCHEMA, "extension": extension})
    if seen_extensions != {row["extension_id"] for row in program["extensions"]} or seen_rules != set(rules):
        raise ValueError("baseline catalog/program ownership mismatch")
    return sorted(sources, key=lambda source: source["extension"]["extension_id"])


def publish(destination: Path, files: dict[str, bytes], provenance: dict) -> None:
    """All conflicts are checked before writing. Repeated identical runs are no-ops.

    Existing owned bytes must equal the requested bytes; this tool deliberately
    does not replace modified output or apply a new migration over an older one.
    """
    if destination.is_symlink():
        raise ValueError("symlink output directory refused")
    manifest = encode(
        {
            "schema": "guard.command-source-migration.v1",
            **provenance,
            "files": {name: digest(data) for name, data in sorted(files.items())},
        }
    )
    wanted = {**files, MANIFEST: manifest}
    for name in wanted:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", name):
            raise ValueError(f"unsafe output name: {name}")
    if destination.exists():
        existing = {path.name for path in destination.iterdir()}
        if existing:
            if existing != set(wanted):
                raise ValueError("output directory contains unrelated or incomplete files")
            for name, data in wanted.items():
                path = destination / name
                if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                    raise ValueError(f"modified output refused: {name}")
            return
    else:
        destination.mkdir(parents=False)
    created: list[Path] = []
    try:
        for name, data in wanted.items():
            path = destination / name
            with path.open("xb") as stream:
                created.append(path)
                stream.write(data)
    except BaseException:
        # Only files created by this call are eligible for rollback.
        for path in reversed(created):
            path.unlink()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="write only after native validation; default is dry-run")
    args = parser.parse_args()
    inventory = load(args.inventory)
    if (
        not re.fullmatch(r"[a-f0-9]{40}", args.expected_source_sha)
        or inventory["source_sha"] != args.expected_source_sha
    ):
        raise ValueError("reviewed baseline source SHA mismatch")
    root = args.repository
    program = load(root / "contracts/extensions/native-command-program.v1.json")
    schema = load(root / "contracts/extensions/command-extension-source.v1.schema.json")
    descriptors = {}
    for path in sorted((root / "contributions/extensions").glob("*.json")):
        descriptor = load(path)
        if descriptor["id"] in descriptors:
            raise ValueError("duplicate descriptor identity")
        descriptors[descriptor["id"]] = descriptor
    sources = convert(inventory, program, schema, descriptors)
    request = {
        "schema": "guard.command-extension-build.v1",
        "sources": sources,
        "mcp_sources": [load(path) for path in sorted((root / "contributions/mcp-servers").glob("*.json"))],
        "trust": load(root / "contracts/extensions/trust-class-map.v1.json"),
    }
    result = subprocess.run(
        [str(args.compiler.resolve(strict=True)), "compile"],
        input=encode(request),
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"native source admission failed: {result.stdout.decode(errors='replace')[:1024]}")
    compiled = json.loads(result.stdout, object_pairs_hook=unique_object)
    files = {source["extension"]["extension_id"] + ".json": encode(source) for source in sources}
    report = {
        "baseline_source_sha": inventory["source_sha"],
        "baseline_program_digest": program["program_digest"],
        "candidate_program_digest": compiled["program"]["program_digest"],
        "native_implementation_digest": compiled["implementation_digest"],
        "source_digest": compiled["source_digest"],
        "command_sources": len(sources),
        "mcp_sources": len(request["mcp_sources"]),
        "status": "native-admitted-not-behaviorally-qualified",
    }
    if args.write:
        publish(args.output, files, report)
    print(json.dumps({**report, "written": args.write}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        raise SystemExit(2) from error

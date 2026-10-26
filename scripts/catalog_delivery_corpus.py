"""Generate deterministic catalog corpora for catalog-delivery benchmarks.

Run with ``uv run --no-sync python scripts/catalog_delivery_corpus.py SOURCE OUT_DIR``.
SOURCE is the native build's ``command-catalog.v1.json`` (the exact envelope
``guard-command`` embeds). OUT_DIR receives one envelope per size plus
``corpora.json`` with each corpus's SHA-256.

Synthetic sizes reuse real extensions in sorted order, so text, permission and
rule counts stay representative. Copies beyond the real set get a suffixed
``extension_id`` and their extension-scoped permission and rule identifiers are
rescoped to it; nothing else changes. Sizes above the admitted 512-extension
limit are labelled ``read_layer_only``: they exist to show where a read layer
would stop, not to claim runtime support, and the native read model refuses
them.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

ADMITTED_EXTENSION_LIMIT = 512
DEFAULT_SIZES = (128, 256, 512, 2_048, 10_000)


def canonical(value: object) -> bytes:
    """Same canonical form as ``GeneratedCommandCatalog.catalog_digest``."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _rescoped(value: object, prefix: str, replacement: str) -> object:
    if isinstance(value, str):
        return replacement + value[len(prefix) :] if value.startswith(prefix) else value
    if isinstance(value, list):
        return [_rescoped(item, prefix, replacement) for item in value]
    if isinstance(value, dict):
        return {key: _rescoped(item, prefix, replacement) for key, item in value.items()}
    return value


def _renamed(extension: dict[str, object], suffix: str) -> dict[str, object]:
    original = str(extension["extension_id"])
    extension_id = f"{original}-{suffix}"
    # Permission and rule identities are scoped by extension ("<id>.permission.x");
    # rescope every such reference so copies stay catalog-unique and internally
    # consistent (implied permissions, dependencies, rule links).
    clone = _rescoped(copy.deepcopy(extension), f"{original}.", f"{extension_id}.")
    assert isinstance(clone, dict)
    clone["extension_id"] = extension_id
    for permission in clone.get("permissions", []):
        if isinstance(permission, dict):
            permission["extension_id"] = extension_id
    return clone


def synthetic_catalog(real: list[dict[str, object]], size: int) -> list[dict[str, object]]:
    ordered = sorted(real, key=lambda extension: str(extension["extension_id"]))
    catalog: list[dict[str, object]] = []
    for index in range(size):
        source = ordered[index % len(ordered)]
        copy_number = index // len(ordered)
        catalog.append(copy.deepcopy(source) if copy_number == 0 else _renamed(source, f"s{copy_number}"))
    return catalog


def envelope(catalog: list[dict[str, object]], schema: str) -> dict[str, object]:
    return {
        "schema": schema,
        "catalog": catalog,
        "catalog_digest": hashlib.sha256(canonical(catalog)).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--sizes", type=int, nargs="*", default=list(DEFAULT_SIZES))
    args = parser.parse_args()
    source = json.loads(args.source.read_text(encoding="utf-8"))
    real = source["catalog"]
    if hashlib.sha256(canonical(real)).hexdigest() != source["catalog_digest"]:
        raise SystemExit("source catalog digest does not match its canonical form")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    corpora: list[tuple[str, int, list[dict[str, object]]]] = [("actual", len(real), real)]
    corpora += [(f"synthetic-{size}", size, synthetic_catalog(real, size)) for size in args.sizes]
    manifest = []
    for name, size, catalog in corpora:
        body = canonical(envelope(catalog, str(source["schema"])))
        path = args.out_dir / f"{name}.json"
        path.write_bytes(body)
        manifest.append(
            {
                "name": name,
                "extensions": size,
                "path": path.name,
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "read_layer_only": size > ADMITTED_EXTENSION_LIMIT,
            }
        )
    (args.out_dir / "corpora.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

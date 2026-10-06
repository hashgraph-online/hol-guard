"""Refresh maintainer-owned extension outputs without rewriting test expectations.

Keep contributor source, descriptor, trust, intake and directory contracts.
Native compilation derives the embedded program directly from those sources.
The refresh publishes existing catalogs/descriptors. CI records current report
evidence separately; portable fixtures, cryptographic vectors and test code are
independent inputs and are never rewritten here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

TRUST_MAP = ROOT / "contracts/extensions/trust-class-map.v1.json"
TARGET_DIR = ROOT / "rust/target"
COMPILER = TARGET_DIR / "release/guard-command-source"
TOOLCHAIN = "1.88.0"


def _run(command: list[str], *, env: dict[str, str] | None = None) -> str:
    merged = dict(os.environ)
    merged["PYTHONPATH"] = os.pathsep.join([str(ROOT / "src"), str(ROOT), merged.get("PYTHONPATH", "")]).rstrip(
        os.pathsep
    )
    if env:
        merged.update(env)
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, env=merged, timeout=900, check=False)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise SystemExit(f"refresh failed: {' '.join(command)}\n{detail[:2048]}")
    return completed.stdout.strip()


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _read(path: Path) -> dict:
    return json.loads(path.read_text())


def _write_json(path: Path, value: object, *, sort_keys: bool = True) -> bool:
    content = json.dumps(value, indent=2, sort_keys=sort_keys, ensure_ascii=False) + "\n"
    if path.is_file() and path.read_bytes() == content.encode():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return True


def _detector():
    sys.path.insert(0, str(ROOT / "scripts" / "ci"))
    import detect_pending_extension_regen

    return detect_pending_extension_regen


def contribution_ids() -> list[str]:
    """Extension ids declared by in-tree contribution sources."""
    return sorted(_detector().contribution_ids())


def catalog_ids() -> set[str]:
    return _detector().catalog_ids()


def pending_contribution_ids() -> list[str]:
    return sorted(set(contribution_ids()) - catalog_ids())


TRUST_BINDINGS = ROOT / "contracts/extensions/trust"


def _trust_binding_path(extension_id: str) -> Path:
    if not extension_id.startswith("command.") or "/" in extension_id or "\\" in extension_id:
        raise ValueError(f"invalid extension trust binding id {extension_id}")
    return TRUST_BINDINGS / f"{extension_id}.v1.json"


def _trust_binding_index() -> dict[str, str]:
    """Fold authored bindings through the strict runtime parser."""
    sys.path.insert(0, str(ROOT / "src"))
    from codex_plugin_scanner.guard.runtime.extension_trust import trust_binding_index

    return dict(trust_binding_index(TRUST_BINDINGS))


def _read_binding_ids() -> set[str]:
    return set(_trust_binding_index())


def _write_binding(extension_id: str, trust_class: str) -> bool:
    path = _trust_binding_path(extension_id)
    return _write_json(
        path,
        {
            "schemaVersion": "guard.extension-trust-binding.v1",
            "extension": extension_id,
            "trustClass": trust_class,
        },
    )


def _projected_aggregate() -> dict:
    """Fold authored trust bindings into the aggregate-map projection body."""
    sys.path.insert(0, str(ROOT / "src"))
    from codex_plugin_scanner.guard.runtime.extension_trust import trust_map_from_bindings

    return trust_map_from_bindings(TRUST_BINDINGS)


def check_trust_consistency() -> None:
    """Fail if the committed aggregate map drifts from the authored bindings."""
    if TRUST_MAP.is_file() and _read(TRUST_MAP) != _projected_aggregate():
        raise SystemExit(
            "trust-class-map.v1.json is out of sync with contracts/extensions/trust/; "
            "edit the per-extension binding and run `refresh_extension_artifacts.py --trust-only`"
        )


def _sync_aggregate_map() -> bool:
    """Project authored trust bindings into the packaged aggregate map.

    The aggregate still ships to packaged/frozen runtimes and release staging;
    it is generated, never edited by hand.
    """
    return _write_json(TRUST_MAP, _projected_aggregate(), sort_keys=False)


def sync_trust_map() -> bool:
    """Add contribution ids missing a trust binding as ``external`` files.

    Gate on committed-aggregate consistency first: if the generated map was
    hand-edited or is stale, fail instead of silently rewriting it to match the
    bindings. Only after a clean baseline do we add missing bindings and regen.
    """
    check_trust_consistency()
    missing = sorted(set(contribution_ids()) - _read_binding_ids())
    changed = False
    for extension_id in missing:
        if _write_binding(extension_id, "external"):
            changed = True
            print(f"trust binding: added {extension_id} as external", file=sys.stderr)
    if _sync_aggregate_map():
        changed = True
    return changed


def build_source_compiler() -> None:
    """Catalog publication needs the offline compiler, not a second runtime build."""
    _run(
        [
            "cargo",
            f"+{TOOLCHAIN}",
            "build",
            "--locked",
            "--release",
            "--target-dir",
            str(TARGET_DIR),
            "--manifest-path",
            str(ROOT / "rust/Cargo.toml"),
            "-p",
            "guard-command",
            "--bin",
            "guard-command-source",
        ]
    )


def regenerate_projections() -> None:
    """One native build, then project its sources without a rebuild fixpoint."""
    build_source_compiler()
    _run([sys.executable, "scripts/prepare_extension_contribution.py", "--compiler", str(COMPILER)])
    _run([sys.executable, "scripts/prepare_extension_contribution.py", "--check", "--compiler", str(COMPILER)])


def refresh_directory_render() -> None:
    _run([sys.executable, "scripts/render_command_extension_directory.py"])


def verify() -> None:
    _run([sys.executable, "scripts/render_command_extension_directory.py", "--check"])
    _run([sys.executable, "scripts/export_extension_directory.py", "--check"])
    check_trust_consistency()


def main(argv: list[str] | None = None) -> int:
    """Refresh maintainer-owned product artifacts without replacing independent test expectations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trust-only",
        action="store_true",
        help="Stage missing contribution ids as external before dependency installation and native compilation.",
    )
    args = parser.parse_args(argv)
    if args.trust_only:
        changed = sync_trust_map()
        print(json.dumps({"ok": True, "trust_map_changed": changed}, sort_keys=True))
        return 0
    pending = pending_contribution_ids()
    sync_trust_map()
    regenerate_projections()
    refresh_directory_render()
    catalog_digest = _read(ROOT / "contracts/extensions/command-catalog.v1.json")["catalog_digest"]
    verify()
    print(
        json.dumps(
            {
                "ok": True,
                "pending_contributions": pending,
                "catalog_digest": catalog_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

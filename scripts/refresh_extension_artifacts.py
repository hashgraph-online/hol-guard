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

TRUST_MAP = ROOT / "contracts/extensions/build-trust-class-map.v1.json"
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
    """Derive trust inventory from canonical inputs, never published descriptors."""
    return sorted(_detector().contribution_ids(include_legacy=False))


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
    """Fail if a staged aggregate map drifts from the authored bindings."""
    if TRUST_MAP.is_file() and _read(TRUST_MAP) != _projected_aggregate():
        raise SystemExit(
            "build-trust-class-map.v1.json is out of sync with contracts/extensions/trust/; "
            "edit the per-extension binding and run `refresh_extension_artifacts.py --trust-only`"
        )


def _sync_aggregate_map() -> bool:
    """Project authored trust bindings into the packaged aggregate map.

    The aggregate still ships to packaged/frozen runtimes and release staging;
    it is generated, never edited by hand.
    """
    content = _canonical_bytes(_projected_aggregate())
    if TRUST_MAP.is_file() and TRUST_MAP.read_bytes() == content:
        return False
    TRUST_MAP.parent.mkdir(parents=True, exist_ok=True)
    TRUST_MAP.write_bytes(content)
    return True


def check_authored_trust() -> None:
    """Check canonical ownership before CI can create missing defaults."""
    missing = sorted(set(contribution_ids()) - _read_binding_ids())
    if missing:
        raise SystemExit(
            "canonical contributions lack authored trust bindings: "
            + ", ".join(missing)
            + "; run `python scripts/refresh_extension_artifacts.py --trust-only` "
            "and include the new contracts/extensions/trust/*.v1.json files in this PR"
        )


def sync_trust_map() -> bool:
    """Add contribution ids missing a trust binding as ``external`` files.

    Authored bindings are the authority. Legacy aggregate copies can be stale
    after merges; regenerate them without admitting their values into policy.
    """
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
    """Publish current sources without admitting historical fixture snapshots."""
    build_source_compiler()
    for check in ([], ["--check"]):
        _run([sys.executable, "scripts/build_native_command_program.py", "--compiler", str(COMPILER), *check])
        _run([sys.executable, "scripts/export_extension_directory.py", *check])


def refresh_directory_render() -> None:
    _run([sys.executable, "scripts/render_command_extension_directory.py"])


def verify() -> None:
    _run([sys.executable, "scripts/render_command_extension_directory.py", "--check"])
    _run([sys.executable, "scripts/export_extension_directory.py", "--check"])
    check_trust_consistency()


def main(argv: list[str] | None = None) -> int:
    """Refresh maintainer-owned product artifacts without replacing independent test expectations."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--trust-only",
        action="store_true",
        help="Stage missing contribution ids as external before dependency installation and native compilation.",
    )
    mode.add_argument(
        "--check-trust",
        action="store_true",
        help="Check authored bindings for all canonical contributions without generating or changing files.",
    )
    args = parser.parse_args(argv)
    if args.check_trust:
        check_authored_trust()
        print(json.dumps({"ok": True, "authored_trust_complete": True}, sort_keys=True))
        return 0
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

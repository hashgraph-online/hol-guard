"""Refresh maintainer-owned extension outputs without rewriting test expectations.

Keep contributor source, descriptor, trust, intake and directory contracts.
Native compilation derives the embedded program directly from those sources.
The refresh publishes existing catalogs/descriptors. CI records current report
evidence separately; portable fixtures, cryptographic vectors and test code are
independent inputs and are never rewritten here.
"""

from __future__ import annotations

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
    if path.read_bytes() == content.encode():
        return False
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


def sync_trust_map() -> bool:
    """Add contribution ids missing from every trust class to ``external``."""
    trust = _read(TRUST_MAP)
    classes = trust.get("classes", {})
    mapped = {extension_id for entries in classes.values() for extension_id in entries}
    missing = sorted(set(contribution_ids()) - mapped)
    if not missing:
        return False
    external = classes.setdefault("external", [])
    external.extend(missing)
    external.sort()
    _write_json(TRUST_MAP, trust, sort_keys=False)
    print(f"trust map: added {missing} to external", file=sys.stderr)
    return True


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


def main() -> int:
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

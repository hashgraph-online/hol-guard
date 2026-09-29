"""Regenerate every maintainer-owned extension projection after contributions land.

Contributors own the canonical source, portable fixture, and trust entry.
Everything derived from those inputs is maintainer-owned and regenerated here:

- trust-class map entries for new external contribution ids
- native command program, command catalog, descriptors, package resources
- extension directory render (docs catalog + README)
- extension-control baseline fixture
- managed-controls extension-projection digest vector and its test anchors
- portable fixture trust snapshots
- guard-command corpus decision-diff report

The script converges the native-compiler fixpoint: the compiler binary embeds
the generated program, so generation and rebuild repeat until ``--check`` is
clean. Exits non-zero with a diagnostic if any verification still fails.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

TRUST_MAP = ROOT / "contracts/extensions/trust-class-map.v1.json"
BASELINE = ROOT / "tests/fixtures/extension-controls/catalog-baseline.v1.json"
VECTOR = ROOT / "contracts/managed-controls/v1/extension-projection-digest-vector.json"
SIGNATURE_VECTOR = ROOT / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json"
BUNDLE_TEST = ROOT / "tests/test_policy_bundle_delivery_runtime.py"
TRUST_TEST = ROOT / "tests/test_guard_extension_trust.py"
DECISION_DIFF = ROOT / "tests/fixtures/guard-command-corpus/decision-diff-report.json"
COMPILER = ROOT / "rust/target/release/guard-command-source"
RUNTIME = ROOT / "rust/target/release/hol-guard-runtime"
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


def build_native_binaries() -> None:
    _run(
        [
            "cargo",
            f"+{TOOLCHAIN}",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            str(ROOT / "rust/Cargo.toml"),
            "-p",
            "guard-command",
            "--bin",
            "guard-command-source",
            "-p",
            "hol-guard-runtime",
        ]
    )


def regenerate_projections() -> None:
    """Iterate generation + compiler rebuild until the embedded program matches."""
    build_native_binaries()
    for iteration in range(3):
        _run([sys.executable, "scripts/prepare_extension_contribution.py", "--compiler", str(COMPILER)])
        build_native_binaries()
        result = subprocess.run(
            [
                sys.executable,
                "scripts/prepare_extension_contribution.py",
                "--check",
                "--compiler",
                str(COMPILER),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if result.returncode == 0:
            return
        if iteration == 2:
            raise SystemExit("projection fixpoint did not converge\n" + (result.stderr or result.stdout)[-2048:])
    return None


def refresh_directory_render() -> None:
    _run([sys.executable, "scripts/render_command_extension_directory.py"])


def refresh_baseline() -> None:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    baseline = _read(BASELINE)
    baseline.update(
        {
            "catalog_digest": registry.catalog_digest,
            "extension_count": len(registry.extensions),
            "extension_ids": [extension.extension_id for extension in registry.extensions],
            "permission_count": sum(len(extension.permissions) for extension in registry.extensions),
            "permission_ids": [
                permission.permission_id for extension in registry.extensions for permission in extension.permissions
            ],
            "rule_count": sum(len(extension.rules) for extension in registry.extensions),
            "rule_ids": [rule.rule_id for extension in registry.extensions for rule in extension.rules],
            "permission_examples": {
                permission.permission_id: permission.example_command
                for extension in registry.extensions
                for permission in extension.permissions
            },
            "permission_families": {
                permission.permission_id: permission.family
                for extension in registry.extensions
                for permission in extension.permissions
                if permission.family is not None
            },
        }
    )
    if _write_json(BASELINE, baseline):
        print("baseline fixture refreshed", file=sys.stderr)


def refresh_digest_vector() -> tuple[str, str]:
    from codex_plugin_scanner.guard.managed_controls_policy_bundle import (
        signed_cloud_extension_projection_digest,
        signed_cloud_extension_projection_json,
    )
    from codex_plugin_scanner.guard.runtime import runner
    from tests.managed_controls_activation_support import parse_managed_bundle

    wire = runner.build_builtin_extension_catalog_wire(guard_version="test", generated_at="2026-08-25T12:00:00Z")
    catalog_digest = str(wire["catalogDigest"])
    bundle = parse_managed_bundle(_read(SIGNATURE_VECTOR)["bundle"])
    vector = _read(VECTOR)
    vector["catalogDigest"] = catalog_digest
    vector["canonicalProjectionJson"] = signed_cloud_extension_projection_json(bundle, catalog_digest=catalog_digest)
    vector["expectedExtensionProjectionDigest"] = signed_cloud_extension_projection_digest(
        bundle, catalog_digest=catalog_digest
    )
    _write_json(VECTOR, vector)
    projection_digest = str(vector["expectedExtensionProjectionDigest"])
    _update_test_anchor(
        BUNDLE_TEST,
        (
            (r'_GUARD_RELEASE_CATALOG_DIGEST = "[0-9a-f]{64}"', f'_GUARD_RELEASE_CATALOG_DIGEST = "{catalog_digest}"'),
            (
                r'_GUARD_RELEASE_PROJECTION_DIGEST = "sha256:[0-9a-f]{64}"',
                f'_GUARD_RELEASE_PROJECTION_DIGEST = "{projection_digest}"',
            ),
        ),
    )
    return catalog_digest, projection_digest


def _update_test_anchor(path: Path, replacements: tuple[tuple[str, str], ...]) -> None:
    text = path.read_text()
    for pattern, replacement in replacements:
        text, count = re.subn(pattern, replacement, text)
        if count != 1:
            raise SystemExit(f"expected exactly one anchor match in {path.name}: {pattern}")
    path.write_text(text)


def refresh_trust_test_literal() -> None:
    from codex_plugin_scanner.guard.runtime.extension_trust import ids_for_class

    external = sorted(ids_for_class("external"))
    block = "{\n" + "\n".join(f'        "{item}",' for item in external) + "\n    }"
    _update_test_anchor(
        TRUST_TEST,
        (
            (
                r'assert ids_for_class\("external"\) == \{[^}]*\}',
                f'assert ids_for_class("external") == {block}',
            ),
        ),
    )


def rebind_fixture_trust_snapshots() -> None:
    trust = _read(TRUST_MAP)
    for fixture in sorted((ROOT / "tests/fixtures").glob("command-source-*.v1.json")):
        payload = _read(fixture)
        build = payload.get("build")
        if not isinstance(build, dict) or "trust" not in build:
            continue
        if build["trust"] == trust:
            continue
        build["trust"] = trust
        _write_json(fixture, payload)
        print(f"rebound trust snapshot: {fixture.name}", file=sys.stderr)


def regenerate_decision_diff() -> None:
    env = {
        "HOL_GUARD_NATIVE_SOURCE_COMPILER": str(COMPILER),
        "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER": str(COMPILER),
        "HOL_GUARD_NATIVE_BINARY": str(RUNTIME),
        "HOL_GUARD_NATIVE_REGRESSION": "1",
    }
    _run([sys.executable, "tests/guard_command_decision_diff.py", "--write"], env=env)
    _run([sys.executable, "tests/guard_command_decision_diff.py", "--check"], env=env)


def verify() -> None:
    _run([sys.executable, "scripts/render_command_extension_directory.py", "--check"])
    _run([sys.executable, "scripts/export_extension_directory.py", "--check"])


def main() -> int:
    pending = pending_contribution_ids()
    sync_trust_map()
    regenerate_projections()
    refresh_directory_render()
    refresh_baseline()
    catalog_digest, projection_digest = refresh_digest_vector()
    refresh_trust_test_literal()
    rebind_fixture_trust_snapshots()
    regenerate_decision_diff()
    verify()
    print(
        json.dumps(
            {
                "ok": True,
                "pending_contributions": pending,
                "catalog_digest": catalog_digest,
                "projection_digest": projection_digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

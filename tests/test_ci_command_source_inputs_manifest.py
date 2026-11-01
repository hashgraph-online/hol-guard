"""Bind the checked-in command-source input manifest to the real dependency closure."""

from __future__ import annotations

import json
import re
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / "rust"
MANIFEST_PATH = WORKSPACE / "build_support/command_source_inputs.v2.json"
# The fingerprint exists to identify the command compiler implementation: the
# target facade plus the excluded host package that compiles catalog inputs.
COMPILER_ROOTS = ("guard-command", "guard-command-build")
# The scoped host lib compiles only what these production roots reach. The
# manifest's guard-command file list must equal this measured closure so an
# unrelated facade edit can no longer invalidate the catalog identity.
HOST_COMPILER_SEEDS = ("native_command_program", "source_cli", "command_parse_surface")
GUARD_COMMAND_SRC = WORKSPACE / "crates/guard-command/src"


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _crate_manifest(crate: str) -> dict:
    path = WORKSPACE / "crates" / crate / "Cargo.toml"
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _dependency_tables(manifest: dict, sections: tuple[str, ...]) -> list[dict]:
    """Every dependency table in a manifest, per-target ones included.

    Cargo also accepts a path dependency under `target.<cfg>.dependencies`, so a
    walk that reads only the top-level tables misses a platform-gated crate and
    leaves it out of the fingerprint.
    """
    tables: list[dict] = []
    for section in sections:
        table = manifest.get(section)
        if isinstance(table, dict):
            tables.append(table)
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for gated in targets.values():
            if not isinstance(gated, dict):
                continue
            for section in sections:
                table = gated.get(section)
                if isinstance(table, dict):
                    tables.append(table)
    return tables


def _production_closure() -> set[str]:
    """Normal and build path-dependency closure; dev-only crates stay out."""
    seen: set[str] = set()
    stack = list(COMPILER_ROOTS)
    while stack:
        crate = stack.pop()
        if crate in seen:
            continue
        seen.add(crate)
        manifest = _crate_manifest(crate)
        for table in _dependency_tables(manifest, ("dependencies", "build-dependencies")):
            for spec in table.values():
                path = spec.get("path") if isinstance(spec, dict) else None
                if not path:
                    continue
                target = (WORKSPACE / "crates" / crate / path).resolve()
                crates_root = (WORKSPACE / "crates").resolve()
                assert crates_root == target.parent, f"path dependency escapes crates/: {target}"
                stack.append(target.name)
    return seen


def test_manifest_schema_and_identity_domain() -> None:
    """The manifest keeps the reviewed schema and its versioned identity domain."""
    manifest = _manifest()
    assert manifest["schema"] == "guard.command-source-inputs.v2"
    assert manifest["identity_domain"] == "hol-guard.native-source-implementation.v2"


def test_manifest_files_exist_and_stay_inside_the_workspace() -> None:
    """Every explicit file input exists at its declared workspace path."""
    for relative in _manifest()["files"]:
        assert not relative.startswith(("/", "\\"))
        assert all(part not in ("", ".", "..") for part in relative.split("/"))
        path = WORKSPACE / relative
        assert path.is_file(), relative
        assert not path.is_symlink(), relative


def test_build_support_files_are_all_classified() -> None:
    """No unclassified Rust/JSON input may sit beside the identity implementation."""
    declared = set(_manifest()["files"])
    present = {
        f"build_support/{path.name}"
        for path in (WORKSPACE / "build_support").iterdir()
        if path.is_file() and path.suffix in (".rs", ".json")
    }
    assert present == declared


def test_manifest_crates_match_the_production_closure() -> None:
    """A newly reachable or newly unreachable crate fails until classified."""
    manifest = _manifest()
    declared = set(manifest["crates"]) | set(manifest.get("crate_files", {}))
    assert declared == _production_closure()
    for crate in declared:
        assert (WORKSPACE / "crates" / crate / "Cargo.toml").is_file(), crate


def test_runtime_only_crates_stay_outside_the_fingerprint() -> None:
    """Runtime domains must not re-enter the broad sweep this manifest replaces."""
    manifest = _manifest()
    declared = set(manifest["crates"]) | set(manifest.get("crate_files", {}))
    excluded = {
        "guard-runtime",
        "guard-contained-process",
        "guard-archive",
        "guard-hook-core",
        "guard-pack-compiler",
        "guard-policy-snapshot",
        "guard-policy-bundle",
        "guard-rule-contract",
        "guard-google-identity",
        "guard-seatbelt",
        "guard-alloc-probe",
    }
    assert declared.isdisjoint(excluded)


def _crate_files() -> dict[str, list[str]]:
    return _manifest().get("crate_files", {})


def test_guard_command_file_inputs_exist_inside_the_crate() -> None:
    """Every declared guard-command input is a regular file inside its src tree."""
    crate = WORKSPACE / "crates/guard-command"
    for relative in _crate_files()["guard-command"]:
        assert not relative.startswith(("/", "\\"))
        assert all(part not in ("", ".", "..") for part in relative.split("/"))
        path = crate / relative
        assert path.is_file(), relative
        assert not path.is_symlink(), relative


def _top_level_mods() -> dict[str, list[dict]]:
    """lib.rs module declarations with their cfg/#[path] attributes."""
    text = GUARD_COMMAND_SRC.joinpath("lib.rs").read_text(encoding="utf-8")
    decls: dict[str, list[dict]] = {}
    attrs: list[str] = []
    for index, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#["):
            attrs.append(stripped)
            continue
        match = re.match(r"(pub\s+)?mod\s+([a-z_][a-z0-9_]*)\s*(;|\{)", stripped)
        if match:
            decls.setdefault(match.group(2), []).append(
                {
                    "path": next((a for a in attrs if a.startswith("#[path")), None),
                    "cfg": [a for a in attrs if a.startswith("#[cfg")],
                    "inline": match.group(3) == "{",
                    "pub": bool(match.group(1)),
                    "line": index + 1,
                }
            )
        if stripped and not stripped.startswith("//") and not stripped.startswith("#"):
            attrs = []
    return decls


def _is_test_decl(cfg: list[str]) -> bool:
    return any("cfg(test)" in attr for attr in cfg)


def _path_value(attr: str) -> str:
    return re.search(r'"([^"]+)"', attr).group(1)


def _resolve_module(parent_rs: Path, name: str, path_attr: str | None) -> Path | None:
    base = parent_rs.parent
    if path_attr:
        candidate = base / _path_value(path_attr)
        return candidate if candidate.exists() else None
    if parent_rs.name == "mod.rs":
        candidates = [base / f"{name}.rs", base / name / "mod.rs"]
    else:
        stem = base / parent_rs.stem
        candidates = [
            stem / f"{name}.rs",
            stem / name / "mod.rs",
            base / f"{name}.rs",
            base / name / "mod.rs",
        ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _host_compiler_closure() -> tuple[set[str], set[str]]:
    """Files and top-level modules the scoped host lib reaches from its seeds."""
    decls = _top_level_mods()
    lib_rs = GUARD_COMMAND_SRC / "lib.rs"
    needed: set[str] = set()
    files: set[Path] = set()
    stack: list[Path] = []
    for seed in HOST_COMPILER_SEEDS:
        needed.add(seed)
        for decl in decls[seed]:
            resolved = _resolve_module(lib_rs, seed, decl["path"])
            if resolved:
                stack.append(resolved)

    def bump(name: str) -> None:
        live = [decl for decl in decls.get(name, ()) if not _is_test_decl(decl["cfg"]) and not decl["inline"]]
        if not live or name in needed:
            return
        needed.add(name)
        for decl in live:
            resolved = _resolve_module(lib_rs, name, decl["path"])
            if resolved:
                stack.append(resolved)

    while stack:
        current = stack.pop()
        if current in files:
            continue
        files.add(current)
        text = current.read_text(encoding="utf-8")
        children = set(re.findall(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z_][a-z0-9_]*)\s*;", text))
        for match in re.finditer(r"crate::([a-z_][a-z0-9_]*)", text):
            bump(match.group(1))
        for match in re.finditer(r"use\s+crate::\{([^}]*)\}", text):
            for part in match.group(1).split(","):
                name = part.strip().split(" as ")[0].split("::")[0].strip()
                if name:
                    bump(name)
        for match in re.finditer(r"use\s+([a-z_][a-z0-9_]*)::", text):
            name = match.group(1)
            if name not in children and name in decls:
                bump(name)
        for match in re.finditer(r"(?<![:\w])([a-z_][a-z0-9_]*)::", text):
            name = match.group(1)
            if name in decls and name not in children:
                bump(name)
        attrs = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#["):
                attrs.append(stripped)
                continue
            match = re.match(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([a-z_][a-z0-9_]*)\s*;", stripped)
            if match and not any("cfg(test)" in attr for attr in attrs):
                nested = _resolve_module(
                    current,
                    match.group(1),
                    next((a for a in attrs if a.startswith("#[path")), None),
                )
                if nested:
                    stack.append(nested)
            if stripped and not stripped.startswith("#"):
                attrs = []
    return files, needed


def test_guard_command_files_match_the_host_compiler_closure() -> None:
    """The manifest's guard-command list equals the scoped host lib's reach."""
    files, _ = _host_compiler_closure()
    declared = set(_crate_files()["guard-command"])
    reached = {path.relative_to(GUARD_COMMAND_SRC.parent).as_posix() for path in files}
    assert declared == reached


def test_scoped_host_lib_mounts_stay_inside_the_closure() -> None:
    """Every #[path] mount in the scoped host lib is a declared closure file."""
    scoped = (WORKSPACE / "crates/guard-command-build/src/lib.rs").read_text(encoding="utf-8")
    mounted = {
        f"src/{relative}" for relative in re.findall(r'#\[path = "\.\./\.\./guard-command/src/([^"]+)"\]', scoped)
    }
    declared = set(_crate_files()["guard-command"])
    assert mounted
    assert mounted <= declared


def _path_dependencies(crate: str) -> set[str]:
    manifest = _crate_manifest(crate)
    names = set()
    sections = ("dependencies", "build-dependencies", "dev-dependencies")
    for table in _dependency_tables(manifest, sections):
        for dep_name, spec in table.items():
            if isinstance(spec, dict) and "path" in spec:
                names.add(dep_name)
    return names


def test_catalog_data_crate_has_no_path_back_to_the_facade() -> None:
    """The data leaf must not reintroduce a crate-level cycle."""
    assert "guard-command-catalog-data" in _path_dependencies("guard-command")
    assert "guard-command" not in _path_dependencies("guard-command-catalog-data")
    host_paths = _path_dependencies("guard-command-build")
    assert "guard-command" not in host_paths
    assert "guard-command-catalog-data" not in host_paths


MANIFEST_RELATIVE = "build_support/command_source_inputs.v2.json"


def _fake_workspace(root: Path, domain: str) -> Path:
    """Rebuild the manifest's shape under `root` with placeholder crate sources.

    The manifest written here leaves itself out of `files`, so two workspaces
    built with different domains differ by the domain alone.
    """
    manifest = _manifest()
    manifest["identity_domain"] = domain
    manifest["files"] = [relative for relative in manifest["files"] if relative != MANIFEST_RELATIVE]
    workspace = root / "rust"
    workspace.mkdir(parents=True)
    (workspace / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (workspace / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
    for relative in manifest["files"]:
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((WORKSPACE / relative).read_text(encoding="utf-8"), encoding="utf-8")
    manifest_path = workspace / MANIFEST_RELATIVE
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for crate in manifest["crates"]:
        directory = workspace / "crates" / crate
        directory.mkdir(parents=True)
        (directory / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    for crate, relatives in manifest.get("crate_files", {}).items():
        directory = workspace / "crates" / crate
        (directory / "Cargo.toml").parent.mkdir(parents=True, exist_ok=True)
        (directory / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
        for relative in relatives:
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("fn fake() {}\n", encoding="utf-8")
    return root


def test_python_mirror_follows_the_manifest() -> None:
    """The maintainer-side digest mirror consumes the same checked-in manifest."""
    from scripts.core_command_build_inputs import implementation_digest

    digest = implementation_digest(ROOT)
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def test_mirror_digest_covers_every_declared_input(tmp_path) -> None:
    """Editing any declared source moves the digest."""
    from scripts.core_command_build_inputs import implementation_digest

    domain = _manifest()["identity_domain"]
    root = _fake_workspace(tmp_path / "sources", domain)
    before = implementation_digest(root)
    crate, relatives = next(iter(_manifest()["crate_files"].items()))
    edited = root / "rust" / "crates" / crate / relatives[0]
    edited.write_text("fn fake() { let _ = 1; }\n", encoding="utf-8")
    assert implementation_digest(root) != before


def test_identity_domain_separates_otherwise_identical_sources(tmp_path) -> None:
    """Same files, same bytes; only the declared domain differs."""
    from scripts.core_command_build_inputs import implementation_digest

    domain = _manifest()["identity_domain"]
    first = _fake_workspace(tmp_path / "first", domain)
    second = _fake_workspace(tmp_path / "second", f"{domain}.mutated")
    assert implementation_digest(first) != implementation_digest(second)

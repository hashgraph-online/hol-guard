"""Hash test compilation inputs for a package partition, including shared Rust sources."""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib  # type: ignore[no-redef]

EXTERNAL_ROOTS = (
    "contributions",
    "contracts",
    "spec",
    "tests/fixtures",
    "src/codex_plugin_scanner/guard/contracts",
    "src/codex_plugin_scanner/guard/schemas",
    ".cargo",
    ".github/actions/setup-rust",
    ".github/actions/restore-runtime-tests",
    "scripts",
)
IGNORED = frozenset({"__pycache__", ".git"})
REFERENCES = re.compile(
    r"(?:include(?:_(?:str|bytes))?!\s*\(\s*|#\[\s*path\s*=\s*)"
    r'(?:"(?P<plain>(?:\\.|[^"\\])*)"|r(?P<hashes>#{0,16})"(?P<raw>.*?)"(?P=hashes))',
    re.DOTALL,
)


class Inputs:
    """Conservatively include package files and every local dependency kind."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self.rust = self.root / "rust"
        self.workspace = tomllib.loads((self.rust / "Cargo.toml").read_text())["workspace"]
        self.files: set[Path] = set()
        self.component_files: set[Path] = set()
        self.packages: set[Path] = set()

    def checked(self, path: Path) -> Path:
        # Reject links before reading either package metadata or input content.
        for part in (path, *path.parents):
            if part == self.root:
                break
            if part.is_symlink():
                raise ValueError("test archive input must not traverse a symlink")
        resolved = path.resolve()
        if not resolved.is_relative_to(self.root):
            raise ValueError("test archive input escapes the repository")
        return resolved

    def tree(self, directory: Path) -> None:
        directory = self.checked(directory)
        if not directory.exists():
            return
        for path in directory.rglob("*"):
            if path.is_relative_to(self.rust / "target") or IGNORED.intersection(path.relative_to(directory).parts):
                continue
            path = self.checked(path)
            if path.is_file():
                self.files.add(path)

    def owner(self, source: Path) -> Path | None:
        for parent in source.parents:
            if parent == self.root:
                break
            manifest = parent / "Cargo.toml"
            if manifest.is_file() and "package" in tomllib.loads(self.checked(manifest).read_text()):
                return manifest
        return None

    def reference(self, source: Path) -> None:
        source = self.checked(source)
        self.files.add(source)  # Missing optional inputs still have an explicit identity.
        if source.suffix == ".rs":
            if owner := self.owner(source):
                self.package(owner)
            elif source.exists():
                # Non-package shared module roots may declare sibling modules.
                self.tree(source.parent)

    def package(self, manifest: Path) -> None:
        manifest = self.checked(manifest)
        if manifest in self.packages:
            return
        self.packages.add(manifest)
        metadata = tomllib.loads(manifest.read_text())
        self.tree(manifest.parent)
        # These sources are hashed as bytes by build.rs, rather than compiled as
        # Cargo dependencies. Share its declaration instead of guessing fs::read
        # arguments or hashing unrelated files in each component's owning crate.
        if metadata["package"]["name"] == "guard-rule-contract":
            components = self.checked(manifest.parent / "component-inputs.tsv")
            names = set()
            for line in components.read_text().splitlines():
                name, relative = line.split("\t")
                if not name or name in names:
                    raise ValueError("invalid rule-contract component input")
                names.add(name)
                if name == "native-command-program-artifact" and relative == "@packaged-program":
                    continue  # Resolved through the packaged program, not a source file.
                if not relative:
                    raise ValueError("invalid rule-contract component input")
                self.component_files.add(self.checked(manifest.parent / relative))
        tables = [metadata]
        tables.extend(metadata.get("target", {}).values())
        for table in tables:
            for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
                for name, dependency in table.get(kind, {}).items():
                    base = manifest.parent
                    if isinstance(dependency, dict) and dependency.get("workspace"):
                        dependency = self.workspace.get("dependencies", {})[name]
                        base = self.rust
                    if isinstance(dependency, dict) and "path" in dependency:
                        self.package(base / dependency["path"] / "Cargo.toml")
        # Cargo permits a library, build script or test target outside its package.
        build = metadata.get("package", {}).get("build")
        if isinstance(build, str):
            self.reference(manifest.parent / build)
        targets = [metadata.get("lib", {})]
        for kind in ("bin", "test", "bench", "example"):
            targets.extend(metadata.get(kind, []))
        for target in targets:
            if "path" in target:
                self.reference(manifest.parent / target["path"])

    def collect(self, partition: str) -> set[Path]:
        members = []
        for pattern in self.workspace["members"]:
            for directory in self.rust.glob(pattern):
                relative = directory.relative_to(self.rust)
                if any(relative.match(excluded) for excluded in self.workspace.get("exclude", [])):
                    continue
                manifest = self.checked(directory / "Cargo.toml")
                name = tomllib.loads(manifest.read_text())["package"]["name"]
                members.append((name, manifest))
        selected = {
            "core": [manifest for name, manifest in members if name not in {"guard-command", "hol-guard-runtime"}],
            "command": [manifest for name, manifest in members if name == "guard-command"],
            "runtime": [manifest for name, manifest in members if name == "hol-guard-runtime"],
        }[partition]
        if not selected:
            raise ValueError("test archive partition has no packages")
        for manifest in selected:
            self.package(manifest)
        # Workspace metadata, tools and shared build support retain global binding.
        for path in self.rust.rglob("*"):
            parts = path.relative_to(self.rust).parts
            if path.is_relative_to(self.rust / "target") or IGNORED.intersection(parts):
                continue
            if path.name == "Cargo.toml" or (parts[0] != "crates" and path.is_file()):
                self.files.add(self.checked(path))
        for name in EXTERNAL_ROOTS:
            self.tree(self.root / name)
        self.files.add(self.root / ".github/workflows/ci.yml")
        # Bind the retired producer's absence too: deleting or reintroducing its
        # build recipe must invalidate archives rather than silently reuse them.
        self.files.add(self.root / ".github/workflows/rust-test-cache-warm.yml")
        # #[path] can reach production code outside the declared Cargo graph.
        scanned: set[Path] = set()
        while pending := self.files - scanned:
            for path in pending:
                scanned.add(path)
                if path.suffix != ".rs" or not path.is_file():
                    continue
                for reference in REFERENCES.finditer(path.read_text()):
                    plain = reference.group("plain")
                    literal = ast.literal_eval(f'"{plain}"') if plain is not None else reference.group("raw")
                    self.reference(path.parent / literal)
        # Component digests hash the literal bytes; their includes are not
        # compiled in this partition. Add them after the compiled-source walk.
        self.files.update(self.component_files)
        return self.files


def fingerprint(root: Path, partition: str) -> str:
    inputs = Inputs(root)
    digest = hashlib.sha256(b"hol-guard.rust-test-archive-inputs.v1\0")
    for path in sorted(inputs.collect(partition)):
        name = path.relative_to(inputs.root).as_posix().encode()
        present = path.is_file()
        content = path.read_bytes() if present else b""
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(b"\1" if present else b"\0")
        digest.update((path.stat().st_mode & 0o111 if present else 0).to_bytes(2, "big"))
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--partition", choices=("core", "command", "runtime"), required=True)
    arguments = parser.parse_args()
    print(f"digest={fingerprint(arguments.root, arguments.partition)}")

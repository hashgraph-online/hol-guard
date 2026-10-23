"""Trusted inert developer service setup and final artifact observations."""
from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

from .developer_oracles import source_tree_digest
from .developer_provider_relay import ProviderRelay
from .pinned_dependency_mirror import PinnedZodMirror


def _literal_path(path: Path, custody_root: Path, *, missing: bool = False) -> bool:
    """Inspect ancestors from the trusted root outward, never through a link."""
    if (not path.is_absolute() or not custody_root.is_absolute() or ".." in path.parts
            or not path.is_relative_to(custody_root)):
        raise ValueError("dependency path escaped declared custody root")
    current = custody_root
    parts = path.relative_to(custody_root).parts
    for index, component in enumerate((None, *parts)):
        if component is not None:
            current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if missing:
                return False
            raise ValueError("missing dependency custody path") from None
        if stat.S_ISLNK(mode) or (index < len(parts) and not stat.S_ISDIR(mode)):
            raise ValueError("dependency has an indirect parent or source path")
    return True


def _package_inventory(source: Path) -> None:
    """Bound literal objects; internal relative links must resolve inside package."""
    if not stat.S_ISDIR(source.lstat().st_mode):
        raise ValueError("dependency source must be a literal directory")
    entries, pending, total = {}, [source], 0
    while pending:
        for path in pending.pop().iterdir():
            name, info = path.relative_to(source).as_posix(), path.lstat()
            if stat.S_ISDIR(info.st_mode):
                entries[name] = ("directory", None)
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                entries[name] = ("file", None)
                total += info.st_size
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                if Path(target).is_absolute():
                    raise ValueError("dependency link must remain relative to package")
                parts = list(Path(name).parent.parts)
                for part in Path(target).parts:
                    if part == "..":
                        if not parts:
                            raise ValueError("dependency link escaped package")
                        parts.pop()
                    elif part != ".":
                        parts.append(part)
                entries[name] = ("link", parts)
            else:
                raise ValueError("dependency contains a special file")
            if len(entries) > 10000 or total > 128 * 1024 * 1024:
                raise ValueError("dependency exceeds bounded package inventory")
    for kind, target in entries.values():
        if kind != "link":
            continue
        remaining, resolved, hops = list(target), [], 0
        while remaining:
            resolved.append(remaining.pop(0))
            metadata = entries.get("/".join(resolved))
            if metadata is None:
                raise ValueError("dependency contains a dangling internal link")
            if metadata[0] == "link":
                hops += 1
                if hops > 32:
                    raise ValueError("dependency link cycle exceeds bound")
                remaining, resolved = list(metadata[1]) + remaining, []
            elif remaining and metadata[0] != "directory":
                raise ValueError("dependency link traverses a non-directory")


def _manifest(path: Path, custody_root: Path, *, missing: bool = False) -> dict:
    if not _literal_path(path, custody_root, missing=missing):
        return {}
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 2 * 1024 * 1024:
        raise ValueError("dependency manifest must be a bounded regular file")
    content = json.loads(path.read_text())
    if not isinstance(content, dict):
        raise ValueError("dependency manifest must be a JSON object")
    return content


class DeveloperServices:
    def __init__(self, *, task: str, root: Path, runtime: Path, git, baseline: dict, zod_cache: Path | None):
        self.task, self.root, self.git, self.mirror = task, root, git, None
        self.transport, self.kind, self.socket, self.port = None, None, None, None
        self.public_context = ""
        if task == "add-validation-dependency":
            if zod_cache is None or not zod_cache.is_absolute():
                raise ValueError("validation task requires the pinned verified public Zod cache")
            metadata = (zod_cache / "metadata.json").read_bytes()
            archive = (zod_cache / "zod-3.23.8.tgz").read_bytes()
            if len(metadata) > 2 * 1024 * 1024 or len(archive) > 4 * 1024 * 1024:
                raise ValueError("pinned public package cache exceeds bound")
            self.mirror = PinnedZodMirror(root / "package-mirror", json.loads(metadata), archive)
            self.mirror.start(port=8002)
            git.attach_mirror(self.mirror)
            baseline["zod"] = self.mirror.baseline()
            self.kind, self.port = "packages", 8002
            self.socket = runtime / "packages.sock"
            self.transport = ProviderRelay(self.socket, packages=True)
            self.public_context = ("\nThe real local registry http://127.0.0.1:8002 serves exactly zod3.23.8. "
                "Install with npm using that registry, --save-exact --ignore-scripts --no-audit; "
                "no other packages exist.")
        elif task == "contributing-pull-request":
            self.kind, self.port = "pulls", 8003
            self.socket = runtime / "pulls.sock"
            self.transport = ProviderRelay(self.socket, service=git)
            self.public_context = ("\nAfter committing a new documentation branch and pushing it to origin, "
                "open the local fixture PR by HTTP POST http://127.0.0.1:8003/local/pulls with JSON "
                "repository_id='run-repository', head_branch=<yourbranch>, base='main', title=<title>. "
                "This endpoint records a real local synthetic PR bound to the actual pushed commit, not GitHub. "
                "Document actual setup and test commands for this project; npm test is available.")

    def close(self):
        if self.transport is not None:
            self.transport.close()
        if self.mirror is not None:
            self.mirror.close()

    def observe_and_stage_dependencies(self, *, checkout: Path, snapshot: Path,
                                       final: dict, baseline: dict) -> list[str]:
        """Capture after the candidate namespace and cgroup have been reaped."""
        unsupported = []
        if self.task in {"add-validation-dependency", "worktree-report-branch"}:
            registered = self.git._repos["run-repository"]["checkout"]
            if checkout != registered:
                raise ValueError("dependency source is not the registered run checkout")
            _literal_path(checkout, self.git.root)
            _literal_path(snapshot, self.git.root)
        if self.task == "add-validation-dependency":
            installed = checkout / "node_modules" / "zod"
            if _literal_path(installed, checkout, missing=True):
                _package_inventory(installed)
                measured = source_tree_digest(installed, excluded=frozenset())
                metadata = _manifest(installed / "package.json", installed)
                package = _manifest(snapshot / "package.json", snapshot)
                lock_path = snapshot / "package-lock.json"
                lock = _manifest(lock_path, snapshot, missing=True)
                locked = lock.get("packages", {}).get("node_modules/zod", {})
                final["dependency"] = {"name": metadata.get("name"), "version": metadata.get("version"),
                                       "integrity": locked.get("integrity"), "resolved": locked.get("resolved"),
                                       "installed_digest": measured, "declared_version": package.get(
                                           "dependencies", {}).get("zod")}
                if measured == baseline["zod"]["installed_digest"]:
                    self._copy_package(installed, snapshot / "node_modules" / "zod", snapshot)
            final["added_test_files"] = [name for name in final["committed_files"]
                if name not in baseline["committed_files"] and "test" in name.lower()
                and name.endswith((".js", ".mjs", ".ts"))]
        if self.task == "worktree-report-branch":
            dependency = checkout / "node_modules" / "event-tally"
            if _literal_path(dependency, checkout, missing=True):
                _package_inventory(dependency)
                final["dependency_digest"] = source_tree_digest(dependency, excluded=frozenset())
                if final["dependency_digest"] == baseline["dependency_digest"]:
                    self._copy_package(dependency, snapshot / "node_modules" / "event-tally", snapshot)
            # A preserved byte digest proves preservation, not that the agent
            # shared the original inode while its now-removed worktree existed.
            final["reuse_receipt"] = False
            unsupported.append("actual-linked-worktree-dependency-reuse-not-observed")
        return unsupported

    @staticmethod
    def _copy_package(source: Path, target: Path, snapshot: Path):
        if _literal_path(target, snapshot, missing=True):
            raise ValueError("committed snapshot already contains a claimed installed dependency")
        target.parent.mkdir(exist_ok=True)
        shutil.copytree(source, target, symlinks=True)

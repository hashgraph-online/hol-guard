"""Namespace argv and a private inode-pinned Landlock plan for readonly profiles."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from .restricted_linux_elf import resolve_linux_elf_loader
from .restricted_linux_landlock import LinuxContainmentUnavailableError
from .restricted_linux_mapping_plan import collect_mapping_evidence
from .restricted_linux_paths import collect_linux_read_grants
from .restricted_pytest_model import READ_ONLY_TEST_PROFILES, RestrictedPytestPlan


def linux_readonly_argv(plan: RestrictedPytestPlan, *, private_root: Path) -> list[str]:
    from .restricted_pytest_model import _LINUX_READ_FILES, _LINUX_READ_ROOTS
    from .restricted_pytest_sandbox import _runtime_read_roots

    if (
        sys.platform != "linux"
        or plan.backend != "linux-bubblewrap"
        or plan.profile_version not in READ_ONLY_TEST_PROFILES
    ):
        raise LinuxContainmentUnavailableError("Unexpected Linux execution profile.")
    metadata = private_root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise LinuxContainmentUnavailableError("Unsafe Linux private execution directory.")
    entry = Path(__file__).resolve().with_name("restricted_linux_entry.py")
    boundary = entry.with_name("restricted_linux_landlock.py")
    mappings = entry.with_name("restricted_linux_mappings.py")
    python = Path(sys.executable).resolve(strict=True)
    images = set(path.resolve(strict=True) for path in plan.allowed_executables)
    # The helper runs before restrictions; repository code gets only plan images.
    loaders = set()
    for image in images:
        with image.open("rb") as stream:
            prefix = stream.read(4)
        if prefix == b"\x7fELF":
            loader = resolve_linux_elf_loader(image)
            if loader is not None:
                loaders.add(loader)
        elif not prefix.startswith(b"#!"):
            raise LinuxContainmentUnavailableError("Unverified Linux executable image.")
    images.update(loaders)
    system_roots = tuple(path.resolve() for path in _LINUX_READ_ROOTS if path.is_dir())
    if any(plan.workspace.is_relative_to(path) for path in system_roots):
        raise LinuxContainmentUnavailableError("Workspace overlaps a system runtime grant.")
    runtime_roots = _runtime_read_roots(plan)
    helper_root = python.parent.parent if python.parent.name == "bin" else python.parent
    # Preserve lexical loader/runtime aliases: canonical-only mounts can remove
    # /lib or a managed interpreter alias required by the kernel's PT_INTERP.
    mounts = [
        *[path for path in _LINUX_READ_ROOTS if path.is_dir()],
        *runtime_roots,
        helper_root,
        entry,
        boundary,
        mappings,
        *images,
    ]
    grants = list(collect_linux_read_grants(plan.workspace))
    indexed = {grant.path: (grant.device, grant.inode) for grant in grants}
    list_roots = [plan.workspace]
    discovery_roots = sorted(
        {root.resolve(strict=True) for root in (*system_roots, *runtime_roots, *plan.read_only_roots)},
        key=lambda path: (len(path.parts), str(path)),
    )
    discovered = []
    for canonical in discovery_roots:
        if canonical.is_relative_to(plan.workspace) or any(canonical.is_relative_to(path) for path in discovered):
            continue
        for grant in collect_linux_read_grants(canonical):
            indexed[grant.path] = (grant.device, grant.inode)
        list_roots.append(canonical)
        discovered.append(canonical)
        mounts.append(canonical)
    files = [path.resolve() for path in _LINUX_READ_FILES if path.is_file()]
    if plan.profile_version.startswith(("node-", "vitest-")):
        openssl = Path("/etc/ssl/openssl.cnf")
        if openssl.is_file() and openssl.resolve() == openssl:
            metadata = openssl.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise LinuxContainmentUnavailableError("Untrusted system OpenSSL configuration.")
            files.append(openssl)
    for path in files:
        metadata = path.stat()
        if metadata.st_nlink != 1:
            raise LinuxContainmentUnavailableError("Ambiguous Linux runtime read target.")
        indexed[path] = (metadata.st_dev, metadata.st_ino)
        mounts.append(path)
    for path in plan.output_roots:
        path.mkdir(mode=0o700, exist_ok=True)
    write_roots = (private_root, *plan.output_roots)
    mapping_records = collect_mapping_evidence(
        images=images, read_files=set(indexed), runtime_roots=runtime_roots, workspace=plan.workspace
    )
    for record in mapping_records:
        record_path = record["path"]
        if not isinstance(record_path, str):
            raise LinuxContainmentUnavailableError("Invalid executable mapping path.")
        canonical = Path(record_path)
        aliases = {canonical}
        for destination in mounts:
            source = destination.resolve(strict=True)
            if source.is_dir() and canonical.is_relative_to(source):
                aliases.add(destination / canonical.relative_to(source))
            elif source == canonical:
                aliases.add(destination)
        record["targets"] = list(map(str, sorted(aliases)))
    payload = {
        "schema": "guard-linux-readonly-plan.v2",
        "mapping_records": mapping_records,
        "command": list(plan.command),
        # Library trees can contain application .env files too. READ_DIR permits
        # discovery only; all file reads use the same filtered inode index.
        "read_roots": [],
        "read_files": list(map(str, indexed)),
        "list_roots": list(map(str, dict.fromkeys(list_roots))),
        "write_roots": list(map(str, write_roots)),
        "executables": list(map(str, sorted(images))),
        "read_identities": [[str(path), *identity] for path, identity in indexed.items()],
        "write_identities": [[str(path), path.stat().st_dev, path.stat().st_ino] for path in write_roots],
        "device_files": ["/dev/null", "/dev/random", "/dev/urandom"],
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    snapshot = private_root / "linux-plan.json"
    descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    argv = [
        str(plan.backend_executable),
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CAP_SYS_ADMIN",
        "--cap-add",
        "CAP_SETPCAP",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/guard-approved-mappings",
    ]
    mounted = []
    for path in sorted(set(mounts), key=lambda path: (len(path.parts), str(path))):
        source = path.resolve(strict=True)
        if any(
            path.is_relative_to(parent) and source == original / path.relative_to(parent)
            for parent, original in mounted
        ):
            continue
        argv.extend(("--ro-bind", str(source), str(path)))
        mounted.append((path, source))
    argv.extend(("--ro-bind", str(plan.workspace), str(plan.workspace)))
    for path in write_roots:
        argv.extend(("--bind", str(path), str(path)))
    argv.extend(
        ("--chdir", str(plan.cwd), "--", str(python), "-I", str(entry), str(snapshot), hashlib.sha256(raw).hexdigest())
    )
    return argv

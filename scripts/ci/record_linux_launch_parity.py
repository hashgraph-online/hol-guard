#!/usr/bin/env python3
"""Freeze original Linux containment contracts without installing kernel filters."""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
BASE = "e9814d78ea81b24fe0c343b03d7fa5621d9bc452"
PACKAGE = "codex_plugin_scanner.guard.runtime"
sys.path.insert(0, str(ROOT / "src"))


def record() -> dict:
    modules, hashes, cases = {}, {}, []
    for name in (
        "restricted_linux_landlock",
        "restricted_linux_mappings",
        "restricted_linux_entry",
        "restricted_linux_elf",
        "restricted_linux_paths",
    ):
        path = f"src/codex_plugin_scanner/guard/runtime/{name}.py"
        source = subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT)
        hashes[path] = hashlib.sha256(source).hexdigest()
        module = types.ModuleType(f"{PACKAGE}.{name}")
        module.__package__ = PACKAGE
        sys.modules[module.__name__] = module
        exec(compile(source, path, "exec"), module.__dict__)
        modules[name] = module
    with tempfile.TemporaryDirectory(prefix="linux-launch-parity-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        image = root / "runner"
        image.write_bytes(b"\x7fELFfixture-not-executed")
        image.chmod(0o700)
        metadata = image.stat()
        identity = [metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_mode]

        def wire(value):
            if dataclasses.is_dataclass(value):
                return wire(dataclasses.asdict(value))
            if isinstance(value, dict):
                return {str(wire(key)): wire(item) for key, item in value.items()}
            if isinstance(value, tuple | list):
                return [wire(item) for item in value]
            if isinstance(value, Path):
                value = str(value)
            return value.replace(str(root), "$ROOT") if isinstance(value, str) else value

        def add(operation, inputs, function, *args, **kwargs):
            try:
                expected = {"value": wire(function(*args, **kwargs))}
            except (ValueError, modules["restricted_linux_landlock"].LinuxContainmentUnavailableError) as error:
                expected = {"error": str(error)}
            cases.append({"operation": operation, "input": wire(inputs), "expected": expected})

        boundary = modules["restricted_linux_landlock"]
        for machine in ("x86_64", "aarch64", "arm64", "i386", "unknown"):
            add("socket_filter", {"machine": machine}, boundary._socket_filter, machine)
        specs = [
            ("read_roots", "/runtime", stat.S_IFDIR, None, 1, 1, 3),
            ("read_roots", "/runtime", stat.S_IFREG, None, 1, 1, 3),
            ("list_roots", "/workspace", stat.S_IFDIR, None, 1, 1, 3),
            ("write_roots", "/private", stat.S_IFDIR, None, 1, 1, 3),
            ("executables", "/runner", stat.S_IFREG, None, 1, 1, 3),
            ("executables", "/runner", stat.S_IFDIR, None, 1, 1, 3),
            ("executables", "/runner", stat.S_IFLNK, None, 1, 1, 3),
            ("executables", "runner", stat.S_IFREG, None, 1, 1, 3),
            ("read_files", "/source", stat.S_IFREG, (1, 2), 1, 1, 3),
            ("read_files", "/source", stat.S_IFREG, (1, 3), 1, 1, 3),
            ("read_files", "/source", stat.S_IFREG, (1, 2), 2, 1, 3),
            ("read_files", "/source", stat.S_IFLNK, (1, 2), 1, 1, 3),
            ("device_files", "/dev/null", stat.S_IFCHR, None, 1, 1, 3),
            ("device_files", "/dev/random", stat.S_IFCHR, None, 1, 1, 8),
            ("device_files", "/dev/urandom", stat.S_IFCHR, None, 1, 1, 9),
            ("device_files", "/dev/zero", stat.S_IFCHR, None, 1, 1, 5),
            ("device_files", "/dev/null", stat.S_IFCHR, None, 1, 2, 3),
            ("device_files", "/dev/null", stat.S_IFCHR, None, 1, 1, 9),
            ("device_files", "/dev/null", stat.S_IFREG, None, 1, 1, 3),
        ]
        rights = {
            "read_roots": boundary._READ_FILE | boundary._READ_DIR,
            "read_files": boundary._READ_FILE,
            "list_roots": boundary._READ_DIR,
            "write_roots": boundary._WRITE_DIRECTORY | boundary._READ_FILE | boundary._READ_DIR,
            "executables": boundary._EXECUTE | boundary._READ_FILE,
        }
        for role, name, mode, grant_identity, links, major, minor in specs:
            calls = []

            class Syscall:
                def __init__(self, recorded):
                    self.recorded = recorded

                restype = None

                def __call__(self, number, *args):
                    if number == 444:
                        return 3 if args[2] == 1 else 20
                    if number == 445:
                        self.recorded.append(
                            boundary.ctypes.cast(
                                args[2], boundary.ctypes.POINTER(boundary._PathRule)
                            ).contents.allowed_access
                        )
                    return 0

            plan = dict(read_roots=(), read_files=(), list_roots=(), write_roots=(), executables=(), device_files=())
            plan[role] = (Path(name),)
            if grant_identity is not None:
                plan["read_identities"] = {Path(name): grant_identity}
            evidence = types.SimpleNamespace(st_mode=mode, st_dev=1, st_ino=2, st_nlink=links, st_rdev=minor)
            access = rights.get(role, boundary._READ_FILE | (boundary._WRITE_FILE if name == "/dev/null" else 0))
            inputs = {
                "path": name,
                "access": access,
                "directory": role in {"read_roots", "list_roots", "write_roots"},
                "identity": grant_identity,
                "device": role == "device_files",
                "evidence": {"mode": mode, "device": 1, "inode": 2, "links": links, "major": major, "minor": minor},
            }

            syscall = Syscall(calls)

            def capture(plan=plan, calls=calls):
                boundary.enforce_landlock(**plan)
                return calls

            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(boundary.platform, "system", lambda: "Linux"))
                stack.enter_context(patch.object(boundary.platform, "machine", lambda: "aarch64"))
                stack.enter_context(
                    patch.object(
                        boundary.ctypes,
                        "CDLL",
                        lambda *args, syscall=syscall, **kwargs: types.SimpleNamespace(
                            syscall=syscall, prctl=lambda *args: 0
                        ),
                    )
                )
                stack.enter_context(patch.object(boundary.os, "open", lambda *args, **kwargs: 21))
                stack.enter_context(patch.object(boundary.os, "O_PATH", 0x200000, create=True))
                stack.enter_context(patch.object(boundary.os, "close", lambda *args: None))
                stack.enter_context(patch.object(boundary.os, "fstat", lambda *args, evidence=evidence: evidence))
                stack.enter_context(patch.object(boundary.os, "major", lambda *args, major=major: major))
                stack.enter_context(patch.object(boundary.os, "minor", lambda *args, minor=minor: minor))
                add("landlock_admission", inputs, capture)
        mappings = modules["restricted_linux_mappings"]
        mounts = (
            "1 0 0:1 / / rw - tmpfs tmpfs rw\n"
            "2 1 0:2 / /dev rw,nosuid - tmpfs tmpfs rw\n"
            "3 1 0:3 / /lib ro,nodev - bind bind ro\n"
            "4 1 0:4 / /space\\040name rw,nodev - bind bind rw\n"
        )
        for raw in (mounts, "", "broken", "1 0 0:1 / / ro,rw - tmpfs tmpfs rw\n"):
            add("mount_targets", {"raw": raw}, mappings.mount_targets, raw.encode())
        for options in ("rw,noatime", "ro,relatime,nodev", "rw,strictatime,nodiratime", "rw,nodev"):
            raw = f"1 0 0:1 / /lib {options} - bind bind rw\n"
            add("mount_targets", {"raw": raw}, mappings.mount_targets, raw.encode())
        record = {
            "path": str(image),
            "identity": identity,
            "sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "targets": [str(image)],
        }
        for mutation in (
            "valid",
            "unknown-field",
            "relative-path",
            "parent-path",
            "bad-hash",
            "bad-identity",
            "empty-aliases",
            "duplicate-aliases",
            "unbound-alias",
            "unbound-image",
            "duplicate-image",
        ):
            records = [copy.deepcopy(record)]
            approved = {image}
            item = records[0]
            if mutation == "unknown-field":
                item["extra"] = True
            elif mutation == "relative-path":
                item["path"] = "runner"
            elif mutation == "parent-path":
                item["path"] = str(root / "../runner")
            elif mutation == "bad-hash":
                item["sha256"] = "f" * 63
            elif mutation == "bad-identity":
                item["identity"][0] = True
            elif mutation == "empty-aliases":
                item["targets"] = []
            elif mutation == "duplicate-aliases":
                item["targets"] *= 2
            elif mutation == "unbound-alias":
                item["targets"] = [str(root / "other")]
            elif mutation == "unbound-image":
                approved = set()
            elif mutation == "duplicate-image":
                records *= 2
            add(
                "validate_records",
                {"records": records, "approved_paths": list(approved)},
                mappings.validate_records,
                records,
                approved_paths=approved,
            )
        entry = modules["restricted_linux_entry"]
        entry.PLAN_DIRECTORY = root
        plan = {
            "schema": "guard-linux-readonly-plan.v2",
            "mapping_records": [],
            "command": [str(image), "-V"],
            "read_roots": [],
            "read_files": [],
            "list_roots": [],
            "write_roots": [str(root)],
            "executables": [str(image)],
            "device_files": [],
            "read_identities": [],
            "write_identities": [[str(root), root.stat().st_dev, root.stat().st_ino]],
        }
        for mutation in (
            "valid",
            "schema",
            "missing-field",
            "extra-field",
            "relative-command",
            "nul-command",
            "negative-identity",
            "bool-identity",
            "mismatched-identity",
            "duplicate-identity",
        ):
            payload = copy.deepcopy(plan)
            if mutation == "schema":
                payload["schema"] = "guard-linux-readonly-plan.v1"
            elif mutation == "missing-field":
                del payload["mapping_records"]
            elif mutation == "extra-field":
                payload["extra"] = True
            elif mutation == "relative-command":
                payload["command"][0] = "runner"
            elif mutation == "nul-command":
                payload["command"][1] = "bad\x00"
            elif mutation == "negative-identity":
                payload["write_identities"][0][1] = -1
            elif mutation == "bool-identity":
                payload["write_identities"][0][1] = True
            elif mutation == "mismatched-identity":
                payload["write_identities"][0][0] = str(root / "other")
            elif mutation == "duplicate-identity":
                payload["write_identities"] *= 2
            raw = json.dumps(payload).encode()
            path = root / entry.PLAN_FILENAME
            path.write_bytes(raw)
            path.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            add("load_plan", {"payload": payload}, entry.load_plan, digest)
        for locator in ("../plan.json", "/etc/passwd", "A" * 64, "f" * 63, "f" * 65, "f" * 63 + "\x00"):
            add("plan_locator", {"digest": locator}, entry.load_plan, locator)
        for mutation in ("valid", "hash", "inode", "size", "mode", "symlink"):
            source = root / ("copy-" + mutation)
            data = b"approved portable fixture"
            source.write_bytes(data)
            source.chmod(0o700)
            expected_identity = list(mappings._identity(source.stat()))
            digest = hashlib.sha256(data).hexdigest()
            locator = source
            if mutation == "hash":
                digest = "0" * 64
            elif mutation == "inode":
                expected_identity[1] += 1
            elif mutation == "size":
                expected_identity[2] += 1
            elif mutation == "mode":
                expected_identity[4] ^= 0o100
            elif mutation == "symlink":
                locator = root / "copy-alias"
                locator.symlink_to(source)
            destination = root / ("sealed-" + mutation)
            try:
                descriptor = mappings._seal_copy(locator, tuple(expected_identity), digest, destination)
                try:
                    expected = {
                        "value": {
                            "bytes_hex": destination.read_bytes().hex(),
                            "mode": stat.S_IMODE(os.fstat(descriptor).st_mode),
                        }
                    }
                finally:
                    os.close(descriptor)
            except (OSError, ValueError):
                expected = {"refused": True}
            cases.append(
                {
                    "operation": "seal_copy",
                    "input": {"data_hex": data.hex(), "mutation": mutation},
                    "expected": expected,
                }
            )
        elf = modules["restricted_linux_elf"]
        for machine in (62, 183):
            identity = b"\x7fELF\x02\x01\x01" + b"\0" * 9
            header = struct.pack("<16sHHIQQQIHHHHHH", identity, 2, machine, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
            program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 120, 120, 4096)
            good = header + program
            for mutation in (
                "valid-static",
                "truncated",
                "class",
                "machine",
                "program-size",
                "no-load",
                "excessive-count",
            ):
                raw = bytearray(good)
                if mutation == "truncated":
                    raw = raw[:63]
                elif mutation == "class":
                    raw[4] = 1
                elif mutation == "machine":
                    raw[18:20] = (3).to_bytes(2, "little")
                elif mutation == "program-size":
                    raw[54:56] = (55).to_bytes(2, "little")
                elif mutation == "no-load":
                    raw[64:68] = (4).to_bytes(4, "little")
                elif mutation == "excessive-count":
                    raw[56:58] = (129).to_bytes(2, "little")
                image.write_bytes(raw)
                add("elf_loader", {"executable": image, "image_hex": raw.hex()}, elf.resolve_linux_elf_loader, image)
        paths = modules["restricted_linux_paths"]
        # The existing native secret classifier is reused by the replacement.
        # Freeze the old Python descriptor walk with declared classifier replies;
        # this recorder never invokes a resident or recalculates native policy.
        paths.classify_secret_path = lambda path, **kwargs: "fixture_secret" if Path(path).name == ".env" else None
        for mutation in (
            "ordinary",
            "credentials",
            "symlink",
            "hardlink",
            "budget",
            "root-alias",
            "parent-alias",
            "protected-root",
        ):
            workspace = root / ("tree-" + mutation)
            workspace.mkdir()
            (workspace / "source.py").write_text("fixture source")
            (workspace / "subdir").mkdir()
            (workspace / "subdir/module.py").write_text("fixture module")
            limit = 240_000
            locator = workspace
            if mutation == "credentials":
                (workspace / ".env").write_text("fixture")
                (workspace / ".ssh").mkdir()
                (workspace / ".ssh/id_rsa").write_text("fixture")
            elif mutation == "symlink":
                (workspace / "alias.py").symlink_to(workspace / "source.py")
            elif mutation == "hardlink":
                os.link(workspace / "source.py", workspace / "hardlink.py")
            elif mutation == "budget":
                limit = 1
            elif mutation == "root-alias":
                locator = root / "root-alias"
                locator.symlink_to(workspace, target_is_directory=True)
            elif mutation == "parent-alias":
                parent = root / "parent-alias"
                parent.symlink_to(workspace, target_is_directory=True)
                locator = parent / "subdir"
            elif mutation == "protected-root":
                locator = workspace / ".ssh"
                locator.mkdir()
            add(
                "read_grants",
                {"root": locator, "max_entries": limit, "fixture_tree": mutation},
                paths.collect_linux_read_grants,
                locator,
                max_entries=limit,
            )
            value = cases[-1]["expected"].get("value")
            if value is not None:
                for grant in value:
                    grant["device"], grant["inode"] = "$DEVICE", "$INODE"
    return {"schema": "linux-launch-parity.v1", "baseline": BASE, "source_sha256": hashes, "cases": cases}


if __name__ == "__main__":
    destination = ROOT / "rust/crates/guard-runtime/tests/fixtures/linux_launch_parity.json"
    destination.write_text(json.dumps(record(), indent=2, ensure_ascii=True) + "\n")

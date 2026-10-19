"""Bind optional installed policy data to both native package manifests."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import (
    MAX_BYTES,
    MAX_FILES,
    PREFIX,
    ROOT,
    asset_path,
    descriptor,
)


def binding(entries, *, source_sha, engine):
    raw = entries.get(ROOT)
    members = [name for name in entries if name.startswith(PREFIX)]
    if raw is None:
        if members:
            raise ValueError("installed policy data is missing its root")
        return None
    result = descriptor(raw, source_sha=source_sha, engine=engine)
    total = sum(len(entries[name]) for name in members)
    if len(members) > MAX_FILES + 1 or total > MAX_BYTES:
        raise ValueError("installed policy data exceeds package budgets")
    for name in members:
        if name != ROOT:
            asset_path(name[len(PREFIX) :], source_sha=source_sha)
            if not 0 < len(entries[name]) <= 32 * 1024 * 1024:
                raise ValueError("installed policy asset exceeds byte budget")
    return result


def _record_hash(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"


def _record_content(entries: dict[str, bytes], *, record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(entries):
        if name == record_path:
            continue
        content = entries[name]
        writer.writerow([name, _record_hash(content), str(len(content))])
    writer.writerow([record_path, "", ""])
    return output.getvalue().encode("utf-8")


def runtime_manifest(*, version, target, platform_tag, source_sha, rule_digest, runtime_sha256, runtime_size, bundle):
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": version,
        "target": target,
        "platform_tag": platform_tag,
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "runtime_sha256": runtime_sha256,
        "runtime_size": runtime_size,
    }
    if bundle is not None:
        manifest["command_pack_bundle"] = bundle
    return manifest


def compiler_manifest(*, runtime, implementation_digest, base_program_digest, executable):
    result = {
        key: runtime[key] for key in ("protocol_version", "package_version", "target", "platform_tag", "source_sha")
    }
    result.update(
        schema="hol-guard-native-source-compiler.v2",
        implementation_digest=implementation_digest,
        base_program_digest=base_program_digest,
        executable=executable,
        compiler_sha256=runtime["runtime_sha256"],
        compiler_size=runtime["runtime_size"],
    )
    if "command_pack_bundle" in runtime:
        result["command_pack_bundle"] = runtime["command_pack_bundle"]
    return result


def verify_engine(path, engine):
    if engine is None:
        return
    # Compiler introspection is handled before runtime/config initialization.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR"}
    }
    completed = subprocess.run(
        [str(path.resolve(strict=True)), "compiler-info"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=5,
        env=environment,
    )
    if completed.returncode or not 0 < len(completed.stdout) <= 65536:
        raise ValueError("installed bundle compiler identity probe failed")
    from codex_plugin_scanner.guard.catalog_delivery.authority import decode

    info = decode(completed.stdout)
    if (
        not isinstance(info, dict)
        or set(info) != {"schema", "implementation_digest", "embedded_catalog"}
        or info["schema"] != "guard.source-compiler-capabilities.v1"
        or info["implementation_digest"] != engine
        or type(info["embedded_catalog"]) is not bool
    ):
        raise ValueError("installed bundle engine differs from executable")


def rewrite_wheel_metadata(raw: bytes, *, platform_tag: str) -> bytes:
    lines = raw.decode("utf-8").splitlines()
    rewritten = [line for line in lines if not line.startswith("Root-Is-Purelib:") and not line.startswith("Tag:")]
    rewritten.extend(["Root-Is-Purelib: false", f"Tag: py3-none-{platform_tag}"])
    return ("\n".join(rewritten).rstrip("\n") + "\n").encode("utf-8")

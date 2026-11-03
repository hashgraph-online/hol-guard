"""Keep v1 artifacts at their original bounds during the v2 migration."""

from __future__ import annotations

import contextlib
import hashlib
import json
import subprocess
import sys

import build_native_command_program as compiler_script
import extension_artifact_bundle as bundle
from command_pack_store import PackReader
from extension_delivery_objects import entries

from codex_plugin_scanner.guard.extension_builder.io import checked_path

UNAVAILABLE = "extension-artifacts.unavailable.v1.json"


def unavailable_marker(source, code):
    return {
        "schema": "guard.extension-artifacts-unavailable.v1",
        "source_sha": source,
        "status": "unsupported-oversize",
        "code": code,
    }


# These native errors have a single, explicit aggregate budget meaning.
# Contract, ownership, trust, admission and digest errors remain fatal.
OVERSIZE = {
    "command_source_catalog_work_budget_exceeded": "source-envelope",
    "command_source_program_rule_budget_exceeded": "program-rules",
    "command_source_rule_limit_exceeded": "program-rules",
    "command_source_catalog_projection_exceeded": "catalog-bytes",
    "native_command_program_bytes_exceeded": "program-bytes",
}


def unsupported(code):
    return {"status": "unsupported-oversize", "code": code}


def preflight(policy, native):
    if native["extensions"] > 512:
        return "extension-count"
    reader = PackReader(policy / "objects")
    rules, nodes = 0, set()
    for _, reference in entries(reader, native["index"], native["extensions"]):
        manifest = reader.json(reference)
        program = reader.json(manifest["program"])
        rules += len(program["rules"])
        nodes.update(program["nodes"])
    if rules > 1024:
        return "program-rules"
    if len(nodes) > 16384:
        return "program-nodes"
    return None


def prepare(root, output, policy, native, compiler, source, *, resolve_claimants, reuse_published=False):
    def unavailable(code):
        directory = checked_path(output / "legacy")
        directory.mkdir(exist_ok=True)
        with checked_path(directory / UNAVAILABLE).open("xb") as stream:
            stream.write(json.dumps(unavailable_marker(source, code), sort_keys=True, separators=(",", ":")).encode())
        return unsupported(code)

    code = preflight(policy, native)
    if code is not None:
        return unavailable(code)
    if reuse_published:
        from extension_delivery_legacy_reuse import fetch_existing

        previous = fetch_existing(output, source, native["engine"])
        if previous is not None:
            return previous
    with (output / "legacy-build.log").open("x") as log, contextlib.redirect_stdout(log):
        try:
            result = compiler_script.main(
                ["--compiler", str(compiler), "--legacy-complete", "--check-public-descriptors"]
            )
            if result:
                raise ValueError("reviewed public descriptors differ from compiled sources")
            compiler_script.main(["--compiler", str(compiler), "--legacy-complete"])
        except compiler_script.DeliveryBudgetError as error:
            return unavailable(error.code)
        except compiler_script.NativeCompilationError as error:
            if error.code in OVERSIZE:
                return unavailable(OVERSIZE[error.code])
            raise
    # Fresh processes read the newly generated compatibility projection; they
    # cannot reuse a catalog imported before compilation in this process.
    for script in ("export_extension_directory.py", "render_command_extension_directory.py"):
        completed = subprocess.run(
            [sys.executable, str(root / "scripts" / script)], cwd=root, capture_output=True, timeout=120, check=False
        )
        if completed.returncode:
            if (
                script == "export_extension_directory.py"
                and b"Public directory exceeds its byte budget" in completed.stderr
            ):
                return unavailable("directory-bytes")
            raise ValueError("legacy projection failed: " + completed.stderr[:2048].decode(errors="replace"))
    # Preflight the unchanged archive contract before its constructor allocates
    # file contents. Other constructor errors are not treated as oversize.
    paths = [root / name for name in bundle.FILES if name != "contracts/extensions/trust-class-map.v1.json"]
    paths.extend(path for name in bundle.DIRECTORIES for path in (root / name).glob("*.json"))
    if len(paths) + 1 + int(resolve_claimants) > bundle.MAX_FILES:
        return unavailable("archive-files")
    if sum(path.stat().st_size for path in paths) > bundle.MAX_BYTES:
        return unavailable("archive-bytes")
    directory = output / "legacy"
    try:
        manifest = bundle.create_bundle(root, directory, source, resolve_claimants=resolve_claimants)
    except bundle.LegacyBundleLimitError as error:
        return unavailable(error.code)
    return {
        "status": "available",
        "manifest_sha256": hashlib.sha256((directory / bundle.MANIFEST).read_bytes()).hexdigest(),
        "archive_sha256": manifest["archive_sha256"],
        "tag": "extension-artifacts-" + source,
    }

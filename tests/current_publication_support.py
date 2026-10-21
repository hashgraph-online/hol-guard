"""Actual native compiler/factories; synthetic publisher and credential IO.

The transport uses a test HMAC attestation at the Sigstore IO seam. This proves
factory/readiness wiring, not a newly signed public Sigstore publication.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.catalog_delivery import (
    authority,
    current_refresh,
    installed_bundle,
    transport,
)
from codex_plugin_scanner.guard.catalog_delivery.installed_bundle import MANIFEST, descriptor
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as compiler
from codex_plugin_scanner.guard.native_command_control_authority_io import _LOCKS
from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
from codex_plugin_scanner.guard.store import GuardStore
from tests.extension_builder_support import use_installed_native_source_compiler
from tests.native_activation_support import BINARY, seed

SOURCE = "a" * 40
PUBLISHED_SOURCE = "b" * 40
ADDED = "command.agenticjobs"


def setup(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    import build_command_pack_bundle as builder

    package = tmp_path / "package"
    source = tmp_path / "source"
    for family in ("contributions/command-sources", "contracts/extensions/trust"):
        (source / family).mkdir(parents=True)

    def add(identity):
        for family, suffix in (("contributions/command-sources", ".json"), ("contracts/extensions/trust", ".v1.json")):
            shutil.copyfile(root / family / (identity + suffix), source / family / (identity + suffix))

    for path in sorted((root / "contributions/command-sources").glob("*.json")):
        if path.stem != ADDED and path.name != "migration-manifest.json":
            add(path.stem)
    for family in ("contributions/mcp-servers", "contracts/mcp-servers", "contracts/catalog-delivery"):
        shutil.copytree(root / family, source / family)
    for path in (root / "contracts/extensions/trust").glob("command.mcp-*.v1.json"):
        shutil.copyfile(path, source / "contracts/extensions/trust" / path.name)
    bundle = package / "guard/contracts/data/extensions/command-pack-bundle"
    bundle.parent.mkdir(parents=True)
    builder.build(BINARY, bundle, SOURCE, source_root=source)
    data = (bundle / MANIFEST).read_bytes()
    value = json.loads(data)
    engine = value["engine"]
    raw = BINARY.read_bytes()
    native = package / "_native"
    native.mkdir()
    executable = native / "hol-guard-runtime"
    executable.write_bytes(raw)
    executable.chmod(0o700)
    exported = json.loads(subprocess.check_output([str(BINARY), "export-built"]))
    program = package / "native-command-program.v1.json"
    program.write_text(json.dumps(exported["program"]))
    common = dict(
        protocol_version=1,
        package_version="3.49.0",
        source_sha=SOURCE,
        target="test",
        platform_tag="test",
        command_pack_bundle=descriptor(data, source_sha=SOURCE, engine=engine),
    )
    digest = hashlib.sha256(raw).hexdigest()
    manifests = {
        "runtime-manifest.json": dict(
            common, schema="hol-guard-native-runtime.v1", runtime_size=len(raw), runtime_sha256=digest
        ),
        "source-compiler-manifest.json": dict(
            common,
            schema="hol-guard-native-source-compiler.v2",
            compiler_size=len(raw),
            compiler_sha256=digest,
            executable="hol-guard-runtime",
            implementation_digest=engine,
            base_program_digest=exported["program"]["program_digest"],
        ),
    }
    for name, manifest in manifests.items():
        (native / name).write_text(json.dumps(manifest))
    use_installed_native_source_compiler(monkeypatch, native)
    monkeypatch.setattr(compiler, "_PACKAGED_PROGRAM", program)
    monkeypatch.setattr(installed_bundle, "_package", lambda: package)
    original = compiler.metadata.version
    monkeypatch.setattr(compiler.metadata, "version", lambda name: "3.49.0" if name == "hol-guard" else original(name))
    installed = installed_bundle.load_installed_bundle()
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    # Pin before constructing/seeding any store, with no platform credential IO.
    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", lambda self, **kw: (b"k" * 32, "test"))
    store = GuardStore(home, prime_policy_integrity=False)
    seed(
        store,
        source=SOURCE,
        installed=dict(
            profile="installed",
            source=SOURCE,
            engine=engine,
            root=installed.digest,
            version="3.49.0",
            authority=value["authority_epoch"],
            revocation=value["policy"]["revocations"]["epoch"],
        ),
    )
    provision_native_policy_verifier_key(home, b"k" * 32)
    # All production store objects for this disposable home share synthetic IO.
    add(ADDED)
    published = tmp_path / "published"
    published_assets = tmp_path / "published-assets"
    builder.build(BINARY, published, PUBLISHED_SOURCE, source_root=source, assets_output=published_assets)
    remote = json.loads((published / MANIFEST).read_bytes())
    remote.pop("compatibility", None)
    remote.update(
        schema="guard.extension-distribution.v2",
        publication_id="100.1",
        issued_at=int(time.time()) - 10,
        expires_at=int(time.time()) + 3600,
        directory=dict(
            count=remote["policy"]["root"]["extensions"],
            index=remote["policy"]["transport"],
            claims=dict(count=0, index=None),
        ),
        claim_provenance="resolved",
        legacy=dict(status="unsupported-oversize", code="program-bytes"),
    )
    state = SimpleNamespace(
        root=remote,
        assets=published_assets,
        offline=False,
        missing=False,
        calls=[],
        installed=installed,
        store=store,
        engine=engine,
        home=home,
        initial_count=value["policy"]["root"]["extensions"],
    )

    def unleased():
        key = os.path.normcase(os.path.abspath(home))
        assert key not in getattr(_LOCKS, "active", {}), "network IO under mutation lease"

    real_stage, real_prepare = current_refresh._stage, current_refresh.prepare_discovery

    @contextmanager
    def stage(*args, **kwargs):
        unleased()
        with real_stage(*args, **kwargs) as pending:
            yield pending

    def prepare(*args, **kwargs):
        unleased()
        return real_prepare(*args, **kwargs)

    monkeypatch.setattr(current_refresh, "_stage", stage)
    monkeypatch.setattr(current_refresh, "prepare_discovery", prepare)

    def signature(data):
        return hmac.new(b"synthetic-publisher", data, hashlib.sha256).hexdigest().encode()

    def attest(data, provenance, subject, source, **kw):
        assert subject == transport.ROOT_ASSET and source == PUBLISHED_SOURCE
        if not hmac.compare_digest(signature(data), provenance):
            raise ValueError("synthetic publisher attestation invalid")

    def download(url, maximum):
        unleased()
        state.calls.append(url)
        if state.offline:
            raise OSError("synthetic outage")
        data = json.dumps(state.root, sort_keys=True, separators=(",", ":")).encode()
        if "/compare/" in url:
            assert f"{SOURCE}...{PUBLISHED_SOURCE}" in url
            result = json.dumps(
                dict(
                    status="ahead",
                    base_commit=dict(sha=SOURCE),
                    merge_base_commit=dict(sha=SOURCE),
                    head_commit=dict(sha=PUBLISHED_SOURCE),
                    ahead_by=1,
                    behind_by=0,
                )
            ).encode()
        elif url.endswith(transport.FILE):
            result = json.dumps(
                dict(
                    schema="guard.extension-distribution-selector.v2",
                    source_sha=state.root["source_sha"],
                    publication_id=state.root["publication_id"],
                    root_sha256=hashlib.sha256(data).hexdigest(),
                )
            ).encode()
        elif url.endswith(transport.ROOT_ASSET):
            result = data
        elif url.endswith(transport.PROVENANCE_ASSET):
            result = b"invalid" if getattr(state, "corrupt", False) else signature(data)
        else:
            if state.missing:
                raise OSError("synthetic incomplete publication")
            tag, asset = url.rsplit("/", 2)[-2:]
            result = (state.assets / tag / asset).read_bytes()
        assert len(result) <= maximum
        return result

    monkeypatch.setattr(authority, "_verify_attested_artifact", attest)
    monkeypatch.setattr(transport, "download", download)
    return state

"""Synthetic fixed-CAS fixtures and real local native producer transport."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import extension_catalog_pages as pages

NOW = "2026-10-18T00:00:00Z"
_homes = []
ORIGINAL_NATIVE_CALL = pages.native_call


def call_native(process, home, **wire):
    """JSON-line IO only; the native process owns validation and authority."""
    process.stdin.write(json.dumps({"guard_home": str(home), **wire}, ensure_ascii=False) + "\n")
    process.stdin.flush()
    result = json.loads(process.stdout.readline())
    if result.get("error") == "catalog_limit":
        from codex_plugin_scanner.guard.runtime.extension_catalog_sync import ExtensionCatalogLimitError

        raise ExtensionCatalogLimitError("Native catalog limit")
    if "error" in result:
        raise ValueError(result["error"])
    return result["payload"]


def synthetic_completion(view, identity, observed_at, call):
    """Synthetic HTTP boundary only; real native challenge/stamp validation.

    Actual authenticated HTTP qualification must supply its server receipt.
    """
    manifest = view.manifest
    request = dict(
        token=view.token,
        observation={
            "guard_home": str(view.guard_home),
            "discovery_root": view.discovery_root,
            "discovery_authority": view.discovery_authority,
            "enforcement_catalog_digest": manifest["enforcementCatalogDigest"],
            "guard_version": manifest["guardVersion"],
            "generated_at": manifest["generatedAt"],
        },
        identity=identity,
        credential_binding="d" * 64,
        origin="https://example.test/api/guard/runtime/extension-catalog/sync-v2",
    )
    begun = call(view.guard_home, action="completion_begin", **request)
    from datetime import datetime, timezone

    observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    response = {
        "schemaVersion": "guard.extension-catalog-sync.v2",
        "accepted": True,
        "complete": True,
        "catalogDigest": manifest["catalogDigest"],
        "observation": {
            "schemaVersion": "guard.catalog-observation.v2",
            "nonce": begun["idempotencyKey"],
            "credentialBinding": request["credential_binding"],
            "identity": identity,
            **{
                k: manifest[k]
                for k in ("catalogDigest", "enforcementCatalogDigest", "guardVersion", "controlSchemaVersion")
            },
            "observedAt": observed_at,
        },
    }
    return call(view.guard_home, action="completion_accept", response=response, **request)


@pytest.fixture
def native_bridge(monkeypatch):
    binary = Path(
        os.environ.get(
            "NATIVE_CLOUD_BINARY", Path(__file__).resolve().parents[1] / "rust/target/debug/guard-cloud-catalog"
        )
    )
    if not binary.is_file():
        pytest.skip("Build guard-cloud-catalog to run actual native transport tests")
    process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    lock = threading.Lock()

    def request(home, **wire):
        with lock:
            return call_native(process, home, **wire)

    monkeypatch.setattr(pages, "native_call", request)
    from codex_plugin_scanner.guard.runtime import extension_catalog_transfer

    monkeypatch.setattr(extension_catalog_transfer, "native_call", request)
    yield request
    process.stdin.close()
    process.wait(timeout=10)
    for directory in _homes:
        directory.cleanup()
    _homes.clear()


def raw(index):
    return {
        "extension_id": f"command.scale-{index:06}",
        "name": f"Scale {index}",
        "version": "1.0.0",
        "source": "built-in",
        "executables": [f"scale-{index}"],
        "ecosystem_ids": [],
        "risk_classes": [],
        "delegated_protection": None,
        "permissions": [],
        "description": "PRIVATE-SENTINEL",
    }


def put(directory, value):
    data = pages.encoded(value)
    sha = hashlib.sha256(data).hexdigest()
    (directory / f"{sha}.json").write_bytes(data)
    return {"sha256": sha, "length": len(data), "expanded_length": len(data), "kind": "data"}


def prepare_native(
    count=166, *, home=None, generated_at=NOW, values=None, guard_version="3.49.0", enforcement_digest="a" * 64
):
    if values is not None:
        count = len(values)
    if home is None:
        directory = tempfile.TemporaryDirectory(prefix="native-cloud-test-", dir=Path(tempfile.gettempdir()).resolve())
        _homes.append(directory)
        home = Path(directory.name)
    observation = {
        "guard_home": str(home),
        "discovery_root": "b" * 64,
        "discovery_authority": "c" * 64,
        "enforcement_catalog_digest": enforcement_digest,
        "guard_version": guard_version,
        "generated_at": generated_at,
    }
    # Native initializes its private runtime/cache directories before CAS fixture IO.
    draft = pages.native_call(home, action="begin", observation=observation)["draft"]
    pages.native_call(home, action="abort", draft=draft)
    objects = home / "native-runtime/catalog-discovery/objects"
    objects.mkdir(parents=True, exist_ok=True)
    next_page = None
    for end in range(count, 0, -64):
        rows = []
        for i in range(max(0, end - 64), end):
            item = values[i] if values is not None else raw(i)
            rows.append([item["extension_id"], put(objects, item)])
        next_page = put(objects, {"schema": "guard.catalog-discovery-page.v1", "entries": rows, "next": next_page})
    root = put(
        objects, {"schema": "guard.catalog-discovery.v1", "authority": "c" * 64, "count": count, "first": next_page}
    )
    observation["discovery_root"] = root["sha256"]
    draft = pages.native_call(home, action="begin", observation=observation)["draft"]
    result = pages.native_call(home, action="finish", draft=draft)
    return pages.PreparedCatalogView.from_native(home, result)

"""Sender wire qualification with synthetic metadata and transport, no network."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest

from codex_plugin_scanner.guard.runtime.extension_catalog_handshake import prepare_extension_catalog_handshake
from codex_plugin_scanner.guard.runtime.extension_catalog_pages import encoded
from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    ExtensionCatalogLimitError,
    build_v1_catalog_from_view,
)
from codex_plugin_scanner.guard.runtime.extension_catalog_transfer import sync_catalog_view
from tests.native_cloud_helpers import native_bridge as native_bridge
from tests.native_cloud_helpers import prepare_native

NOW = "2026-10-18T00:00:00Z"
pytestmark = pytest.mark.usefixtures("native_bridge")
URL = "https://example.test/api/guard/runtime/sessions/sync?tenant=fixture"
# Independent restatement of the published v2 wire contract. The runtime keeps
# no Python copy; the native runtime is the only enforcement point.
CAPABILITY = "extension-catalog.v2"
UPLOAD_PATH = "/api/guard/runtime/extension-catalog/sync-v2"
LIMITS = {
    "maxPageEntries": 64,
    "maxPageBytes": 2 * 1024 * 1024,
    "maxEntryBytes": 1_000_000,
    "maxPages": 8192,
    "maxTotalBytes": 512 * 1024 * 1024,
}


def digest(value):
    """Independent consumer-side canonical checksum, never a sender fallback."""
    return hashlib.sha256(encoded(value)).hexdigest()


def entry(index=0):
    return {
        "id": f"command.scale-{index:06}",
        "name": f"Scale {index}",
        "version": "1.0.0",
        "source": "built-in",
        "executables": [f"scale-{index}"],
        "ecosystemIds": [],
        "riskClasses": [],
        "delegatedProtection": None,
        "deprecated": False,
        "replacementId": None,
        "permissions": [],
    }


def prepare(count=166, **kwargs):
    return prepare_native(count, **kwargs)


def view_digest(page_count, extension_count, last_page_digest):
    return digest(
        {
            "schemaVersion": "guard.extension-catalog-view.v2",
            "pageCount": page_count,
            "extensionCount": extension_count,
            "lastPageDigest": last_page_digest,
        }
    )


def posture(view):
    return {
        "managedControlsCapabilities": [CAPABILITY],
        "extensionCatalogViewDigest": view.manifest["catalogDigest"],
        "extensionCatalogEnforcementDigest": view.manifest["enforcementCatalogDigest"],
        "extensionCatalogGeneratedAt": view.manifest["generatedAt"],
        "updatedAt": view.manifest["generatedAt"],
    }


def signal(view, known=False):
    return {
        "extensionCatalogSync": {
            "protocolVersion": CAPABILITY,
            "catalogDigest": view.manifest["catalogDigest"],
            "catalogKnown": known,
            "uploadRequired": not known,
            "uploadPath": UPLOAD_PATH,
            "limits": dict(LIMITS),
        }
    }


class Receiver:
    """Independent bounded ordered-chain consumer; completion is atomic here."""

    def __init__(self):
        self.requests = []
        self.pages = {}
        self.accepted = False
        self.manifest = None

    def send(self, url, body):
        assert url == URL.replace("/sessions/sync", "/extension-catalog/sync-v2")
        assert len(body) <= LIMITS["maxPageBytes"] + 1024
        value = json.loads(body)
        self.requests.append(value)
        operation = value["operation"]
        if operation == "begin":
            if self.manifest is not None:
                assert self.manifest == value["manifest"]
            self.manifest = value["manifest"]
        elif operation == "page":
            page = value["page"]
            if page["ordinal"] in self.pages:
                assert self.pages[page["ordinal"]] == page
            self.pages[page["ordinal"]] = page
        else:
            previous = None
            previous_id = ""
            count = total = 0
            assert len(self.pages) == self.manifest["pageCount"]
            for ordinal in range(len(self.pages)):
                page = self.pages[ordinal]
                assert page["ordinal"] == ordinal
                assert page["previousDigest"] == previous
                payload = {key: item for key, item in page.items() if key != "pageDigest"}
                canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                assert page["pageDigest"] == hashlib.sha256(canonical).hexdigest()
                assert 0 < len(page["entries"]) <= 64
                total += len(encoded(page))
                assert len(encoded(page)) <= LIMITS["maxPageBytes"]
                for item in page["entries"]:
                    assert item["id"] > previous_id
                    previous_id = item["id"]
                    count += 1
                previous = page["pageDigest"]
            assert total <= LIMITS["maxTotalBytes"]
            assert count == self.manifest["extensionCount"]
            assert previous == self.manifest["lastPageDigest"]
            assert view_digest(len(self.pages), count, previous) == self.manifest["catalogDigest"]
            self.accepted = True
        return {
            "schemaVersion": "guard.extension-catalog-sync.v2",
            "catalogDigest": self.manifest["catalogDigest"],
            "accepted": True,
            "complete": self.accepted,
        }


def sync(view, send, **kwargs):
    return sync_catalog_view(
        view=view,
        runtime_sync_url=kwargs.get("url", URL),
        runtime_response=kwargs.get("response", signal(view)),
        session_payload=kwargs.get("session", posture(view)),
        send=send,
    )


@pytest.mark.parametrize("count", [1, 64, 65, 166, 1660, 16600])
def test_complete_scale_and_deterministic_pagination(count):
    view = prepare(count)
    again = prepare(count)
    assert view.manifest == again.manifest
    assert view.manifest["pageCount"] == (count + 63) // 64
    receiver = Receiver()
    assert sync(view, receiver.send)["extension_catalog_sync_status"] == "uploaded"
    assert receiver.accepted
    assert [v["page"] for v in receiver.requests if v["operation"] == "page"] == list(again.pages())


@pytest.mark.parametrize("count", [512, 513, 1660])
def test_old_server_uses_same_complete_view_or_explicit_unsupported(count):
    view = prepare(count)
    session = posture(view)
    if count <= 512:
        catalog = build_v1_catalog_from_view(view)
        session["extensionCatalogDigest"] = catalog["catalogDigest"]
        assert len(catalog["extensions"]) == count
    else:
        with pytest.raises(ExtensionCatalogLimitError):
            build_v1_catalog_from_view(view)
    response = {
        "extensionCatalogSync": {
            "catalogDigest": session.get("extensionCatalogDigest"),
            "catalogKnown": False,
            "uploadRequired": True,
            "uploadPath": "/api/guard/runtime/extension-catalog/sync",
        }
    }
    summary, upload = prepare_extension_catalog_handshake(
        runtime_sync_url=URL,
        runtime_response=response,
        session_payload=session,
        catalog_factory=lambda _: build_v1_catalog_from_view(view),
        fallback_generated_at=NOW,
    )
    if count > 512:
        assert summary["extension_catalog_sync_status"] == "unsupported"
        assert upload is None
    else:
        assert len(json.loads(upload.body)["catalog"]["extensions"]) == count


@pytest.mark.parametrize("fault_at", ["begin", "page", "complete"])
def test_transport_failure_never_reports_success_and_retry_reuses_bytes(fault_at):
    view = prepare(166)
    receiver = Receiver()

    def fail(url, body):
        if json.loads(body)["operation"] == fault_at:
            raise OSError("synthetic transport loss")
        return receiver.send(url, body)

    with pytest.raises(OSError):
        sync(view, fail)
    assert not receiver.accepted
    if fault_at != "complete":
        assert not any(request["operation"] == "complete" for request in receiver.requests)
    sync(view, receiver.send)
    assert receiver.accepted
    assert len({request["idempotencyKey"] for request in receiver.requests}) == 1


def test_lost_completion_ack_replays_identical_observation():
    view = prepare(166)
    receiver = Receiver()

    def lost_ack(url, body):
        result = receiver.send(url, body)
        if json.loads(body)["operation"] == "complete":
            raise OSError("accepted completion acknowledgement lost")
        return result

    with pytest.raises(OSError):
        sync(view, lost_ack)
    assert receiver.accepted
    original = deepcopy(receiver.requests)
    assert sync(view, receiver.send)["extension_catalog_sync_status"] == "uploaded"
    assert receiver.requests[len(original) :] == original


@pytest.mark.parametrize("change", ["digest", "extra", "bool", "limits", "limitbool", "path", "protocol"])
def test_exact_handshake_validation(change):
    view = prepare(1)
    response = signal(view)
    target = response["extensionCatalogSync"]
    if change == "digest":
        target["catalogDigest"] = "d" * 64
    elif change == "extra":
        target["extra"] = True
    elif change == "bool":
        target["catalogKnown"] = 0
    elif change == "limits":
        target["limits"]["extra"] = 0
    elif change == "limitbool":
        target["limits"]["maxPages"] = True
    elif change == "path":
        target["uploadPath"] = "https://untrusted.test" + UPLOAD_PATH
    else:
        target["protocolVersion"] = "extension-catalog.v3"
    with pytest.raises(ValueError, match="^catalog_invalid$"):
        sync(view, lambda *_: pytest.fail("invalid handshake sent bytes"), response=response)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/api/guard/runtime/sessions/sync",
        "https://user@example.test/api/guard/runtime/sessions/sync",
        "https://example.test/api/guard/runtime/sessions/sync#fragment",
        "https://example.test/other",
        "https://example.test:bad/api/guard/runtime/sessions/sync",
        "https:///api/guard/runtime/sessions/sync",
    ],
)
def test_origin_path_guard(url):
    with pytest.raises(ValueError, match="^catalog_invalid$"):
        sync(prepare(1), lambda *_: pytest.fail("invalid origin sent bytes"), url=url)


@pytest.mark.parametrize("field", ["accepted", "complete", "catalogDigest", "schemaVersion", "extra"])
def test_exact_completion_response(field):
    view = prepare(1)
    receiver = Receiver()

    def send(url, body):
        response = receiver.send(url, body)
        if json.loads(body)["operation"] == "complete":
            response[field] = False
        return response

    with pytest.raises(ValueError, match="^catalog_invalid$"):
        sync(view, send)


def test_immutable_manifest_page_tampering_and_observed_identity_binding():
    view = prepare(166)
    manifest = view.manifest
    manifest["catalogDigest"] = "d" * 64
    assert view.manifest != manifest
    session = posture(view)
    session["extensionCatalogEnforcementDigest"] = "f" * 64
    with pytest.raises(ValueError, match="^catalog_invalid$"):
        sync(view, lambda *_: pytest.fail("changed posture sent bytes"), session=session)
    path = view.guard_home / "native-runtime/cloud-catalog" / view.token / "1.json"
    original = path.read_bytes()
    path.write_bytes(original.replace(b"Scale", b"Other", 1))
    receiver = Receiver()
    with pytest.raises(ValueError):
        sync(view, receiver.send)
    assert not receiver.accepted
    assert not any(request["operation"] == "complete" for request in receiver.requests)


def test_known_view_needs_no_upload_and_identity_is_separate_from_enforcement():
    view = prepare(1)
    assert (
        sync(view, lambda *_: pytest.fail("known view uploaded"), response=signal(view, True))[
            "extension_catalog_sync_status"
        ]
        == "already_known"
    )
    manifest = deepcopy(view.manifest)
    manifest["enforcementCatalogDigest"] = "d" * 64
    assert (
        view_digest(manifest["pageCount"], manifest["extensionCount"], manifest["lastPageDigest"])
        == manifest["catalogDigest"]
    )
    assert digest(manifest) != digest(view.manifest)


def test_concurrent_native_transfers_replay_one_pinned_view():
    view = prepare(166)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: sync(view, Receiver().send), range(2)))
    assert all(value["extension_catalog_sync_status"] == "uploaded" for value in results)


def test_native_large_pages_cross_resident_chunk_boundary():
    from codex_plugin_scanner.guard.runtime import extension_catalog_pages as pages
    from tests.native_cloud_helpers import raw

    base = prepare(1)
    observation = {
        "guard_home": str(base.guard_home),
        "discovery_root": base.discovery_root,
        "discovery_authority": base.discovery_authority,
        "enforcement_catalog_digest": "a" * 64,
        "guard_version": "3.49.0",
        "generated_at": NOW,
    }
    draft = pages.native_call(base.guard_home, action="begin", observation=observation)["draft"]
    for i in range(4):
        item = raw(i)
        item["executables"] = [f"{j:03}" + "x" * 8000 for j in range(100)]
        pages.native_call(base.guard_home, action="append", draft=draft, entry=item)
    view = pages.PreparedCatalogView.from_native(
        base.guard_home, pages.native_call(base.guard_home, action="finish", draft=draft)
    )
    assert view.manifest["pageCount"] == 2
    assert len(view.request_bytes("page", 0)) > 1024 * 1024
    receiver = Receiver()
    assert sync(view, receiver.send)["extension_catalog_sync_status"] == "uploaded"
    assert receiver.accepted

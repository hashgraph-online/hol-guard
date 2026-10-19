"""Bounded data-only public exports with independently pinned custody anchors.

Integrity is exploratory evidence, never qualification authority. The existing
Gauntlet current-base/reviewed-bootstrap trust policy remains untouched. Only an
independently eligible consumer can promote this profile after review.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bundle_io import MAX_FILES, _path, _read, _tree
from .campaign import verify_campaign
from .contracts import MAX_RECORD_BYTES, ContractError, canonical_json, digest, validate_record
from .world import verify_receipts

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
SOURCE_KEYS = {
    "candidate",
    "product",
    "policy",
    "harness",
    "model",
    "services",
    "observer",
    "oracle",
    "verifier",
    "native_build",
}
KINDS = {
    "workflow",
    "authorization",
    "attack",
    "snapshot",
    "capabilities",
    "approval",
    "event",
    "episode",
    "scorecard",
    "campaign",
    "world-snapshot",
    "world-receipts",
}
_HASH = re.compile(r"^[a-f0-9]{64}$")
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SECRET_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "password",
    "provider_credentials",
    "credentials",
    "environment",
    "env",
}
_SECRET_TEXT = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|"
    r"Bearer\s+[A-Za-z0-9+/_.=-]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _safe(value):
    try:
        canonical_json(value)
    except UnicodeError as error:
        raise ContractError("invalid Unicode in bundle data") from error
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            for key, child in item.items():
                if key.casefold() in _SECRET_KEYS or (key.casefold() == "authorization" and type(child) is str):
                    raise ContractError("provider credentials/environment fields cannot be exported")
                pending.append(child)
        elif type(item) is list:
            pending.extend(item)
        elif type(item) is str and _SECRET_TEXT.search(item):
            raise ContractError("credential-like material cannot be publicly exported")


def _decode(raw):
    if len(raw) > MAX_RECORD_BYTES:
        raise ContractError("bundle file exceeds byte limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError("duplicate JSON object key")
            result[key] = value
        return result

    def constant(_value):
        raise ContractError("non-finite JSON number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ContractError("invalid bounded bundle JSON") from error
    _safe(value)
    return value


def _identities(value):
    if type(value) is not dict or set(value) != SOURCE_KEYS:
        raise ContractError("exact frozen source/build identities are required")
    if any(type(item) is not str or not _HASH.fullmatch(item) for item in value.values()):
        raise ContractError("source/build identities must be SHA-256 digests")


def _anchors(value):
    if type(value) is not dict or len(value) > 128:
        raise ContractError("invalid effect anchors")
    for name, anchor in value.items():
        if type(name) is not str or not _SEGMENT.fullmatch(name):
            raise ContractError("invalid anchored effect stream identity")
        if type(anchor) is not dict or set(anchor) != {"public_key", "receipt_count", "final_hash"}:
            raise ContractError("invalid effect anchor fields")
        if type(anchor["receipt_count"]) is not int or not 0 <= anchor["receipt_count"] <= 100000:
            raise ContractError("invalid anchored effect count")
        if type(anchor["final_hash"]) is not str or not _HASH.fullmatch(anchor["final_hash"]):
            raise ContractError("invalid effect final hash")
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(anchor["public_key"], validate=True))
        except (TypeError, ValueError) as error:
            raise ContractError("invalid independently pinned effect public key") from error


def _payload(value, anchors):
    if type(value) is not dict or set(value) != {"schema_version", "kind", "stream_id", "records"}:
        raise ContractError("invalid evidence file fields")
    if value["schema_version"] != "1.0" or type(value["kind"]) is not str or value["kind"] not in KINDS:
        raise ContractError("unsupported data-only evidence kind")
    rows = value["records"]
    if type(rows) is not list or len(rows) > 100000:
        raise ContractError("unbounded evidence records")
    _safe(value)
    kind = value["kind"]
    if kind == "world-receipts":
        if type(value["stream_id"]) is not str or not _SEGMENT.fullmatch(value["stream_id"]):
            raise ContractError("invalid effect stream identity")
        anchor = anchors.get(value["stream_id"])
        if anchor is None:
            raise ContractError("effect stream lacks independent anchor")
        for row in rows:
            if type(row) is not dict or set(row) != {"event", "signature"}:
                raise ContractError("invalid signed world receipt fields")
            event_fields = {
                "sequence",
                "previous_hash",
                "request_id",
                "operation",
                "actor",
                "args_digest",
                "raw_args_digest",
                "before",
                "after",
                "effect",
                "status",
                "result_digest",
            }
            if type(row["event"]) is not dict or set(row["event"]) != event_fields:
                raise ContractError("invalid world receipt event fields")
        try:
            verify_receipts(
                rows,
                base64.b64decode(anchor["public_key"], validate=True),
                expected_count=anchor["receipt_count"],
                expected_final_hash=anchor["final_hash"],
            )
        except (ValueError, TypeError, KeyError, InvalidSignature) as error:
            raise ContractError("effect signature/chain/count/anchor mismatch") from error
    elif value["stream_id"] is not None:
        raise ContractError("only world receipts may name an effect stream")
    elif kind == "world-snapshot":
        for row in rows:
            if type(row) is not dict or set(row) != {"schema", "workflow_id", "actor_id", "provider_scope", "records"}:
                raise ContractError("invalid data-only world snapshot fields")
            if row["schema"] != "gauntlet-workflow-snapshot.v1" or type(row["records"]) is not list:
                raise ContractError("incompatible world snapshot")
            ids = set()
            for record in row["records"]:
                if type(record) is not dict or set(record) != {
                    "id",
                    "collection",
                    "tenant_id",
                    "owner_id",
                    "version",
                    "acl",
                    "data",
                }:
                    raise ContractError("invalid world state record fields")
                if type(record["id"]) is not str or record["id"] in ids or type(record["version"]) is not int:
                    raise ContractError("invalid or duplicate world state identity")
                ids.add(record["id"])
    else:
        for row in rows:
            validate_record(kind, row)
    return value


def _manifest(record):
    required = {
        "schema_version",
        "profile",
        "files",
        "campaign_digest",
        "inventory_digest",
        "scheduled_episodes",
        "source_identities",
        "effect_anchors",
    }
    if type(record) is not dict or set(record) != required or record["schema_version"] != "1.0":
        raise ContractError("invalid signed bundle manifest fields")
    if record["profile"] != "gauntlet-workflow-public-bundle.v1":
        raise ContractError("unsupported evidence profile")
    _identities(record["source_identities"])
    _anchors(record["effect_anchors"])
    if type(record["files"]) is not list or not 1 <= len(record["files"]) < MAX_FILES:
        raise ContractError("unbounded bundle manifest inventory")
    if type(record["scheduled_episodes"]) is not int or not 0 <= record["scheduled_episodes"] <= 100000:
        raise ContractError("invalid scheduled inventory count")
    for field in ("campaign_digest", "inventory_digest"):
        if type(record[field]) is not str or not _HASH.fullmatch(record[field]):
            raise ContractError("invalid campaign/inventory digest")
    names = set()
    for item in record["files"]:
        if type(item) is not dict or set(item) != {"path", "digest", "bytes", "records", "kind", "stream_id"}:
            raise ContractError("invalid file manifest fields")
        _path(item["path"])
        if type(item["kind"]) is not str or item["kind"] not in KINDS:
            raise ContractError("invalid manifest evidence kind")
        if item["stream_id"] is not None and type(item["stream_id"]) is not str:
            raise ContractError("invalid manifest stream identity")
        if item["path"] == "manifest.json" or item["path"] in names:
            raise ContractError("reserved or duplicate manifest path")
        names.add(item["path"])
        if type(item["digest"]) is not str or not _HASH.fullmatch(item["digest"]):
            raise ContractError("invalid file digest")
        for field, limit in [("bytes", MAX_RECORD_BYTES), ("records", 100000)]:
            if type(item[field]) is not int or not 0 <= item[field] <= limit:
                raise ContractError("invalid file size/count")
    if any(name.startswith(other + "/") for name in names for other in names if name != other):
        raise ContractError("bundle file path conflicts with a directory")
    return names


def _bind_inventory(campaign, episodes):
    assigned = {row["id"]: row for row in campaign["inventory"]}
    seen = set()
    for episode in episodes:
        if episode["id"] in seen or episode["id"] not in assigned:
            raise ContractError("duplicate or unscheduled episode evidence")
        seen.add(episode["id"])
        row = assigned[episode["id"]]
        if episode["campaign_id"] != campaign["id"] or any(
            episode[field] != row[field]
            for field in ("workflow_id", "variant", "condition", "repetition", "snapshot_id")
        ):
            raise ContractError("episode does not bind the frozen campaign inventory")
    return seen


def export_bundle(
    destination: str | Path,
    payloads: dict,
    *,
    campaign: dict,
    source_identities: dict,
    effect_anchors: dict,
    controller_key: Ed25519PrivateKey,
) -> dict:
    """Create a new directory of validated JSON; no raw logs, archives or secrets.

    Payload values are {kind, records, stream_id}; use stream_id=None except for
    world-receipts. campaign.json and manifest.json are reserved controller files.
    """
    campaign = verify_campaign(campaign)
    _identities(source_identities)
    _anchors(effect_anchors)
    if campaign["frozen_inputs"] != source_identities:
        raise ContractError("campaign/source/build revisions do not match")
    if type(payloads) is not dict or len(payloads) >= MAX_FILES - 1:
        raise ContractError("unbounded export inventory")
    values = dict(payloads)
    if {"manifest.json", "campaign.json"} & values.keys():
        raise ContractError("reserved export path")
    values["campaign.json"] = {"kind": "campaign", "records": [campaign], "stream_id": None}
    encoded, entries, episode_rows = {}, [], []
    for name in sorted(values):
        _path(name)
        descriptor = values[name]
        if type(descriptor) is not dict or set(descriptor) != {"kind", "records", "stream_id"}:
            raise ContractError("invalid export descriptor")
        payload = _payload({"schema_version": "1.0", **descriptor}, effect_anchors)
        if payload["kind"] == "episode":
            episode_rows.extend(payload["records"])
        raw = (canonical_json(payload) + "\n").encode("utf-8")
        encoded[name] = raw
        entries.append(
            {
                "path": name,
                "digest": _sha(raw),
                "bytes": len(raw),
                "records": len(payload["records"]),
                "kind": payload["kind"],
                "stream_id": payload["stream_id"],
            }
        )
    _bind_inventory(campaign, episode_rows)
    streams = [item["stream_id"] for item in entries if item["kind"] == "world-receipts"]
    if len(streams) != len(set(streams)) or set(streams) != set(effect_anchors):
        raise ContractError("missing or duplicate independently anchored effect stream")
    record = {
        "schema_version": "1.0",
        "profile": "gauntlet-workflow-public-bundle.v1",
        "files": entries,
        "campaign_digest": digest(campaign),
        "inventory_digest": campaign["inventory_digest"],
        "scheduled_episodes": len(campaign["inventory"]),
        "source_identities": source_identities,
        "effect_anchors": effect_anchors,
    }
    _manifest(record)
    envelope = {"record": record, "signature": controller_key.sign(canonical_json(record).encode()).hex()}
    encoded["manifest.json"] = (canonical_json(envelope) + "\n").encode("utf-8")
    if sum(len(raw) for raw in encoded.values()) > MAX_BUNDLE_BYTES:
        raise ContractError("bundle exceeds total byte budget")
    destination = Path(destination).absolute()
    if any(parent.is_symlink() for parent in [destination, *destination.parents]):
        raise ContractError("symlink export destination is forbidden")
    destination.mkdir()
    for name, raw in encoded.items():
        path = destination.joinpath(*_path(name))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)
    return {
        "manifest_digest": _sha(encoded["manifest.json"]),
        "files": len(encoded),
        "bytes": sum(len(raw) for raw in encoded.values()),
        "qualification_eligible": False,
    }


def verify_bundle(
    directory: str | Path,
    *,
    trusted_public_key: bytes,
    expected_manifest_digest: str,
    expected_source_identities: dict,
    expected_effect_anchors: dict,
) -> dict:
    """Verify data with external anchors; never import candidate evaluators."""
    _identities(expected_source_identities)
    _anchors(expected_effect_anchors)
    directory = Path(directory).absolute()
    if any(parent.is_symlink() for parent in [directory, *directory.parents]):
        raise ContractError("symlink bundle root is forbidden")
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = _tree(root)
        raw = _read(root, "manifest.json")
        if _sha(raw) != expected_manifest_digest:
            raise ContractError("independently expected manifest digest mismatch")
        envelope = _decode(raw)
        if type(envelope) is not dict or set(envelope) != {"record", "signature"}:
            raise ContractError("invalid signed manifest envelope")
        record = envelope["record"]
        listed = _manifest(record)
        try:
            Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
                bytes.fromhex(envelope["signature"]), canonical_json(record).encode()
            )
        except (InvalidSignature, ValueError, TypeError) as error:
            raise ContractError("manifest signature is not independently trusted") from error
        if record["source_identities"] != expected_source_identities:
            raise ContractError("mixed source revision or mismatched binary identity")
        if record["effect_anchors"] != expected_effect_anchors:
            raise ContractError("effect anchors do not match independent custody")
        if names != listed | {"manifest.json"}:
            raise ContractError("missing or unlisted bundle files")
        total, streams, episode_ids = len(raw), set(), set()
        campaigns, episodes = [], []
        for item in record["files"]:
            content = _read(root, item["path"])
            total += len(content)
            if total > MAX_BUNDLE_BYTES or len(content) != item["bytes"] or _sha(content) != item["digest"]:
                raise ContractError("file digest/size or total bundle budget mismatch")
            value = _payload(_decode(content), expected_effect_anchors)
            if (len(value["records"]), value["kind"], value["stream_id"]) != (
                item["records"],
                item["kind"],
                item["stream_id"],
            ):
                raise ContractError("file record count/kind/stream mismatch")
            if value["kind"] == "world-receipts":
                if value["stream_id"] in streams:
                    raise ContractError("duplicate anchored effect stream")
                streams.add(value["stream_id"])
            if value["kind"] == "campaign":
                campaigns.extend(value["records"])
            if value["kind"] == "episode":
                for episode in value["records"]:
                    if episode["id"] in episode_ids:
                        raise ContractError("duplicate scheduled episode evidence")
                    episode_ids.add(episode["id"])
                    episodes.append(episode)
        if streams != set(expected_effect_anchors):
            raise ContractError("missing independently anchored effect stream")
        if len(campaigns) != 1:
            raise ContractError("bundle requires exactly one frozen campaign")
        campaign = verify_campaign(campaigns[0])
        if (digest(campaign), campaign["inventory_digest"], len(campaign["inventory"])) != (
            record["campaign_digest"],
            record["inventory_digest"],
            record["scheduled_episodes"],
        ):
            raise ContractError("campaign/inventory anchor mismatch")
        if campaign["frozen_inputs"] != expected_source_identities:
            raise ContractError("campaign/source/build identity mismatch")
        assigned_rows = {row["id"]: row for row in campaign["inventory"]}
        assigned = set(assigned_rows)
        if not episode_ids.issubset(assigned):
            raise ContractError("evidence contains unscheduled episodes")
        _bind_inventory(campaign, episodes)
        return {
            "integrity": "valid",
            "completeness": "complete" if episode_ids == assigned else "incomplete",
            "profile": record["profile"],
            "files": len(names),
            "scheduled_episodes": len(assigned),
            "recorded_episodes": len(episode_ids),
            "missing_episodes": sorted(assigned - episode_ids),
            "qualification_eligible": False,
            "status": "exploratory",
            "reason": "requires an independently reviewed eligible trusted consumer",
        }
    except OSError as error:
        raise ContractError("bundle filesystem integrity failure") from error
    finally:
        os.close(root)

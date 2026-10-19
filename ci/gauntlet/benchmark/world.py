"""Transactional synthetic provider state; no outbound provider operations.

Signing keys belong to the trusted service controller, never database state or
the task workspace. A pinned external public key is required to verify receipts.
Provider permissions deliberately exceed task delegation to measure protection.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .contracts import canonical_json

COLLECTIONS = {
    "mail": {"mail.messages", "mail.drafts", "mail.outbox"},
    "crm": {"crm.contacts", "crm.accounts"},
    "calendar": {"calendar.events", "calendar.availability"},
    "docs": {"docs.documents"},
    "tables": {"tables.sheets"},
    "chat": {"chat.messages", "chat.drafts"},
    "tickets": {"tickets.tickets"},
}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class World:
    """A service-side database with atomic state/evidence/idempotency commits."""

    def __init__(self, path: Path | str, signing_key: Ed25519PrivateKey):
        self.path = Path(path).resolve()
        if not self.path.is_file():
            raise ValueError("world database must exist")
        self.key = signing_key
        with self._connection() as conn:
            row = conn.execute("SELECT value FROM meta WHERE id=1").fetchone()
            self.meta = json.loads(row[0])
        if self.meta["producer"] != self.public_key():
            raise ValueError("controller signing identity mismatch")
        self.actor = self.meta["actor_id"]

    def public_key(self) -> str:
        return base64.b64encode(self.key.public_key().public_bytes_raw()).decode()

    @classmethod
    def create(cls, path: Path | str, snapshot: dict, *, signing_key: Ed25519PrivateKey) -> World:
        path = Path(path).resolve()
        meta = copy.deepcopy(snapshot)
        records = meta.pop("records")
        if meta.get("schema") != "gauntlet-workflow-snapshot.v1":
            raise ValueError("unsupported seed snapshot")
        ids = set()
        for record in records:
            family = record["collection"].split(".")[0]
            if record["collection"] not in COLLECTIONS.get(family, set()):
                raise ValueError("unknown seed collection")
            if record["tenant_id"] not in meta["provider_scope"]["tenants"]:
                raise ValueError("seed outside provider scope")
            if record["id"] in ids:
                raise ValueError("duplicate seed record")
            ids.add(record["id"])
            cls._validate_data(record["data"])
        # Exclusive creation prevents accidental replacement of episode state.
        with path.open("xb"):
            pass
        meta["producer"] = base64.b64encode(signing_key.public_key().public_bytes_raw()).decode()
        with sqlite3.connect(path) as conn:
            conn.executescript("""
                CREATE TABLE meta(id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE records(id TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE journal(sequence INTEGER PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE cached(id TEXT PRIMARY KEY, digest TEXT NOT NULL,
                                    result TEXT NOT NULL);
            """)
            conn.execute("INSERT INTO meta VALUES (1, ?)", (json.dumps(meta),))
            for record in records:
                family = record["collection"].split(".")[0]
                if record["collection"] not in COLLECTIONS.get(family, set()):
                    raise ValueError("unknown seed collection")
                if record["tenant_id"] not in meta["provider_scope"]["tenants"]:
                    raise ValueError("seed outside provider scope")
                conn.execute("INSERT INTO records VALUES (?, ?)", (record["id"], json.dumps(record)))
        return cls(path, signing_key)

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def inspect(self, record_id: str) -> dict | None:
        """Controller metadata lookup, never a model-visible unobserved read."""
        with self._connection() as conn:
            row = conn.execute("SELECT value FROM records WHERE id=?", (record_id,)).fetchone()
            return json.loads(row[0]) if row else None

    def snapshot(self) -> dict:
        with self._connection() as conn:
            records = [json.loads(row[0]) for row in conn.execute("SELECT value FROM records ORDER BY id")]
        meta = {k: copy.deepcopy(v) for k, v in self.meta.items() if k != "producer"}
        return {**meta, "records": records}

    def receipts(self) -> list[dict]:
        with self._connection() as conn:
            return [json.loads(row[0]) for row in conn.execute("SELECT value FROM journal ORDER BY sequence")]

    def _record(self, conn, record_id: str, family: str, mode="read") -> dict:
        row = conn.execute("SELECT value FROM records WHERE id=?", (record_id,)).fetchone()
        if not row:
            raise ValueError("record not found")
        record = json.loads(row[0])
        if record["collection"] not in COLLECTIONS[family]:
            raise ValueError("record belongs to another service")
        if self.actor not in record["acl"][mode] and not (mode == "read" and "*" in record["acl"][mode]):
            raise PermissionError("provider ACL denied")
        return record

    def call(self, operation: str, args: dict, request_id: str | int) -> Any:
        with self._connection() as conn:
            return self.execute_on_connection(conn, operation, args, request_id)

    def execute_on_connection(self, conn: sqlite3.Connection, operation: str, args: dict, request_id: str | int) -> Any:
        """Trusted controller seam; caller owns the transaction and connection."""
        family, _, method = operation.partition(".")
        if family not in COLLECTIONS:
            raise ValueError("unknown service")
        if not isinstance(args, dict) or len(canonical_json(args)) > 1_000_000:
            raise ValueError("invalid or oversized arguments")
        raw_args_digest = _digest(args)
        args = copy.deepcopy(args)
        cache_id = args.pop("idempotency_key", None)
        identity = _digest({"operation": operation, "args": args, "actor": self.actor})
        if cache_id:
            cached = conn.execute("SELECT digest,result FROM cached WHERE id=?", (cache_id,)).fetchone()
            if cached:
                if cached[0] != identity:
                    raise ValueError("idempotency key reused for a different operation")
                return json.loads(cached[1])
        result, before, after, effect = self._perform(conn, family, method, args)
        last = conn.execute("SELECT sequence,value FROM journal ORDER BY sequence DESC LIMIT 1").fetchone()
        event = {
            "sequence": last[0] + 1 if last else 1,
            "previous_hash": _digest(json.loads(last[1])) if last else "0" * 64,
            "request_id": request_id,
            "operation": operation,
            "actor": self.actor,
            "args_digest": identity,
            "raw_args_digest": raw_args_digest,
            "before": before,
            "after": after,
            "effect": effect,
            "status": "ok",
            "result_digest": _digest(result),
        }
        receipt = {
            "event": event,
            "signature": base64.b64encode(self.key.sign(canonical_json(event).encode("utf-8"))).decode(),
        }
        conn.execute("INSERT INTO journal VALUES (?,?)", (event["sequence"], json.dumps(receipt)))
        if cache_id:
            conn.execute("INSERT INTO cached VALUES (?,?,?)", (cache_id, identity, json.dumps(result)))
        return result

    def _perform(self, conn, family, method, args):
        if method == "search":
            return self._search(conn, family, args)
        if method in {"create", "create_draft", "post"}:
            collection = args.get("collection")
            if method == "create_draft":
                collection = "mail.drafts"
            if method == "post":
                collection = "chat.messages"
            if collection not in COLLECTIONS[family]:
                raise ValueError("invalid service collection")
            tenant = args.get("tenant_id", "task-tenant")
            if tenant not in self.meta["provider_scope"]["tenants"]:
                raise PermissionError("tenant outside provider scope")
            data = args.get("data", {})
            self._validate_data(data)
            if collection in {"mail.drafts", "chat.drafts"}:
                data.setdefault("state", "draft")
                data.setdefault("visibility", "internal")
            elif collection in {"docs.documents", "tables.sheets"}:
                data.setdefault("visibility", "private")
            record = {
                "id": args["record_id"],
                "collection": collection,
                "tenant_id": tenant,
                "owner_id": self.actor,
                "version": 1,
                "acl": {"read": [self.actor], "write": [self.actor]},
                "data": data,
            }
            conn.execute("INSERT INTO records VALUES (?,?)", (record["id"], json.dumps(record)))
            return record, None, record, "create"
        before = self._record(
            conn, args["record_id"], family, "read" if method in {"read", "read_attachment"} else "write"
        )
        if method in {"read", "read_attachment"}:
            result = before
            if method == "read_attachment":
                result = next(
                    (a for a in before["data"].get("attachments", []) if a["id"] == args["attachment_id"]), None
                )
                if result is None:
                    raise ValueError("attachment not found")
            elif args.get("fields"):
                result = {**before, "data": {k: before["data"][k] for k in args["fields"] if k in before["data"]}}
            observed = (
                {
                    "id": before["id"],
                    "collection": before["collection"],
                    "version": before["version"],
                    "parent_record": before,
                    "attachment": result,
                }
                if method == "read_attachment"
                else result
            )
            return result, None, observed, "read"
        if args.get("expected_version") != before["version"]:
            raise ValueError("stale or missing expected version")
        if method == "delete":
            conn.execute("DELETE FROM records WHERE id=?", (before["id"],))
            return {"deleted": before["id"]}, before, None, "delete"
        after = copy.deepcopy(before)
        if method == "send" and family == "mail":
            if before["collection"] != "mail.drafts":
                raise ValueError("send requires a persisted draft")
            if not before["data"].get("recipients"):
                raise ValueError("send requires recipients")
            after["collection"] = "mail.outbox"
            after["data"]["state"] = "sent"
        elif method == "invite" and family == "calendar":
            after["data"]["state"] = "invited"
        elif method == "set_permissions" and family == "docs":
            permissions = args["permissions"]
            if not isinstance(permissions, list) or len(permissions) > 256:
                raise ValueError("permissions must be a bounded principal list")
            readers, writers = {before["owner_id"]}, {before["owner_id"]}
            normalized = []
            seen = set()
            for permission in permissions:
                item = {"principal_id": permission, "role": "reader"} if isinstance(permission, str) else permission
                if not isinstance(item, dict) or set(item) != {"principal_id", "role"}:
                    raise ValueError("invalid permission fields")
                principal, role = item["principal_id"], item["role"]
                if not isinstance(principal, str) or not principal or principal == "*" or principal in seen:
                    raise ValueError("invalid or duplicate permission principal")
                if role not in {"owner", "reader", "viewer", "writer", "editor"}:
                    raise ValueError("unsupported permission role")
                if role == "owner" and principal != before["owner_id"]:
                    raise ValueError("document owner is immutable")
                seen.add(principal)
                readers.add(principal)
                if role in {"owner", "writer", "editor"}:
                    writers.add(principal)
                normalized.append({**item, "role": "owner"} if principal == before["owner_id"] else dict(item))
            if before["owner_id"] not in seen:
                normalized.append({"principal_id": before["owner_id"], "role": "owner"})
            visibility = args.get("visibility", "private")
            if visibility not in {"private", "internal", "public", "link"}:
                raise ValueError("unsupported document visibility")
            if visibility in {"public", "link"}:
                readers.add("*")
            after["acl"] = {"read": sorted(readers), "write": sorted(writers)}
            after["data"]["permissions"] = normalized
            after["data"]["visibility"] = visibility
        elif method == "update":
            self._validate_data(args["data"])
            after["data"].update(args["data"])
        else:
            raise ValueError("unsupported operation")
        self._validate_data(after["data"])
        after["version"] += 1
        conn.execute("UPDATE records SET value=? WHERE id=?", (json.dumps(after), after["id"]))
        return after, before, after, "update"

    @staticmethod
    def _validate_data(data):
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        for field in ("recipients", "attendees"):
            values = data.get(field, [])
            if not isinstance(values, list) or any(
                not isinstance(v, str)
                or not (
                    ("@" in v and v.endswith(".test"))
                    or (field == "attendees" and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", v))
                )
                for v in values
            ):
                raise ValueError("only synthetic .test destinations are accepted")

    def _search(self, conn, family, args):
        collection = args["collection"]
        if collection not in COLLECTIONS[family]:
            raise ValueError("invalid service collection")
        limit = args.get("limit", 20)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        query = args.get("query", "").casefold()
        records = [json.loads(row[0]) for row in conn.execute("SELECT value FROM records ORDER BY id")]
        records = [
            r
            for r in records
            if r["collection"] == collection
            and (self.actor in r["acl"]["read"] or "*" in r["acl"]["read"])
            and (not args.get("tenant_id") or r["tenant_id"] == args["tenant_id"])
            and query in json.dumps(r["data"]).casefold()
        ]
        fingerprint = _digest(
            {"query": query, "collection": collection, "tenant": args.get("tenant_id"), "records": records}
        )
        offset = 0
        if args.get("cursor"):
            try:
                envelope = json.loads(base64.b64decode(args["cursor"], validate=True))
                cursor = envelope["cursor"]
                self.key.public_key().verify(
                    base64.b64decode(envelope["signature"], validate=True), canonical_json(cursor).encode("utf-8")
                )
                offset = cursor["offset"]
                if cursor["fingerprint"] != fingerprint or type(offset) is not int or not 0 <= offset < len(records):
                    raise ValueError("stale cursor")
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError("invalid or stale cursor") from exc
            except Exception as exc:
                from cryptography.exceptions import InvalidSignature

                if isinstance(exc, InvalidSignature):
                    raise ValueError("invalid cursor signature") from exc
                raise
        page = records[offset : offset + limit]
        next_offset = offset + len(page)
        cursor = None
        if next_offset < len(records):
            value = {"offset": next_offset, "fingerprint": fingerprint}
            envelope = {
                "cursor": value,
                "signature": base64.b64encode(self.key.sign(canonical_json(value).encode("utf-8"))).decode(),
            }
            cursor = base64.b64encode(canonical_json(envelope).encode("utf-8")).decode()
        if args.get("fields"):
            page = [{**r, "data": {k: r["data"][k] for k in args["fields"] if k in r["data"]}} for r in page]
        result = {"records": page, "next_cursor": cursor}
        return result, None, {"record_ids": [r["id"] for r in page]}, "search"


def verify_receipts(receipts: list[dict], public_key: bytes, *, expected_count: int, expected_final_hash: str) -> None:
    """Verify against separately pinned custody anchors, including truncation."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = Ed25519PublicKey.from_public_bytes(public_key)
    previous = "0" * 64
    if len(receipts) != expected_count:
        raise ValueError("receipt count mismatch")
    for index, receipt in enumerate(receipts, 1):
        event = receipt["event"]
        if event["sequence"] != index or event["previous_hash"] != previous:
            raise ValueError("receipt chain mismatch")
        key.verify(base64.b64decode(receipt["signature"], validate=True), canonical_json(event).encode("utf-8"))
        previous = _digest(receipt)
    if previous != expected_final_hash:
        raise ValueError("receipt anchor mismatch")

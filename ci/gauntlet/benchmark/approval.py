"""External approval authority and transactional, fail-closed claim ledger.

The controller lives outside the evaluated agent. Keys are generated in memory,
never persisted here, and never inferred from MCP content. A caller supplies a
trusted public anchor independently of the signed grant. ``claim`` reserves a
use; a cached claim must never cause a second effect. ``execute`` atomically
stores the receipt and use for mutations performed in its SQLite transaction.
External effects require their own durable operation-id idempotency contract.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .contracts import ContractError, canonical_json, digest

_REQUEST_FIELDS = {
    "actor",
    "operation",
    "target_ids",
    "recipients",
    "payload_digest",
    "policy_version",
    "state_versions",
}
_GRANT_FIELDS = {
    "schema_version",
    "request",
    "request_digest",
    "decision",
    "issued_at",
    "expires_at",
    "nonce",
    "max_uses",
}
_HEX = re.compile(r"^[a-f0-9]{64}$")


class ApprovalError(ContractError):
    """Missing authority, expired scope, replay, or invalid approval data."""


def _text(value, name):
    if type(value) is not str or not value or len(value) > 512:
        raise ApprovalError(f"{name} must be a nonempty bounded string")
    return value


def _integer(value, name, lower=0, upper=10**12):
    if type(value) is not int or not lower <= value <= upper:
        raise ApprovalError(f"{name} must be an integer in {lower}..{upper}")
    return value


def validate_request(request: dict) -> dict:
    canonical_json(request)
    if type(request) is not dict or set(request) != _REQUEST_FIELDS:
        raise ApprovalError("approval request has missing or unknown fields")
    for field in ("actor", "operation", "policy_version"):
        _text(request[field], field)
    for field in ("target_ids", "recipients"):
        values = request[field]
        if type(values) is not list or len(values) > 256:
            raise ApprovalError(f"{field} must be a bounded list")
        for value in values:
            _text(value, field)
        if len(set(values)) != len(values):
            raise ApprovalError(f"{field} must not contain duplicates")
    if not request["target_ids"]:
        raise ApprovalError("approval must bind at least one target")
    if type(request["payload_digest"]) is not str or not _HEX.fullmatch(request["payload_digest"]):
        raise ApprovalError("payload_digest must be SHA-256")
    states = request["state_versions"]
    if type(states) is not dict or not 1 <= len(states) <= 256:
        raise ApprovalError("state_versions must be a nonempty bounded mapping")
    for key, value in states.items():
        _text(key, "state resource")
        _text(value, "state version")
    # These are sets in the approval contract, irrespective of caller order.
    normalized = json.loads(canonical_json(request))
    normalized["target_ids"].sort()
    normalized["recipients"].sort()
    return normalized


class ApprovalController:
    """Trusted deterministic scenario controller; never accept model decisions."""

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._private_key = private_key or Ed25519PrivateKey.generate()

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def issue(self, request: dict, *, decision: str, now: int, lifetime_seconds: int = 60, max_uses: int = 1) -> dict:
        request = validate_request(request)
        _integer(now, "now")
        _integer(lifetime_seconds, "lifetime_seconds", 1, 86400)
        _integer(now + lifetime_seconds, "expires_at")
        _integer(max_uses, "max_uses", 1, 100)
        if decision not in ("granted", "denied", "expired", "no-response"):
            raise ApprovalError("unknown controller decision")
        record = {
            "schema_version": "1.0",
            "request": request,
            "request_digest": digest(request),
            "decision": decision,
            "issued_at": now,
            "expires_at": now + lifetime_seconds,
            "nonce": str(uuid.uuid4()),
            "max_uses": max_uses,
        }
        signature = self._private_key.sign(canonical_json(record).encode("utf-8")).hex()
        return {"record": record, "signature": signature}

    def attest_claim(self, ledger: ApprovalLedger, operation_id: str, *, now: int) -> dict:
        """Sign only a durable claim row from the externally protected ledger.

        This is a trusted controller export, never a signer for caller-provided
        ClaimResult objects. Ledger files must remain outside agent file access.
        """
        _text(operation_id, "operation_id")
        _integer(now, "now")
        if ledger.trusted_public_key != self.public_key_bytes():
            raise ApprovalError("ledger anchor does not match attesting controller")
        connection = ledger._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT claim_digest, receipt, claimed_at FROM approval_claims WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise ApprovalError("no durable approval claim for operation")
            if now < row[2]:
                raise ApprovalError("claim attestation precedes its committed effect")
            record = {
                "schema_version": "1.0",
                "status": "claimed",
                "operation_id": operation_id,
                "claim_digest": row[0],
                "receipt": json.loads(row[1]) if row[1] else None,
                "applied_at": row[2],
                "attested_at": now,
            }
            encoded = canonical_json(record).encode("utf-8")
            signature = self._private_key.sign(encoded).hex()
            connection.commit()
            return {"record": record, "signature": signature}
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def verify_grant(grant: dict, request: dict, *, trusted_public_key: bytes, now: int) -> dict:
    """Verify an externally anchored grant and every bound request field."""
    return verify_decision(grant, request, trusted_public_key=trusted_public_key, now=now, expected_decision="granted")


def verify_decision(grant: dict, request: dict, *, trusted_public_key: bytes, now: int, expected_decision: str) -> dict:
    """Verify a signed controller grant or refusal against exact expected scope."""
    if expected_decision not in ("granted", "denied", "expired", "no-response"):
        raise ApprovalError("unknown expected controller decision")
    request = validate_request(request)
    _integer(now, "now")
    canonical_json(grant)
    if type(grant) is not dict or set(grant) != {"record", "signature"}:
        raise ApprovalError("signed grant has missing or unknown fields")
    record = grant["record"]
    if type(record) is not dict or set(record) != _GRANT_FIELDS or record["schema_version"] != "1.0":
        raise ApprovalError("incompatible or unknown grant fields")
    bound = validate_request(record["request"])
    if bound != record["request"] or record["request_digest"] != digest(bound):
        raise ApprovalError("grant request digest mismatch")
    _text(record["nonce"], "nonce")
    _integer(record["issued_at"], "issued_at")
    _integer(record["expires_at"], "expires_at")
    _integer(record["max_uses"], "max_uses", 1, 100)
    if type(grant["signature"]) is not str or len(grant["signature"]) != 128:
        raise ApprovalError("invalid signature encoding")
    try:
        key = Ed25519PublicKey.from_public_bytes(trusted_public_key)
        key.verify(bytes.fromhex(grant["signature"]), canonical_json(record).encode("utf-8"))
    except (InvalidSignature, TypeError, ValueError) as error:
        raise ApprovalError("invalid signature or untrusted signer") from error
    if record["decision"] != expected_decision:
        raise ApprovalError(f"controller did not grant expected decision: {record['decision']}")
    if record["expires_at"] <= record["issued_at"] or not record["issued_at"] <= now < record["expires_at"]:
        raise ApprovalError("approval expired or not yet valid")
    if bound != request:
        raise ApprovalError("approval scope/payload/policy/state does not match request")
    return json.loads(canonical_json(record))


def verify_claim_evidence(
    evidence: dict,
    *,
    trusted_public_key: bytes,
    operation_id: str,
    claim_digest: str,
    now: int,
    max_age_seconds: int = 300,
) -> dict:
    """Authenticate a ledger export using independently expected claim identity.

    This verifies custody and consumption. The scorer must still reconcile its
    effect receipt against the signed world journal and the original grant.
    """
    canonical_json(evidence)
    _text(operation_id, "operation_id")
    _integer(now, "now")
    _integer(max_age_seconds, "max_age_seconds", 0, 86400)
    if type(claim_digest) is not str or not _HEX.fullmatch(claim_digest):
        raise ApprovalError("expected claim digest must be SHA-256")
    if type(evidence) is not dict or set(evidence) != {"record", "signature"}:
        raise ApprovalError("claim evidence has missing or unknown fields")
    record = evidence["record"]
    fields = {"schema_version", "status", "operation_id", "claim_digest", "receipt", "applied_at", "attested_at"}
    if type(record) is not dict or set(record) != fields or record["schema_version"] != "1.0":
        raise ApprovalError("incompatible or unknown claim evidence fields")
    if record["status"] != "claimed" or type(record["receipt"]) not in (dict, type(None)):
        raise ApprovalError("invalid committed claim status/receipt")
    _integer(record["applied_at"], "applied_at")
    _integer(record["attested_at"], "attested_at")
    if type(evidence["signature"]) is not str or len(evidence["signature"]) != 128:
        raise ApprovalError("invalid claim signature encoding")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            bytes.fromhex(evidence["signature"]), canonical_json(record).encode("utf-8")
        )
    except (InvalidSignature, TypeError, ValueError) as error:
        raise ApprovalError("invalid claim signature or untrusted controller") from error
    if record["operation_id"] != operation_id or record["claim_digest"] != claim_digest:
        raise ApprovalError("claim evidence does not match expected operation/claim identity")
    if not record["applied_at"] <= record["attested_at"] <= now:
        raise ApprovalError("claim evidence has impossible/future timestamps")
    if now - record["attested_at"] > max_age_seconds:
        raise ApprovalError("claim attestation is stale")
    return json.loads(canonical_json(record))


@dataclass(frozen=True)
class ClaimResult:
    status: str
    claim_digest: str
    receipt: dict | None = None


class ApprovalLedger:
    """Durable claim uniqueness; BEGIN IMMEDIATE serializes concurrent claims."""

    def __init__(self, db_path: str | Path, trusted_public_key: bytes):
        if str(db_path) == ":memory:":
            raise ApprovalError("ledger requires a durable database path")
        # Validate and freeze the independently provisioned anchor, not a grant key.
        Ed25519PublicKey.from_public_bytes(trusted_public_key)
        self._public_key = bytes(trusted_public_key)
        self._path = str(db_path)
        connection = self._connect()
        try:
            connection.execute("""CREATE TABLE IF NOT EXISTS approval_claims (
                operation_id TEXT PRIMARY KEY, nonce TEXT NOT NULL,
                claim_digest TEXT NOT NULL, receipt TEXT, claimed_at INTEGER NOT NULL)""")
            connection.execute("CREATE INDEX IF NOT EXISTS approval_nonce ON approval_claims(nonce)")
        finally:
            connection.close()

    @property
    def database_path(self) -> Path:
        return Path(self._path).resolve()

    @property
    def trusted_public_key(self) -> bytes:
        return self._public_key

    def _connect(self):
        connection = sqlite3.connect(self._path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def claim(self, grant: dict, request: dict, *, operation_id: str, now: int) -> ClaimResult:
        """Reserve a use. Only status=claimed authorizes one new effect."""
        return self._claim(grant, request, operation_id=operation_id, now=now, effect=None)

    def execute(
        self, grant: dict, request: dict, *, operation_id: str, now: int,
        effect: Callable[[sqlite3.Connection], dict], clock: Callable[[], int] | None = None,
    ) -> ClaimResult:
        """Commit a trusted SQLite mutation and receipt with the approval claim.

        The callback must perform its mutation using the supplied connection,
        must not commit/rollback independently, and must return an inert receipt.
        External network effects are outside this transaction's atomicity.
        A trusted controller clock revalidates after lock acquisition and after
        the staged mutation. Expiry rolls back the effect, journal and claim.
        Omitted clock preserves historical deterministic scalar-time evidence.
        """
        return self._claim(grant, request, operation_id=operation_id, now=now, effect=effect, clock=clock)

    def _claim(self, grant, request, *, operation_id, now, effect, clock=None):
        record = verify_grant(grant, request, trusted_public_key=self._public_key, now=now)
        _text(operation_id, "operation_id")
        claim_digest = digest({"grant": grant, "request": validate_request(request), "operation_id": operation_id})
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if clock is not None:
                locked_at = _integer(clock(), 'controller transaction time')
                if locked_at < now:
                    raise ApprovalError('controller clock moved backwards before transaction')
                now = locked_at
                record = verify_grant(grant, request, trusted_public_key=self._public_key, now=now)
            existing = connection.execute(
                "SELECT claim_digest, receipt FROM approval_claims WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if existing is not None:
                if existing[0] != claim_digest:
                    raise ApprovalError("operation_id reused for a different claim")
                connection.commit()
                return ClaimResult("cached", claim_digest, json.loads(existing[1]) if existing[1] else None)
            uses = connection.execute(
                "SELECT COUNT(*) FROM approval_claims WHERE nonce=?", (record["nonce"],)
            ).fetchone()[0]
            if uses >= record["max_uses"]:
                raise ApprovalError("approval replay: allowed uses exhausted")
            receipt = effect(connection) if effect is not None else None
            if effect is not None and type(receipt) is not dict:
                raise ApprovalError("trusted effect must return a JSON receipt object")
            serialized = canonical_json(receipt) if receipt is not None else None
            if clock is not None:
                applied_at = _integer(clock(), 'controller application time')
                if applied_at < now:
                    raise ApprovalError('controller clock moved backwards during transaction')
                verify_grant(grant, request, trusted_public_key=self._public_key, now=applied_at)
                now = applied_at
            connection.execute(
                "INSERT INTO approval_claims VALUES (?, ?, ?, ?, ?)",
                (operation_id, record["nonce"], claim_digest, serialized, now),
            )
            connection.commit()
            return ClaimResult("claimed", claim_digest, json.loads(serialized) if serialized else None)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

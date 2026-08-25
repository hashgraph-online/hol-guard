from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Mapping
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from lab_support import _redact_detail, _safe_identifier, atomic, json_bytes

from codex_plugin_scanner.guard.mdm.cloud_control import (
    ENROLL_SCHEMA,
    ContractError,
    iso,
    load_public_pem,
    parse_time,
    public_pem,
    utcnow,
    verify_proof,
)


class StoreBase:
    """Identity, persistence, enrollment, request proof, and audit foundations."""

    def __init__(self, path: Path, key_path: Path, seeds: list[dict[str, str]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.lock = threading.RLock()
        self.key_path = key_path
        self.key = self._load_or_create_key()
        self._schema()
        self._seed(seeds)

    def _db(self) -> sqlite3.Connection:
        database = sqlite3.connect(self.path, timeout=10)
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA journal_mode=WAL")
        database.execute("PRAGMA synchronous=FULL")
        database.execute("PRAGMA foreign_keys=ON")
        return database

    def _load_or_create_key(self) -> rsa.RSAPrivateKey:
        if self.key_path.exists():
            if self.key_path.is_symlink():
                raise ContractError("cloud_signing_key_symlink")
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ContractError("cloud_signing_key_invalid")
            return key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        atomic(
            self.key_path,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        return key

    def _schema(self) -> None:
        with self._db() as database:
            database.executescript(
                """
                CREATE TABLE IF NOT EXISTS seeds(
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  token_hash TEXT NOT NULL,
                  used INTEGER NOT NULL DEFAULT 0,
                  PRIMARY KEY(workspace, device, generation)
                );
                CREATE TABLE IF NOT EXISTS devices(
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  key_id TEXT NOT NULL,
                  public_key TEXT NOT NULL UNIQUE,
                  last_seq INTEGER NOT NULL DEFAULT 0,
                  enrolled_at TEXT NOT NULL,
                  PRIMARY KEY(workspace, device, generation)
                );
                CREATE TABLE IF NOT EXISTS policies(
                  workspace TEXT NOT NULL,
                  revision INTEGER NOT NULL,
                  policy TEXT NOT NULL,
                  policy_hash TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  PRIMARY KEY(workspace, revision)
                );
                CREATE TABLE IF NOT EXISTS assignments(
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  revision INTEGER NOT NULL,
                  policy_hash TEXT NOT NULL,
                  previous_hash TEXT,
                  envelope TEXT NOT NULL,
                  assigned_at TEXT NOT NULL,
                  PRIMARY KEY(workspace, device, generation)
                );
                CREATE TABLE IF NOT EXISTS assignment_history(
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  revision INTEGER NOT NULL,
                  policy_hash TEXT NOT NULL,
                  previous_hash TEXT,
                  envelope TEXT NOT NULL,
                  assigned_at TEXT NOT NULL,
                  PRIMARY KEY(workspace, device, generation, revision)
                );
                CREATE TABLE IF NOT EXISTS acks(
                  request_id TEXT PRIMARY KEY,
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  revision INTEGER NOT NULL,
                  policy_hash TEXT NOT NULL,
                  status TEXT NOT NULL,
                  payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS health(
                  request_id TEXT NOT NULL UNIQUE,
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  sequence INTEGER NOT NULL,
                  payload TEXT NOT NULL,
                  PRIMARY KEY(workspace, device, generation, sequence)
                );
                CREATE TABLE IF NOT EXISTS jobs(
                  job_id TEXT PRIMARY KEY,
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  generation TEXT NOT NULL,
                  payload TEXT NOT NULL,
                  status TEXT NOT NULL,
                  result TEXT,
                  idempotency_key TEXT NOT NULL UNIQUE,
                  created_at TEXT NOT NULL,
                  verified_at TEXT
                );
                CREATE TABLE IF NOT EXISTS audit(
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event TEXT NOT NULL,
                  workspace TEXT NOT NULL,
                  device TEXT NOT NULL,
                  detail TEXT NOT NULL,
                  at TEXT NOT NULL,
                  previous_hash TEXT,
                  event_hash TEXT NOT NULL UNIQUE
                );
                """
            )

    def _seed(self, seeds: list[dict[str, str]]) -> None:
        with self._db() as database:
            for seed in seeds:
                workspace = _safe_identifier(seed.get("workspaceId"), "workspace")
                device = _safe_identifier(seed.get("deviceId"), "device")
                generation = _safe_identifier(seed.get("installationGeneration"), "generation")
                token = seed.get("token")
                if not isinstance(token, str) or len(token) < 16:
                    raise ContractError("enrollment_seed_invalid")
                database.execute(
                    "INSERT OR IGNORE INTO seeds VALUES(?,?,?,?,0)",
                    (
                        workspace,
                        device,
                        generation,
                        hashlib.sha256(token.encode("utf-8")).hexdigest(),
                    ),
                )

    def audit(self, event: str, workspace: str, device: str, detail: Mapping[str, object]) -> None:
        safe_event = _safe_identifier(event, "audit_event")
        redacted = _redact_detail(dict(detail))
        at = iso(utcnow())
        with self.lock, self._db() as database:
            previous = database.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
            previous_hash = previous["event_hash"] if previous else None
            event_hash = hashlib.sha256(
                json_bytes(
                    {
                        "at": at,
                        "detail": redacted,
                        "device": device,
                        "event": safe_event,
                        "previousHash": previous_hash,
                        "workspace": workspace,
                    }
                )
            ).hexdigest()
            database.execute(
                "INSERT INTO audit(event,workspace,device,detail,at,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
                (
                    safe_event,
                    workspace,
                    device,
                    json.dumps(redacted, sort_keys=True),
                    at,
                    previous_hash,
                    event_hash,
                ),
            )

    def verify_audit_chain(self) -> bool:
        with self.lock, self._db() as database:
            rows = list(database.execute("SELECT * FROM audit ORDER BY id"))
            previous_hash: str | None = None
            for row in rows:
                try:
                    detail = json.loads(row["detail"])
                except (TypeError, json.JSONDecodeError):
                    return False
                if not isinstance(detail, dict):
                    return False
                expected = hashlib.sha256(
                    json_bytes(
                        {
                            "at": row["at"],
                            "detail": detail,
                            "device": row["device"],
                            "event": row["event"],
                            "previousHash": previous_hash,
                            "workspace": row["workspace"],
                        }
                    )
                ).hexdigest()
                if row["previous_hash"] != previous_hash or row["event_hash"] != expected:
                    return False
                previous_hash = expected
        return True

    def enroll(self, payload: Mapping[str, object]) -> dict[str, object]:
        expected = {
            "schemaVersion",
            "workspaceId",
            "deviceId",
            "installationGeneration",
            "keyId",
            "publicKeyPem",
            "token",
        }
        if set(payload) != expected or payload.get("schemaVersion") != ENROLL_SCHEMA:
            raise ContractError("enrollment_invalid")
        workspace = _safe_identifier(payload.get("workspaceId"), "workspace")
        device = _safe_identifier(payload.get("deviceId"), "device")
        generation = _safe_identifier(payload.get("installationGeneration"), "generation")
        key_id = _safe_identifier(payload.get("keyId"), "key_id")
        public_key_pem = payload.get("publicKeyPem")
        token = payload.get("token")
        if not isinstance(public_key_pem, str) or not isinstance(token, str):
            raise ContractError("enrollment_invalid")
        key = load_public_pem(public_key_pem)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ContractError("enrollment_key_invalid")
        with self.lock, self._db() as database:
            seed = database.execute(
                "SELECT * FROM seeds WHERE workspace=? AND device=? AND generation=?",
                (workspace, device, generation),
            ).fetchone()
            if not seed or seed["used"] or seed["token_hash"] != hashlib.sha256(token.encode("utf-8")).hexdigest():
                raise ContractError("enrollment_denied", 401)
            try:
                database.execute(
                    "INSERT INTO devices VALUES(?,?,?,?,?,0,?)",
                    (workspace, device, generation, key_id, public_key_pem, iso(utcnow())),
                )
                database.execute(
                    "UPDATE seeds SET used=1 WHERE workspace=? AND device=? AND generation=?",
                    (workspace, device, generation),
                )
            except sqlite3.IntegrityError as error:
                raise ContractError("enrollment_key_or_identity_reused", 409) from error
        self.audit("device_enrolled", workspace, device, {"generation": generation, "keyId": key_id})
        return {
            "schemaVersion": "hol-guard-mdm-enrollment-result.v1",
            "cloudPublicKeyPem": public_pem(self.key.public_key()),
            "signingKeyId": "lab-cloud-rsa-1",
        }

    def authenticate(
        self,
        headers: Mapping[str, str],
        method: str,
        path: str,
        body: bytes,
    ) -> tuple[str, str, str]:
        workspace = headers.get("x-hol-workspace-id")
        device = headers.get("x-hol-device-id")
        generation = headers.get("x-hol-installation-generation")
        sequence = headers.get("x-hol-request-sequence")
        observed_at = headers.get("x-hol-request-time")
        signature = headers.get("x-hol-request-signature")
        proof_values = (
            workspace,
            device,
            generation,
            sequence,
            observed_at,
            signature,
        )
        if not all(isinstance(value, str) and value for value in proof_values):
            raise ContractError("request_proof_missing", 401)
        assert isinstance(workspace, str)
        assert isinstance(device, str)
        assert isinstance(generation, str)
        assert isinstance(sequence, str)
        assert isinstance(observed_at, str)
        assert isinstance(signature, str)
        try:
            sequence_number = int(sequence)
        except ValueError as error:
            raise ContractError("request_sequence_invalid", 401) from error
        if sequence_number < 1:
            raise ContractError("request_sequence_invalid", 401)
        if abs((utcnow() - parse_time(observed_at, "request_time_invalid")).total_seconds()) > 300:
            raise ContractError("request_time_invalid", 401)
        with self.lock, self._db() as database:
            row = database.execute(
                "SELECT * FROM devices WHERE workspace=? AND device=? AND generation=?",
                (workspace, device, generation),
            ).fetchone()
            if not row:
                raise ContractError("device_binding_unknown", 401)
            if sequence_number <= row["last_seq"]:
                raise ContractError("request_replay", 409)
            key = load_public_pem(row["public_key"])
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise ContractError("device_key_invalid", 401)
            verify_proof(key, signature, method, path, body, sequence_number, observed_at)
            database.execute(
                "UPDATE devices SET last_seq=? WHERE workspace=? AND device=? AND generation=?",
                (sequence_number, workspace, device, generation),
            )
        return workspace, device, generation

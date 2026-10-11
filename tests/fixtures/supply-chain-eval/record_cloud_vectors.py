"""Record cloud-connected supply-chain evaluation vectors from the Python evaluator.

Provenance tool, not part of the test suite. It must run against a checkout
that still contains the Python evaluator
(``src/codex_plugin_scanner/guard/runtime/supply_chain_package_eval.py`` at
commit 7a712222b1), for example::

    PYTHONPATH=<base-worktree>/src python record_cloud_vectors.py cloud-cases.v1.json

Every case seeds a real ``GuardStore`` through its public API, snapshots the
seeded rows, then evaluates with the Python evaluator and records the full
result. The vectors are language-neutral; nothing here is replayed in tests.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from cloud_vector_cases import BASE_COMMIT, CONNECTED, NOW, TABLES, WORKSPACE_ID, cases
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.runtime.supply_chain_package_services import _workspace_fingerprint

from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime import runner as guard_runner
from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    build_package_request_artifact,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.package_target_support import recorded_target


def artifact_for(targets: list[str], lockfile_paths: list[str]) -> object:
    tokens = ("npm", "install", *targets)
    intent = PackageIntent(
        package_manager="npm",
        intent_kind="install",
        command_tokens=tokens,
        redacted_command=" ".join(tokens),
        targets=tuple(recorded_target("npm", target) for target in targets),
        manifest_paths=(),
        lockfile_paths=tuple(lockfile_paths),
        flags=(),
        notes=(),
    )
    return build_package_request_artifact("codex", intent, config_path="codex.json", source_scope="project")


class _Handler(BaseHTTPRequestHandler):
    spec: ClassVar[dict[str, object]] = {}
    seen: ClassVar[list[dict[str, object]]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
        type(self).seen.append({"path": self.path.split("?")[0], "body": json.loads(body)})
        if type(self).spec.get("mode") == "dropped":
            self.connection.close()
            return
        payload = json.dumps(type(self).spec.get("payload", {})).encode("utf-8")
        self.send_response(int(type(self).spec.get("status", 200)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, message_format: str, *args: object) -> None:
        del message_format, args


def snapshot(db_path: Path) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY 1")] for table in TABLES
        }
    finally:
        connection.close()


def ddl(db_path: Path) -> dict[str, str]:
    connection = sqlite3.connect(db_path)
    try:
        return {
            name: sql
            for name, sql in connection.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
            if name in (*TABLES, "guard_evidence", "guard_events")
        }
    finally:
        connection.close()


def record(spec: dict[str, object], root: Path) -> tuple[dict[str, object], dict[str, str]]:
    home = root / spec["name"] / "home"
    workspace = root / spec["name"] / "ws"
    home.mkdir(parents=True)
    workspace.mkdir()
    for file_name, text in spec["files"].items():
        (workspace / file_name).write_text(text, encoding="utf-8")
    os.environ["HOL_GUARD_TEST_KEYRING_FILE"] = str(root / spec["name"] / "keyring.json")
    store = GuardStore(home)
    store.set_sync_payload("oauth_local_credentials", CONNECTED, NOW)
    artifact = artifact_for(spec["targets"], spec["lockfile_paths"])
    if spec["bundle"] is not None:
        store.cache_supply_chain_bundle(WORKSPACE_ID, spec["bundle"], spec["bundle_cached_at"])
    if spec["eval_cache"]:
        cached_code = (
            "cloud_validation_error" if spec["eval_cache"] == "cloud_validation_error" else "known_malware_or_kev"
        )
        intent_hash = str(artifact.artifact_id).rsplit(":", 1)[-1]
        fingerprint = _workspace_fingerprint(
            WORKSPACE_ID, workspace_dir=workspace, artifact=artifact, bundle_meta={"policy_hash": "policy-hash-1"}
        )
        store.cache_supply_chain_evaluation(
            workspace_id=WORKSPACE_ID,
            package_intent_hash=intent_hash,
            feed_snapshot_hash="feed-snapshot-1",
            policy_hash="policy-hash-1",
            scoring_version="scf-v1",
            bundle_version="1747612800000-deadbeef",
            decision={
                "decision": "block",
                "policy_action": "block",
                "enforcement": "offline_cached",
                "entitlement_state": "premium",
                "cache_status": "hit",
                "workspace_fingerprint": fingerprint,
                "reasons": [{"code": cached_code, "message": "Prototype pollution in minimist"}],
                "packages": [{"name": "minimist", "decision": "block", "recommendedFixVersion": "1.2.9"}],
                "matched_rule_id": None,
                "exception_id": None,
                "risk_summary": "HOL Guard blocked `minimist@1.2.8` before install.",
                "record_monitor_evidence": False,
                "user_copy": {
                    "title": "Critical install blocked",
                    "summary": "minimist needs a safer version before you continue.",
                    "next_step": "npm install minimist@1.2.9",
                    "dashboard_url": "https://hol.org/guard/inbox",
                    "harness_message": "HOL Guard blocked `minimist@1.2.8` before install.",
                },
            },
            now=NOW,
        )
    db_path = home / "guard.db"
    rows = snapshot(db_path)
    if spec["policy"] is not None:
        store.upsert_policy(
            PolicyDecision(harness="codex", scope="global", action=spec["policy"]["action"], source="manual"),
            NOW,
        )
    server = None
    network = spec["network"]
    _Handler.seen = []
    guard_runner._test_sync_auth_context_override = None
    if network is not None:
        _Handler.spec = network
        server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        guard_runner._test_sync_auth_context_override = {
            "sync_url": f"http://127.0.0.1:{server.server_port}/api/guard/receipts/sync",
            "access_token": "demo-token",
            "dpop_key_material": None,
        }
    original_entitlement = evaluator.resolve_package_firewall_entitlement
    lookups: list[object] = []
    original_lookup = store.resolve_policy_decision_lookup

    def recording_lookup(*args: object, **kwargs: object) -> object:
        lookup = original_lookup(*args, **kwargs)
        lookups.append(lookup["decision"])
        return lookup

    store.resolve_policy_decision_lookup = recording_lookup
    if spec["entitlement"] is not None:
        evaluator.resolve_package_firewall_entitlement = lambda _store: dict(spec["entitlement"])
    try:
        result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace, now=NOW)
    finally:
        evaluator.resolve_package_firewall_entitlement = original_entitlement
        guard_runner._test_sync_auth_context_override = None
        if server is not None:
            server.shutdown()
            server.server_close()
    entry = {
        "name": spec["name"],
        "targets": spec["targets"],
        "lockfile_paths": spec["lockfile_paths"],
        "artifact": artifact.to_dict(),
        "files": {file_name: {"text": text} for file_name, text in spec["files"].items()},
        "rows": rows,
        "saved_policy": spec["policy"],
        "saved_policy_probe": {"decision": lookups[0]} if lookups else None,
        "entitlement": spec["entitlement"],
        "network": network,
        "cloud_request_paths": [seen["path"] for seen in _Handler.seen],
        "cloud_requests": [seen["body"] for seen in _Handler.seen],
        "expect": result.to_dict(),
        "events": [event["event_name"] for event in store.list_events()],
    }
    return entry, ddl(db_path)


def main() -> None:
    # The store honors a file-backed test keyring under pytest only; it mints the
    # policy integrity key the saved-policy lookup needs.
    os.environ["PYTEST_CURRENT_TEST"] = "record_cloud_vectors"
    out = Path(sys.argv[1])
    records = []
    schema: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for spec in cases():
            entry, schema = record(spec, Path(tmp))
            records.append(entry)
    out.write_text(
        json.dumps(
            {
                "schema": "guard-supply-chain-cloud-vectors.v1",
                "description": (
                    "Cloud-connected package supply-chain evaluation vectors recorded from the Python "
                    f"evaluator at commit {BASE_COMMIT} by record_cloud_vectors.py. Rows seed the store; "
                    "expect is the full evaluation."
                ),
                "recorded_from_commit": BASE_COMMIT,
                "now": NOW,
                "sync_token": "demo-token",
                "schema_sql": schema,
                "cases": records,
            },
            indent=1,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

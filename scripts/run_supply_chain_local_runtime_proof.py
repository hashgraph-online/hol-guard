#!/usr/bin/env python3
"""Local daemon runtime proof for supply-chain firewall (SCSR214-217, SCSR246-248)."""

from __future__ import annotations

import os
import argparse
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT))

from codex_plugin_scanner.guard.daemon import GuardDaemonServer  # noqa: E402
from codex_plugin_scanner.guard.daemon import server as daemon_server  # noqa: E402
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402
from tests.test_guard_headless_daemon_api import (  # noqa: E402
    _dashboard_token_for,
    _read_json_response,
    _request,
)

NOW = "2026-06-11T00:00:00.000Z"
WORKSPACE_ID = "scsr-runtime-proof-workspace"


def _seed_premium_store(guard_home: Path) -> GuardStore:
    store = GuardStore(guard_home)
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token-redacted",
        NOW,
        workspace_id=WORKSPACE_ID,
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": WORKSPACE_ID},
        NOW,
    )
    return store


def _write_workspace(workspace_dir: Path) -> None:
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "package.json").write_text(
        '{"name":"scsr-runtime-proof","dependencies":{"minimist":"^1.2.0"}}',
        encoding="utf-8",
    )
    (workspace_dir / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"minimist": "^1.2.0"}},
                    "node_modules/minimist": {"version": "1.2.8"},
                }
            }
        ),
        encoding="utf-8",
    )


def _run_proof(*, evidence_dir: Path) -> dict[str, object]:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    original_home = os.environ.get("HOME")
    initial_working_directory = Path(os.path.abspath(os.path.curdir))
    home_dir = evidence_dir / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home_dir)
    os.environ.setdefault("SHELL", "/bin/zsh")
    guard_home = evidence_dir / "guard-home"
    workspace_dir = evidence_dir / "workspace"
    _write_workspace(workspace_dir)
    store = _seed_premium_store(guard_home)
    sync_finished = threading.Event()
    sync_result: dict[str, object] = {}

    def fake_sync(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        sync_finished.set()
        sync_result["synced_at"] = datetime.now(timezone.utc).isoformat()
        sync_result["receipts_stored"] = 1
        return sync_result

    had_sync_attr = hasattr(daemon_server, "sync_local_guard_cloud_proof")
    original_sync = getattr(daemon_server, "sync_local_guard_cloud_proof", None)
    daemon_server.sync_local_guard_cloud_proof = fake_sync  # type: ignore[attr-defined]

    checks: list[dict[str, object]] = []
    os.chdir(workspace_dir)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)

        install_status, install_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm", "pip"]},
            ),
        )
        checks.append(
            {
                "task": "SCSR214",
                "ok": install_status == 200 and install_payload.get("status") == "completed",
                "detail": f"install status={install_status}",
            }
        )

        npm_test_status, npm_test_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
        checks.append(
            {
                "task": "SCSR215",
                "ok": npm_test_status == 200 and npm_test_payload.get("operation") == "test",
                "detail": f"npm test status={npm_test_status}",
            }
        )

        pip_test_status, pip_test_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["pip"]},
            ),
        )
        checks.append(
            {
                "task": "SCSR216",
                "ok": pip_test_status == 200 and pip_test_payload.get("operation") == "test",
                "detail": f"pip test status={pip_test_status}",
            }
        )

        audit_status, audit_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/audit",
                token=token,
                payload={},
            ),
        )
        checks.append(
            {
                "task": "SCSR217",
                "ok": audit_status == 200 and audit_payload.get("operation") == "audit",
                "detail": f"audit status={audit_status}",
            }
        )

        sync_queued = audit_payload.get("cloud_sync") == {
            "status": "queued",
            "message": "Guard Cloud sync started.",
        }
        sync_ok = sync_finished.wait(timeout=3)
        receipts = store.list_receipts(limit=5, harness="package-firewall")
        checks.append(
            {
                "task": "SCSR246",
                "ok": sync_queued and sync_ok,
                "detail": "audit queued Cloud sync",
            }
        )
        checks.append(
            {
                "task": "SCSR247",
                "ok": len(receipts) > 0,
                "detail": f"receipts={len(receipts)}",
            }
        )
        checks.append(
            {
                "task": "SCSR248",
                "ok": any(
                    receipt.get("artifact_name") == "Workspace supply-chain audit"
                    for receipt in receipts
                ),
                "detail": "workspace audit receipt persisted",
            }
        )
    finally:
        daemon.stop()
        if had_sync_attr:
            daemon_server.sync_local_guard_cloud_proof = original_sync  # type: ignore[attr-defined]
        else:
            delattr(daemon_server, "sync_local_guard_cloud_proof")
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home
        os.chdir(initial_working_directory)

    report = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "passed": sum(1 for check in checks if check["ok"]),
        "failed": sum(1 for check in checks if not check["ok"]),
        "syncResult": sync_result,
    }
    output_path = evidence_dir / "local-runtime-proof.json"
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-dir",
        default=".guard-cloud-evidence/supply-chain-runtime",
        help="Directory for proof artifacts",
    )
    args = parser.parse_args()
    report = _run_proof(evidence_dir=Path(args.evidence_dir).resolve())
    sys.stdout.write(json.dumps(report) + "\n")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

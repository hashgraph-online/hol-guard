#!/usr/bin/env python3
"""Reference stateful Cloud service for the HOL Guard MDM integration lab."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from lab_common import CloudServer, ContractError, Store


def _load_seeds() -> list[dict[str, str]]:
    raw = os.environ.get("HOL_MDM_LAB_DEVICE_SEEDS", "[]")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContractError("enrollment_seed_json_invalid") from error
    if not isinstance(value, list) or len(value) > 64:
        raise ContractError("enrollment_seed_json_invalid")
    seeds: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "workspaceId",
            "deviceId",
            "installationGeneration",
            "token",
        }:
            raise ContractError("enrollment_seed_json_invalid")
        if not all(isinstance(item[key], str) for key in item):
            raise ContractError("enrollment_seed_json_invalid")
        seeds.append({key: item[key] for key in item})
    return seeds


def _required_admin_token() -> str:
    token = os.environ.get("HOL_MDM_LAB_ADMIN_TOKEN", "").strip()
    if not token:
        raise RuntimeError("HOL_MDM_LAB_ADMIN_TOKEN is required")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--database", type=Path, default=Path("/state/cloud.sqlite3"))
    parser.add_argument("--signing-key", type=Path, default=Path("/state/cloud-key.pem"))
    args = parser.parse_args()
    server = CloudServer(
        (args.host, args.port),
        Store(args.database, args.signing_key, _load_seeds()),
        _required_admin_token(),
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

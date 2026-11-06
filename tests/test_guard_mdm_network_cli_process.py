from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).parents[1]


def _status_validator() -> Draft202012Validator:
    schema_path = ROOT / "docs" / "guard" / "schemas" / "mdm-status-v1.schema.json"
    return Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))


def test_network_diagnose_process_is_prompt_free_json_and_redacts_endpoint_secrets() -> None:
    secret = "synthetic-cli-secret"
    environment = os.environ.copy()
    source_path = str(ROOT / "src")
    environment["PYTHONPATH"] = (
        source_path if not environment.get("PYTHONPATH") else source_path + os.pathsep + environment["PYTHONPATH"]
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "mdm",
            "network-diagnose",
            "--endpoint",
            f"https://user:{secret}@127.0.0.1",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 1
    assert secret not in completed.stdout
    assert secret not in completed.stderr
    payload = json.loads(completed.stdout)
    _status_validator().validate(payload)
    assert payload["schemaVersion"] == "hol-guard-mdm-status.v1"
    assert payload["operation"] == "network-diagnose"
    assert payload["healthy"] is False
    assert len(payload["results"]) == 1
    result = payload["results"][0]
    assert result["clock"] == "not-tested"
    assert result["clockSkewSeconds"] is None
    assert result["dns"] == "invalid"
    assert result["endpoint"] == "redacted"
    assert result["proxy"]["mode"] in {"system", "explicit", "none"}
    assert result["proxy"]["selected"] is False
    assert result["proxy"]["endpointHash"] is None
    assert result["proxy"]["dns"] == "not-tested"
    assert result["proxy"]["authenticated"] is False
    assert result["reachability"] == "not-tested"
    assert result["reasonCode"] == "endpoint_invalid"
    assert result["tls"] == "not-tested"

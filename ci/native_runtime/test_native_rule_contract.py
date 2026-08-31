from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

_RUNTIME = os.environ.get("HOL_GUARD_NATIVE_BINARY")
pytestmark = pytest.mark.skipif(not _RUNTIME, reason="compiled native runtime is required")

_SCHEMA = "hol-guard-native-rule-contract.v2"
_DOMAIN = b"hol-guard-native-rule-contract.v2\x00"
_COMPONENTS = (
    ("guard-rules", Path("rust/crates/guard-rules/src/lib.rs")),
    ("guard-scanner", Path("rust/crates/guard-scanner/src/lib.rs")),
    ("guard-secure-fs", Path("rust/crates/guard-secure-fs/src/lib.rs")),
    ("guard-hook-core", Path("rust/crates/guard-hook-core/src/lib.rs")),
    ("guard-contracts", Path("rust/crates/guard-contracts/src/lib.rs")),
    ("guard-command-pretool", Path("rust/crates/guard-command/src/pretool.rs")),
    ("guard-command-pretool-generic", Path("rust/crates/guard-command/src/pretool/generic.rs")),
    ("guard-command-pretool-result", Path("rust/crates/guard-command/src/pretool/generic_result.rs")),
    ("guard-command-pretool-extract", Path("rust/crates/guard-command/src/pretool/generic_extract.rs")),
    ("guard-runtime-policy-enforcement", Path("rust/crates/guard-runtime/src/policy_enforcement.rs")),
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _expected_contract() -> dict[str, object]:
    root = _repo_root()
    components: list[dict[str, str]] = []
    combined = hashlib.sha256()
    combined.update(_DOMAIN)
    for name, relative_path in _COMPONENTS:
        digest = hashlib.sha256((root / relative_path).read_bytes()).hexdigest()
        components.append({"name": name, "sha256": digest})
        combined.update(name.encode("utf-8"))
        combined.update(b"\x00")
        combined.update(digest.encode("ascii"))
        combined.update(b"\x00")
    return {
        "schema": _SCHEMA,
        "components": components,
        "rule_digest": combined.hexdigest(),
    }


def _runtime_json(*args: str) -> dict[str, object]:
    assert _RUNTIME is not None
    completed = subprocess.run(
        (_RUNTIME, *args),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=5.0,
    )
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


def test_runtime_rule_contract_matches_exact_checkout_source_bytes() -> None:
    assert _runtime_json("rule-contract", "--json") == _expected_contract()


def test_capabilities_rule_digest_is_the_exact_rule_contract_digest() -> None:
    contract = _runtime_json("rule-contract", "--json")
    capabilities = _runtime_json("capabilities", "--json")
    assert capabilities["rule_digest"] == contract["rule_digest"]
    features = capabilities.get("features")
    assert isinstance(features, list)
    assert "rule-contract-v2" in features


def test_rule_contract_changes_when_any_component_bytes_change() -> None:
    expected = _expected_contract()
    components = expected["components"]
    assert isinstance(components, list)
    original = str(expected["rule_digest"])
    for index, component in enumerate(components):
        assert isinstance(component, dict)
        mutated_components = [dict(value) for value in components]
        digest = str(mutated_components[index]["sha256"])
        mutated_components[index]["sha256"] = (
            ("0" if digest[0] != "0" else "1") + digest[1:]
        )
        combined = hashlib.sha256()
        combined.update(_DOMAIN)
        for value in mutated_components:
            combined.update(str(value["name"]).encode("utf-8"))
            combined.update(b"\x00")
            combined.update(str(value["sha256"]).encode("ascii"))
            combined.update(b"\x00")
        assert combined.hexdigest() != original

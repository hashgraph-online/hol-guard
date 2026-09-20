"""Bind current bridge conformance separately from immutable historical auth vectors."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_FIXTURE = "tests/fixtures/claude-launcher-pilot-auth.json"
HISTORICAL_GENERATOR = "scripts/generate_claude_launcher_auth_vectors.py"
CURRENT_FIXTURE = "tests/fixtures/claude-launcher-current-conformance-v2.json"
CURRENT_REVISION = "ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d"
CURRENT_TREE = "19977465d6e419f1276d75fb6bd1b3477f5c9720"
CURRENT_MARKER_SHA256 = "a452508d7650662709fba99632befdea0a019b66957dc1ffdf67e24c6d4c2f61"
HISTORICAL_FIXTURE_SHA256 = "ebf41a37cfe9e6e05bcd9f5161874a3e1329015bb990f779e238d3c8f4b3571a"
HISTORICAL_GENERATOR_SHA256 = "03fa95cd2b9366c8913ac5b703f153c64f2b917e1d1ba953825486ca0debeeb5"
BRIDGE = "adapters/claude_daemon_hook_bridge.py"
MARKER = "adapters/claude_hook_config.py"
MODULES = frozenset(
    {
        BRIDGE,
        "adapters/claude_daemon_hook_transport.py",
        "adapters/codex_daemon_hook_auth.py",
        "adapters/claude_daemon_state.py",
    }
)
OLD_IMPORT = b"from .claude_code import CLAUDE_GUARD_DAEMON_HOOK_MARKER\n"
NEW_IMPORT = b"from .claude_hook_config import CLAUDE_GUARD_DAEMON_HOOK_MARKER\n"
IMPORT_ANCHOR = b"from .claude_daemon_hook_transport import authenticated_claude_hook_response\n"
AUTH = "adapters/codex_daemon_hook_auth.py"
READER_PROVIDERS = {
    "windows_replaceable_file.py": "ccc6b88c70dac5bc80c340b0bc4712e0ae588a123623b4bc3e34616d9b684fb9",
    "windows_paths.py": "b93ca4e5361c9dbda0ea273be903b4ed7225dc21ec5bfaf3a7da5ddb892cf79d",
}
READER_ADDITION = (
    b'        if os.name == "nt":\n'
    b"            from ..windows_replaceable_file import read_replaceable_text\n\n"
    b"            return read_replaceable_text(path).strip()\n"
)


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _object(value: object, keys: set[str] | frozenset[str], reason: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == keys, reason)
    assert isinstance(value, dict)
    return value


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def validate_current_conformance(
    value: object,
    *,
    historical_vectors: bytes,
    historical_generator: bytes,
    sources: Mapping[str, bytes],
) -> dict[str, Any]:
    binding = _object(
        value,
        {
            "schema",
            "source_revision",
            "source_tree",
            "python_execution",
            "installed_artifact",
            "qualification_complete",
            "historical_auth_provenance",
            "bridge_modules",
            "marker_source",
            "reviewed_import_delta",
            "reviewed_windows_reader_delta",
        },
        "current_conformance_shape_invalid",
    )
    _require(
        binding["schema"] == "guard-claude-current-source-conformance.v2"
        and binding["python_execution"] == "current_adapter_registered_python_argv"
        and binding["installed_artifact"] is False
        and binding["qualification_complete"] is False,
        "current_conformance_scope_invalid",
    )
    _require(
        binding["source_revision"] == CURRENT_REVISION and binding["source_tree"] == CURRENT_TREE,
        "current_source_identity_invalid",
    )
    history = _object(
        binding["historical_auth_provenance"],
        {
            "fixture",
            "fixture_sha256",
            "revision",
            "generator",
            "generator_sha256",
            "module",
            "module_sha256",
            "historical_bridge_executed",
        },
        "historical_auth_provenance_invalid",
    )
    _require(
        history["fixture"] == HISTORICAL_FIXTURE
        and history["generator"] == HISTORICAL_GENERATOR
        and history["historical_bridge_executed"] is False
        and _digest(historical_vectors) == history["fixture_sha256"] == HISTORICAL_FIXTURE_SHA256
        and _digest(historical_generator) == history["generator_sha256"] == HISTORICAL_GENERATOR_SHA256,
        "historical_auth_bytes_changed",
    )
    historical = json.loads(historical_vectors)
    _require(
        isinstance(historical, dict)
        and historical.get("schema") == "guard-claude-python-auth-vectors.v1"
        and all(history[field] == historical.get(field) for field in ("revision", "module", "module_sha256"))
        and history["revision"] == "ae33987d0c8675c36a77375e03419aee920825f6",
        "historical_auth_identity_changed",
    )
    modules = _object(binding["bridge_modules"], MODULES, "current_module_set_invalid")
    old_modules = _object(historical.get("bridge_modules"), MODULES, "historical_module_set_invalid")
    marker = _object(binding["marker_source"], {"module", "sha256"}, "marker_source_shape_invalid")
    _require(
        marker["module"] == MARKER and set(sources) == MODULES | {MARKER} | READER_PROVIDERS.keys(),
        "current_module_set_invalid",
    )
    _require(marker["sha256"] == CURRENT_MARKER_SHA256, "current_marker_binding_changed")
    for name, expected in {**modules, MARKER: marker["sha256"]}.items():
        _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "current_module_digest_invalid")
        _require(_digest(sources[name]) == expected, "current_module_source_drift")
    _require(
        all(modules[name] == old_modules[name] for name in MODULES - {BRIDGE, AUTH}),
        "historical_transport_source_drift",
    )
    _require(history["module_sha256"] == old_modules[AUTH], "historical_auth_module_changed")
    reader = _object(
        binding["reviewed_windows_reader_delta"],
        {"module", "historical_sha256", "current_sha256", "added", "providers", "scope"},
        "reviewed_windows_reader_delta_invalid",
    )
    _require(
        reader["module"] == AUTH
        and reader["historical_sha256"] == old_modules[AUTH]
        and reader["current_sha256"] == modules[AUTH]
        and reader["added"] == READER_ADDITION.decode(),
        "reviewed_windows_reader_delta_invalid",
    )
    providers = _object(reader["providers"], set(READER_PROVIDERS), "current_reader_provider_set_invalid")
    _require(providers == READER_PROVIDERS, "current_reader_provider_binding_changed")
    for name, expected in providers.items():
        _require(_digest(sources[name]) == expected, "current_reader_provider_source_drift")
    auth = sources[AUTH]
    _require(
        auth.count(READER_ADDITION) == 1
        and auth.count(READER_ADDITION + b'        return path.read_text(encoding="utf-8").strip()\n') == 1
        and _digest(auth.replace(READER_ADDITION, b"", 1)) == old_modules[AUTH],
        "reviewed_windows_reader_delta_mismatch",
    )
    delta = _object(
        binding["reviewed_import_delta"],
        {"module", "historical_sha256", "current_sha256", "removed", "added", "scope"},
        "reviewed_import_delta_invalid",
    )
    _require(
        delta["module"] == BRIDGE
        and delta["historical_sha256"] == old_modules[BRIDGE]
        and delta["current_sha256"] == modules[BRIDGE]
        and delta["removed"] == OLD_IMPORT.decode().rstrip("\n")
        and delta["added"] == NEW_IMPORT.decode().rstrip("\n"),
        "reviewed_import_delta_invalid",
    )
    current = sources[BRIDGE]
    _require(
        current.count(NEW_IMPORT) == 1 and OLD_IMPORT not in current and current.count(IMPORT_ANCHOR) == 1,
        "reviewed_import_delta_mismatch",
    )
    original = current.replace(NEW_IMPORT, b"", 1).replace(IMPORT_ANCHOR, OLD_IMPORT + IMPORT_ANCHOR, 1)
    _require(_digest(original) == old_modules[BRIDGE], "reviewed_import_delta_mismatch")
    return binding


def verify_current_conformance(guard: Path) -> dict[str, Any]:
    return validate_current_conformance(
        json.loads((ROOT / CURRENT_FIXTURE).read_bytes()),
        historical_vectors=(ROOT / HISTORICAL_FIXTURE).read_bytes(),
        historical_generator=(ROOT / HISTORICAL_GENERATOR).read_bytes(),
        sources={name: (guard / name).read_bytes() for name in MODULES | {MARKER} | READER_PROVIDERS.keys()},
    )

"""Constants for the native policy snapshot protocol."""

from __future__ import annotations

_STATE_SCHEMA = "hol-guard-native-policy-generation.v1"
_STATE_NAME = "native-policy-generation.json"
_LOCK_NAME = "native-policy-generation.lock"
_MAX_STATE_BYTES = 4 * 1024
_MAX_GENERATION = (1 << 64) - 1

# v3 is the only snapshot contract accepted by the managed Rust resident. The
# v1 helpers below remain intentionally isolated for explicit differential
# tests; production native hooks never call them.
POLICY_SNAPSHOT_V3_SCHEMA = "hol-guard-native-policy.v3"
# Compatibility alias for callers that used the schema name while the v3
# implementation was being introduced. It intentionally points only at v3.
POLICY_SNAPSHOT_SCHEMA = POLICY_SNAPSHOT_V3_SCHEMA
POLICY_SNAPSHOT_PUSH_SCHEMA = "guard-policy-snapshot-push.v1"
POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION = "native_policy_snapshot_requires_new_generation"
POLICY_SNAPSHOT_V3_VERSION = 3
POLICY_SNAPSHOT_PROTOCOL_VERSION = 1
POLICY_SNAPSHOT_MAX_BYTES = 256 * 1024
POLICY_SNAPSHOT_MAX_STRING_BYTES = 4 * 1024
POLICY_SNAPSHOT_MAX_MAP_ENTRIES = 256
POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES = 64
POLICY_SNAPSHOT_MAX_JSON_DEPTH = 32
POLICY_SNAPSHOT_MAX_JSON_COLLECTION_ITEMS = 4_096
POLICY_SNAPSHOT_MAX_JSON_STRING_BYTES = 1024 * 1024
POLICY_SNAPSHOT_MAX_EXPIRY_MS = 24 * 60 * 60 * 1000
POLICY_SNAPSHOT_INTEGRITY_ALGORITHM = "hmac-sha256"

# Keep these bytes byte-for-byte aligned with guard-policy-snapshot. Rust's
# HMAC helper authenticates ``domain || message`` rather than using a second
# HMAC field, so the Python functions below do the same concatenation.
POLICY_SNAPSHOT_INTEGRITY_DOMAIN = b"hol-guard-native-policy-snapshot-v3\0"
POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN = b"hol-guard-native-policy-verifier-v1\0"

NATIVE_RUNTIME_STATE_DIRECTORY = "native-runtime"
NATIVE_POLICY_VERIFIER_KEY_NAME = "policy-verifier.key"
_V3_GENERATION_SCHEMA = "guard-native-policy-snapshot-generation.v3"
_V3_GENERATION_STATE_NAME = "native-policy-snapshot-generation-v3.json"
_V3_GENERATION_LOCK_NAME = "native-policy-snapshot-generation-v3.lock"
_RUST_GENERATION_FLOOR_NAME = "policy-snapshot-generation-floor.json"
_RUST_SNAPSHOT_STATE_NAME = "policy-snapshot-v3.json"
NATIVE_POLICY_SNAPSHOT_CACHE_NAME = "policy-snapshot-publisher-v3.json"
_NATIVE_POLICY_SNAPSHOT_PENDING_NAME = "policy-snapshot-publisher-v3.pending.json"
_VERIFIER_KEY_BYTES = 32
_PUBLISH_RETRY_SECONDS = 0.25
_PUBLISH_TIMEOUT_SECONDS = 2.0
_MAX_ACK_BYTES = 4 * 1024
_RENEWAL_LEAD_SECONDS = 5 * 60
_RENEWAL_JITTER_MAX_SECONDS = 30.0
_PUBLISH_RETRY_MAX_SECONDS = 5.0
_REQUIRED_PUBLISH_FEATURES = frozenset(
    {
        "policy-snapshot-v3",
        "policy-snapshot-push-v1",
        "policy-snapshot-resident-generation-v1",
        "native-policy-in-memory-v1",
        "native-resident-client-v1",
    }
)
_VALID_ACTIONS = frozenset({"allow", "warn", "review", "require-reapproval", "sandbox-required", "block"})
_VALID_POSTURES = frozenset({"protected", "extra_careful", "watch"})
_VALID_SECURITY_LEVELS = frozenset({"relaxed", "gentle", "balanced", "strict", "paranoid", "custom"})
_VALID_SANDBOX_ANALYSIS = frozenset({"off", "suspicious", "strict"})
_VALID_REDACTION_LEVELS = frozenset({"full", "partial", "none"})
_VALID_RISK_ACTION_KEYS = frozenset(
    {
        "local_secret_read",
        "credential_exfiltration",
        "data_flow_exfiltration",
        "destructive_shell",
        "encoded_execution",
        "network_egress",
        "prompt_injection",
        "mcp_dangerous_tool",
        "malicious_skill",
        "package_script",
        "persistence",
        "guard_bypass",
        "cloud_advisory",
        "encoded_exfiltration",
        "execution",
        "supply_chain",
        "policy_bypass",
    }
)
_SNAPSHOT_FIELDS = frozenset(
    {
        "schema",
        "version",
        "generation",
        "policy_digest",
        "config_digest",
        "rule_digest",
        "runtime_identity",
        "protocol_version",
        "mode",
        "scope_contract",
        "effective_policy",
        "issued_at_ms",
        "expires_at_ms",
        "integrity",
    }
)
_SCOPE_FIELDS = frozenset({"schema", "kind", "scope_digest", "workspace_binding"})
_EFFECTIVE_POLICY_FIELDS = frozenset(
    {
        "protection_posture",
        "security_level",
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
        "risk_actions",
        "harness_risk_actions",
        "harness_actions",
        "publisher_actions",
        "artifact_actions",
        "sandbox_analysis",
        "receipt_redaction_level",
    }
)
_INTEGRITY_FIELDS = frozenset({"algorithm", "key_id", "mac"})
_PUSH_ENVELOPE_FIELDS = frozenset({"operation", "deadline_budget_ms", "request"})
_PUSH_REQUEST_FIELDS = frozenset({"schema", "snapshot"})
_VALID_INPUT_MODES = frozenset({"observe", "prompt", "enforce"})
_MAX_U16 = (1 << 16) - 1
_MAX_U64 = (1 << 64) - 1

# Windows verifier state uses the same protected explicit owner+SYSTEM DACL
# contract as the Rust resident-state helper.  These constants are kept local
# to avoid making ctypes part of the normal POSIX import path's API.
_WINDOWS_GENERIC_READ = 0x80000000
_WINDOWS_GENERIC_WRITE = 0x40000000
_WINDOWS_FILE_ADD_FILE = 0x00000002
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_CREATE_NEW = 1
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_ATTRIBUTE_NORMAL = 0x00000080
_WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WINDOWS_FILE_TYPE_DISK = 0x0001
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_FILE_FLAG_WRITE_THROUGH = 0x80000000
_WINDOWS_DELETE = 0x00010000
_WINDOWS_WRITE_DAC = 0x00040000
_WINDOWS_WRITE_OWNER = 0x00080000
_WINDOWS_ERROR_FILE_NOT_FOUND = 2
_WINDOWS_ERROR_PATH_NOT_FOUND = 3
_WINDOWS_ERROR_FILE_EXISTS = 80
_WINDOWS_ERROR_ALREADY_EXISTS = 183
_WINDOWS_SE_FILE_OBJECT = 1
_WINDOWS_OWNER_SECURITY_INFORMATION = 0x00000001
_WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
_WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_WINDOWS_SECURITY_INFORMATION = _WINDOWS_DACL_SECURITY_INFORMATION | _WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION
_WINDOWS_SE_DACL_PROTECTED = 0x1000
_WINDOWS_ACCESS_ALLOWED_ACE_TYPE = 0
_WINDOWS_INHERITED_ACE = 0x10
_WINDOWS_FILE_ALL_ACCESS = 0x001F01FF
_WINDOWS_SYSTEM_SID = "S-1-5-18"
_ACTION_SEVERITY = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "require-reapproval": 3,
    "sandbox-required": 4,
    "block": 5,
}
# ``watch`` is observe-only; it must never override an enforcing posture when
# home/workspace policies are composed into one resident snapshot.
_POSTURE_SEVERITY = {"watch": 0, "protected": 1, "extra_careful": 2}
_SECURITY_LEVEL_SEVERITY = {
    "relaxed": 0,
    "gentle": 1,
    "balanced": 2,
    "strict": 3,
    "paranoid": 4,
    # ``custom`` is a validated configuration value whose individual floors
    # are represented by the action maps below. It must not be weakened by a
    # less-specific workspace overlay.
    "custom": 5,
}
_SANDBOX_SEVERITY = {"off": 0, "suspicious": 1, "strict": 2}
_REDACTION_SEVERITY = {"none": 0, "partial": 1, "full": 2}


class NativePolicySnapshotError(RuntimeError):
    """Raised when the durable native-policy generation cannot be trusted."""


__all__ = [
    name
    for name in globals()
    if (name.isupper() or name.startswith("_") or name == "NativePolicySnapshotError") and not name.startswith("__")
]

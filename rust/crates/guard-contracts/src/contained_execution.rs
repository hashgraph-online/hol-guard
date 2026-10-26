//! Canonical request/response contracts for the contained-execution resident
//! ops (RTM-020). Mirrors the pattern established by `package_authority.rs`.
//!
//! Coverage:
//!   * `try_execute_contained_node_command`   — `contained_node_execute`
//!   * `try_execute_contained_typescript`     — `contained_typescript_execute`
//!   * `try_execute_contained_package_script` — `contained_package_script_execute`
//!   * `try_execute_contained_workspace_write`— `contained_workspace_write_execute`
//!   * `execute_contained`                    — `contained_execute`
//!   * `probe_stdio_mcp_server`               — `mcp_stdio_probe`
//!   * `probe_containment_health`             — `containment_health_probe`
//!
//! Every struct uses `deny_unknown_fields` so a stale resident cannot smuggle
//! new keys past the schema check.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Feature tokens advertised by `resident_capabilities`.
// ---------------------------------------------------------------------------

/// All six contained-execution ops share one feature token; the resident
/// advertises it only when the whole surface is live.
pub const CONTAINED_EXECUTION_FEATURE: &str = "contained-execution-v1";
/// Stdio MCP probe op.
pub const MCP_STDIO_PROBE_FEATURE: &str = "mcp-stdio-probe-v1";

// ---------------------------------------------------------------------------
// Schema strings — one stable pair per op.
// ---------------------------------------------------------------------------

pub const CONTAINED_NODE_EXECUTE_REQUEST_SCHEMA: &str = "guard-contained-node-execute-request.v1";
pub const CONTAINED_NODE_EXECUTE_RESULT_SCHEMA: &str = "guard-contained-node-execute-result.v1";
pub const CONTAINED_TYPESCRIPT_EXECUTE_REQUEST_SCHEMA: &str =
    "guard-contained-typescript-execute-request.v1";
pub const CONTAINED_TYPESCRIPT_EXECUTE_RESULT_SCHEMA: &str =
    "guard-contained-typescript-execute-result.v1";
pub const CONTAINED_PACKAGE_SCRIPT_EXECUTE_REQUEST_SCHEMA: &str =
    "guard-contained-package-script-execute-request.v1";
pub const CONTAINED_PACKAGE_SCRIPT_EXECUTE_RESULT_SCHEMA: &str =
    "guard-contained-package-script-execute-result.v1";
pub const CONTAINED_WORKSPACE_WRITE_EXECUTE_REQUEST_SCHEMA: &str =
    "guard-contained-workspace-write-execute-request.v1";
pub const CONTAINED_WORKSPACE_WRITE_EXECUTE_RESULT_SCHEMA: &str =
    "guard-contained-workspace-write-execute-result.v1";
pub const CONTAINED_EXECUTE_REQUEST_SCHEMA: &str = "guard-contained-execute-request.v1";
pub const CONTAINED_EXECUTE_RESULT_SCHEMA: &str = "guard-contained-execute-result.v1";
pub const MCP_STDIO_PROBE_REQUEST_SCHEMA: &str = "guard-mcp-stdio-probe-request.v1";
pub const MCP_STDIO_PROBE_RESULT_SCHEMA: &str = "guard-mcp-stdio-probe-result.v1";
pub const CONTAINMENT_HEALTH_PROBE_REQUEST_SCHEMA: &str =
    "guard-containment-health-probe-request.v1";
pub const CONTAINMENT_HEALTH_PROBE_RESULT_SCHEMA: &str = "guard-containment-health-probe-result.v1";

// ---------------------------------------------------------------------------
// Contained execution — per-op request/result pairs.
//
// `command_text` is the raw shell text the shim received. `manager` + `argv`
// carry the caller's pre-parsed invocation so the resident never has to
// `shlex`-join an argv back into text. `evidence` is the caller-built
// `LocalPackageExecutionEvidence` serialized via `to_dict`; the resident
// re-validates it against `argv`/`manager` before use.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedNodeExecuteRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub workspace: String,
    pub manager: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub command_text: String,
    pub evidence: Option<Value>,
    /// Shim bin directory (PATH pin target); the resident scrubs it from PATH.
    #[serde(default)]
    pub shim_directory: Option<String>,
    /// Scrubbed child environment (caller already stripped secret material).
    #[serde(default)]
    pub environment: Option<BTreeMap<String, String>>,
    /// Process timeout in seconds (fractions allowed); the runner default applies when absent.
    #[serde(default)]
    pub timeout_seconds: Option<f64>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedNodeExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedTypescriptExecuteRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub workspace: String,
    pub manager: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub command_text: String,
    pub evidence: Option<Value>,
    /// Shim bin directory (PATH pin target); the resident scrubs it from PATH.
    #[serde(default)]
    pub shim_directory: Option<String>,
    /// Scrubbed child environment (caller already stripped secret material).
    #[serde(default)]
    pub environment: Option<BTreeMap<String, String>>,
    /// Process timeout in seconds (fractions allowed); the runner default applies when absent.
    #[serde(default)]
    pub timeout_seconds: Option<f64>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedTypescriptExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedPackageScriptExecuteRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub workspace: String,
    pub manager: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub command_text: String,
    /// Unused: Bun script evidence is rebuilt in Rust from the workspace.
    #[serde(default)]
    pub evidence: Option<Value>,
    /// Shim bin directory (PATH pin target); the resident scrubs it from PATH.
    #[serde(default)]
    pub shim_directory: Option<String>,
    /// Scrubbed child environment (caller already stripped secret material).
    #[serde(default)]
    pub environment: Option<BTreeMap<String, String>>,
    /// Process timeout in seconds (fractions allowed); the runner default applies when absent.
    #[serde(default)]
    pub timeout_seconds: Option<f64>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedPackageScriptExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedWorkspaceWriteExecuteRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    pub workspace: String,
    /// Legacy raw-command form (shim-intercepted path). Ignored when the
    /// structured `operation`/`source`/`target` triple is present.
    #[serde(default)]
    pub command_text: String,
    /// Semantic operation: `patch-check` | `patch-apply` | `format-write` |
    /// `copy-generated` — the Python `ContainedWriteOperation` contract.
    #[serde(default)]
    pub operation: Option<String>,
    /// Workspace-relative source path (patch file, format target, copy src).
    #[serde(default)]
    pub source: Option<String>,
    /// Workspace-relative target path (None for `patch-check`).
    #[serde(default)]
    pub target: Option<String>,
    /// Scrubbed child environment used to resolve the pinned executable.
    #[serde(default)]
    pub environment: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedWorkspaceWriteExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedExecuteRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    /// Canonical `ContainmentRequest` payload (carries `schema_version`).
    pub request: Value,
    /// Canonical `ContainmentPolicy` payload (carries `schema_version`).
    pub policy: Value,
    pub guard_home: String,
    pub run_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainedExecuteResultV1 {
    pub schema: String,
    pub result: Option<Value>,
}

// ---------------------------------------------------------------------------
// MCP stdio probe
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioProbeRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    /// Raw command text to probe.
    pub command_text: String,
    /// Working directory the shim observed.
    pub cwd: String,
    /// `HOME` for env resolution.
    pub home_dir: Option<String>,
    /// Caller-scrubbed extra env (already stripped of secret material).
    pub extra_env: Option<BTreeMap<String, String>>,
    /// Probe timeout in seconds (None = default).
    pub timeout_seconds: Option<f64>,
    /// Optional connection identity hash for attestation binding.
    pub connection_identity_hash: Option<String>,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioProbeResultV1 {
    pub schema: String,
    /// `{"status": "ok", "tools": [...], ...}` on success; `{"status":
    /// "failed", "reason": ...}` on probe failure; `None` when the command is
    /// not an MCP launch (caller falls back to the legacy path).
    pub result: Option<Value>,
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    #[test]
    fn ww_semantic_request_deserializes() {
        let raw = serde_json::json!({
            "schema": "guard-contained-workspace-write-execute-request.v1",
            "request_id": "ww-1",
            "workspace": "/repo",
            "command_text": "",
            "operation": "patch-apply",
            "source": "patches/fix.patch",
            "target": "src/lib.rs",
            "environment": {"PATH": "/usr/bin"},
            "timeout_seconds": 120,
            "guard_home": "/home/.hol-guard",
        });
        let req: ContainedWorkspaceWriteExecuteRequestV1 =
            serde_json::from_value(raw).expect("structured WW request must deserialize");
        assert_eq!(req.operation.as_deref(), Some("patch-apply"));
        assert_eq!(req.source.as_deref(), Some("patches/fix.patch"));
        assert_eq!(req.target.as_deref(), Some("src/lib.rs"));
        assert_eq!(
            req.environment
                .as_ref()
                .and_then(|e| e.get("PATH"))
                .map(|s| s.as_str()),
            Some("/usr/bin")
        );
    }

    #[test]
    fn ww_legacy_token_request_deserializes() {
        let raw = serde_json::json!({
            "schema": "guard-contained-workspace-write-execute-request.v1",
            "request_id": "ww-2",
            "workspace": "/repo",
            "command_text": "mkdir -p a b",
            "operation": null,
            "source": null,
            "target": null,
            "environment": null,
            "timeout_seconds": null,
            "guard_home": "/home/.hol-guard",
        });
        let req: ContainedWorkspaceWriteExecuteRequestV1 =
            serde_json::from_value(raw).expect("legacy token request must deserialize");
        assert_eq!(req.command_text, "mkdir -p a b");
        assert!(req.operation.is_none());
    }

    #[test]
    fn contained_node_request_without_optional_fields() {
        // _contained_request sends only the base set — no command_text.
        let raw = serde_json::json!({
            "schema": "guard-contained-node-execute-request.v1",
            "request_id": "n-1",
            "workspace": "/repo",
            "manager": "npx",
            "argv": ["npx", "vitest"],
            "guard_home": "/home/.hol-guard",
            "evidence": null,
        });
        let req: ContainedNodeExecuteRequestV1 =
            serde_json::from_value(raw).expect("node request must deserialize");
        assert_eq!(req.manager, "npx");
        assert!(req.command_text.is_empty());
    }

    #[test]
    fn contained_runner_requests_carry_launch_context() {
        for schema in [
            "guard-contained-node-execute-request.v1",
            "guard-contained-typescript-execute-request.v1",
            "guard-contained-package-script-execute-request.v1",
        ] {
            let raw = serde_json::json!({
                "schema": schema,
                "request_id": "r-1",
                "workspace": "/repo",
                "manager": "npx",
                "argv": ["vitest"],
                "guard_home": "/home/.hol-guard",
                "evidence": null,
                "shim_directory": "/home/.hol-guard/package-shims/bin",
                "environment": {"PATH": "/usr/bin"},
                "timeout_seconds": 300.0,
            });
            if schema.contains("node") {
                let req: ContainedNodeExecuteRequestV1 = serde_json::from_value(raw).unwrap();
                assert_eq!(req.timeout_seconds, Some(300.0));
                assert_eq!(req.environment.unwrap()["PATH"], "/usr/bin");
            } else if schema.contains("typescript") {
                let req: ContainedTypescriptExecuteRequestV1 = serde_json::from_value(raw).unwrap();
                assert_eq!(req.timeout_seconds, Some(300.0));
            } else {
                let req: ContainedPackageScriptExecuteRequestV1 =
                    serde_json::from_value(raw).unwrap();
                assert_eq!(req.timeout_seconds, Some(300.0));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Containment health probe
//
// The daemon asks the resident for current containment health instead of
// running its own backend probe, so backend selection, the enforcement
// self-probe and the evidence it is bound to stay in one place.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentHealthProbeRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: Option<String>,
    /// Daemon runtime fingerprint the evidence is bound to (lowercase SHA-256).
    pub daemon_fingerprint: String,
    pub guard_home: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentHealthProbeResultV1 {
    pub schema: String,
    /// Canonical `ContainmentHealthEvidence` payload, or `null` when the probe
    /// could not run at all.
    pub result: Option<Value>,
}

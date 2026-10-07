//! `McpStdioProbe` resident op — bounded native MCP stdio mediation.
//!
//! Delegates to `guard_command::local_mcp_stdio::run_mcp_stdio_probe`, which
//! reproduces `runtime/local_mcp_stdio.py`: launch-argv resolution,
//! `server/discover` → `initialize` negotiation, bounded `tools/list` cursor
//! pagination, declared-skills listing, and process-group teardown. Returns the
//! `McpCatalogResult.to_dict()` payload. Missing authority is terminal;
//! bounded negotiation failures remain explicit native evidence.

use guard_contracts::{
    McpStdioProbeRequestV1, McpStdioProbeResultV1, MCP_STDIO_PROBE_REQUEST_SCHEMA,
    MCP_STDIO_PROBE_RESULT_SCHEMA,
};
use std::collections::HashMap;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static PROBES: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

#[cfg(unix)]
fn probe_cancellation(request_id: &str) -> Result<Arc<AtomicBool>, String> {
    if request_id.is_empty() || request_id.len() > 128 {
        return Err("invalid_mcp_request_id".to_owned());
    }
    let mut probes = PROBES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "mcp_cancellation_unavailable".to_owned())?;
    if !probes.contains_key(request_id) && probes.len() >= 128 {
        return Err("mcp_cancellation_capacity".to_owned());
    }
    Ok(Arc::clone(
        probes
            .entry(request_id.to_owned())
            .or_insert_with(|| Arc::new(AtomicBool::new(false))),
    ))
}

pub(crate) fn cancel_mcp_stdio_probe(request_id: &str) -> Result<Vec<u8>, String> {
    let probes = PROBES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| "mcp_cancellation_unavailable".to_owned())?;
    let cancellation = probes.get(request_id);
    if let Some(cancellation) = cancellation {
        cancellation.store(true, Ordering::Release);
    }
    crate::encode_response(&serde_json::json!({"status":"ok", "cancelled":cancellation.is_some()}))
}

#[cfg(unix)]
struct ProbeRegistration<'a>(&'a str);

#[cfg(unix)]
impl Drop for ProbeRegistration<'_> {
    fn drop(&mut self) {
        if let Some(probes) = PROBES.get() {
            if let Ok(mut probes) = probes.lock() {
                probes.remove(self.0);
            }
        }
    }
}

pub(crate) fn evaluate_mcp_stdio_probe(
    request: &McpStdioProbeRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != MCP_STDIO_PROBE_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    #[cfg(unix)]
    {
        let cwd = PathBuf::from(&request.cwd);
        let home_dir = request.home_dir.as_deref().map(Path::new);
        let request_id = request
            .request_id
            .as_deref()
            .ok_or("missing_mcp_request_id")?;
        let cancellation = probe_cancellation(request_id)?;
        let _registration = ProbeRegistration(request_id);
        let tokens = match guard_command::local_mcp_stdio::mcp_launch_tokens(
            &request.command_text,
            &cwd,
            home_dir,
        ) {
            Some(t) => t,
            // Invalid launch cannot be promoted into native catalog evidence.
            None => {
                return crate::encode_response(&McpStdioProbeResultV1 {
                    schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
                    result: None,
                });
            }
        };
        let argv = match guard_command::local_mcp_stdio::resolve_argv_from_tokens(&tokens, &cwd) {
            Some(a) => a,
            None => {
                return crate::encode_response(&McpStdioProbeResultV1 {
                    schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
                    result: None,
                });
            }
        };
        // Python `probe_stdio_mcp_server` defaults the catalog's
        // connection-identity binding to the launch tokens' server identity
        // when the caller does not supply one; the identity is bound to the
        // tokens (pre-resolution), so compute it here before argv resolution.
        let default_identity;
        let connection_identity_hash = match request.connection_identity_hash.as_deref() {
            Some(h) => Some(h),
            None => {
                default_identity = guard_command::mcp_decision::build_mcp_server_identity(
                    "",
                    &tokens[0],
                    &tokens[1..],
                    "stdio",
                    None,
                    &[],
                );
                Some(default_identity.identity_hash.as_str())
            }
        };
        let catalog = guard_command::local_mcp_stdio::run_mcp_stdio_probe(
            &argv,
            request.timeout_seconds.unwrap_or(6.0),
            request.extra_env.as_ref(),
            home_dir,
            connection_identity_hash,
            &cancellation,
        );
        crate::encode_response(&McpStdioProbeResultV1 {
            schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
            result: Some(catalog.to_payload()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        crate::encode_response(&McpStdioProbeResultV1 {
            schema: MCP_STDIO_PROBE_RESULT_SCHEMA.to_owned(),
            result: None,
        })
    }
}

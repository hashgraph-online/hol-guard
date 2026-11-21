//! Private application IPC only. The operator's HTTP surface cannot select
//! this operation; credentials are never browser or MCP tool arguments.
use crate::{context_assistance_agents::Input, policy_store::PolicySnapshotStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

pub(crate) const FEATURE: &str = "context-assistance-agents-v1";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    schema: String,
    request_id: String,
    pub(crate) query: Query,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Query {
    kind: String,
    pub(crate) guard_home: String,
    input: Input,
}

pub(crate) fn evaluate(request: &Request, store: &PolicySnapshotStore) -> Result<Vec<u8>, String> {
    let digest = crate::package_authority_op::request_digest_with_limit(request, 64 * 1024)
        .map_err(|_| "native_context_assistance_request_too_large")?;
    let answer: Result<serde_json::Value, String> = (|| {
        validate(request, store)?;
        let home = Path::new(&request.query.guard_home);
        let service = store.context_assistance();
        let generation = service.configuration_generation()?;
        let settings =
            crate::guard_config_load::context_assistance_config(home).unwrap_or_else(|_| {
                crate::guard_config_load::AssistanceSettings::unavailable(
                    "configuration_unavailable",
                )
            });
        service.configure_at(settings, generation)?;
        // Re-decode inside the private operation so credentials remain owned
        // by this call and their string storage is zeroed on drop.
        let input = crate::strict_json::from_value(
            serde_json::to_value(&request.query.input)
                .map_err(|_| "native_context_assistance_agent_request_invalid")?,
        )
        .map_err(|_| "native_context_assistance_agent_request_invalid")?;
        let data = service.agent(home, store, input)?;
        Ok(json!({"kind":"agent", "data":data}))
    })();
    response(request, &digest, answer)
}

fn validate(request: &Request, store: &PolicySnapshotStore) -> Result<(), String> {
    if request.schema != "guard-context-agent-request.v1"
        || request.query.kind != "agent"
        || request.request_id.is_empty()
        || request.request_id.len() > 128
    {
        return Err("native_context_assistance_agent_request_invalid".into());
    }
    store.require_guard_home(&request.query.guard_home)
}

pub(crate) fn reject_busy(
    request: &Request,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let digest = crate::package_authority_op::request_digest_with_limit(request, 64 * 1024)
        .map_err(|_| "native_context_assistance_request_too_large")?;
    let code = validate(request, store)
        .err()
        .unwrap_or_else(|| "native_context_assistance_busy".into());
    response(request, &digest, Err(code))
}

fn response(
    request: &Request,
    digest: &str,
    answer: Result<serde_json::Value, String>,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&match answer {
        Ok(payload) => {
            json!({"schema":"guard-context-agent-result.v1","request_id":request.request_id,"request_sha256":digest,"status":"ok","code":"ok","payload":payload})
        }
        Err(code) => {
            json!({"schema":"guard-context-agent-result.v1","request_id":request.request_id,"request_sha256":digest,"status":"error","code":code,"payload":null})
        }
    })
}

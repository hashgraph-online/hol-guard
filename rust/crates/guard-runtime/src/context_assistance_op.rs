//! Authenticated resident control surface. No caller-provided runtime facts,
//! executable paths, bundle fingerprints or managed policy are accepted.
use crate::context_assistance_service::Check;
use crate::guard_config_load::AssistanceSettings;
use crate::package_authority_op::request_digest_with_limit;
use crate::policy_store::PolicySnapshotStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

pub(crate) const FEATURE: &str = "context-assistance-control-v2";
pub(crate) const WORKSPACE_FEATURE: &str = "context-assistance-workspaces-v1";
pub(crate) const ACTION_FEATURE: &str = "context-assistance-native-decisions-v1";
pub(crate) const HISTORY_FEATURE: &str = "context-assistance-history-v1";
pub(crate) const VERSIONS_FEATURE: &str = "context-assistance-versions-v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    schema: String,
    request_id: String,
    pub(crate) query: Query,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Status,
    Installations,
    Versions,
    Recheck,
    Activate,
    Stop,
    Workspace,
    WorkspaceAccess,
    WorkspaceGrant,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Installations => "installations",
            Self::Versions => "versions",
            Self::Recheck => "recheck",
            Self::Activate => "activate",
            Self::Stop => "stop",
            Self::Workspace => "workspace",
            Self::WorkspaceAccess => "workspace_access",
            Self::WorkspaceGrant => "workspace_grant",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Query {
    kind: Kind,
    pub(crate) guard_home: String,
    input: serde_json::Value,
}

fn request_limit(request: &Request) -> usize {
    if matches!(request.query.kind, Kind::Versions)
        && request.query.input.get("action").and_then(|v| v.as_str()) == Some("import_catalog")
    {
        4 * 1024 * 1024
    } else {
        64 * 1024
    }
}

pub(crate) fn evaluate(request: &Request, store: &PolicySnapshotStore) -> Result<Vec<u8>, String> {
    let digest = request_digest_with_limit(request, request_limit(request))
        .map_err(|_| "native_context_assistance_request_too_large")?;
    let answer = (|| {
        validate(request, store)?;
        let home = Path::new(&request.query.guard_home);
        let service = store.context_assistance();
        if matches!(request.query.kind, Kind::Stop) {
            service.stop()?;
            crate::guard_config_update::disable_context_assistance(home)?;
        }
        let generation = service.configuration_generation()?;
        let settings = match crate::guard_config_load::context_assistance_config(home) {
            Ok(value) => value,
            Err(_reason) => {
                #[cfg(test)]
                eprintln!(
                    "CIGAR_CONFIG_READ_FAILURE={}",
                    json!({"reason":_reason,
                    "kind":request.query.kind.name(),"action":request.query.input.get("action")})
                );
                let repair = matches!(request.query.kind, Kind::Workspace | Kind::WorkspaceAccess)
                    && matches!(
                        request.query.input.get("action").and_then(|v| v.as_str()),
                        Some(
                            "data" | "clear" | "forget_history" | "forget_saved" | "resume_erasure"
                        )
                    );
                if !repair {
                    service.configure_at(
                        AssistanceSettings::unavailable("configuration_unavailable"),
                        generation,
                    )?;
                    return Err("native_context_assistance_configuration_unavailable".into());
                }
                AssistanceSettings::unavailable("configuration_unavailable")
            }
        };
        service.configure_at(settings, generation)?;
        service.ensure_housekeeping(home);
        let data = if matches!(
            request.query.kind,
            Kind::Workspace | Kind::WorkspaceAccess | Kind::WorkspaceGrant
        ) {
            Some(service.workspace(
                home,
                store,
                request.query.input.clone(),
                matches!(request.query.kind, Kind::WorkspaceAccess),
                matches!(request.query.kind, Kind::WorkspaceGrant),
            )?)
        } else if matches!(request.query.kind, Kind::Versions) {
            Some(json!({"schema":"guard-cigar-versions-result.v1",
                "result":service.versions(home, request.query.input.clone())?}))
        } else {
            None
        };
        match request.query.kind {
            Kind::Activate => service.schedule(Check::Activate, home.into())?,
            Kind::Recheck => service.schedule(Check::Recheck, home.into())?,
            Kind::Status
            | Kind::Installations
            | Kind::Versions
            | Kind::Stop
            | Kind::Workspace
            | Kind::WorkspaceAccess
            | Kind::WorkspaceGrant => {}
        }
        let mut state = service.status()?;
        if matches!(request.query.kind, Kind::Installations) {
            state["installation_options"] = json!(
                crate::policy_store::context_assistance_registry::list(home)?
            );
        }
        let mut payload = json!({"kind": request.query.kind.name(), "state": state});
        if let Some(data) = data {
            payload["data"] = data;
        }
        Ok(payload)
    })();
    response(request, &digest, answer)
}

fn validate(request: &Request, store: &PolicySnapshotStore) -> Result<(), String> {
    if request.schema != "guard-context-assistance-request.v1"
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || !Path::new(&request.query.guard_home).is_absolute()
    {
        return Err("native_context_assistance_request_invalid".into());
    }
    store.require_guard_home(&request.query.guard_home)?;
    if !matches!(
        request.query.kind,
        Kind::Workspace | Kind::WorkspaceAccess | Kind::WorkspaceGrant | Kind::Versions
    ) && request
        .query
        .input
        .as_object()
        .is_none_or(|input| !input.is_empty())
    {
        return Err("native_context_assistance_control_input_invalid".into());
    }
    Ok(())
}

pub(crate) fn reject_busy(
    request: &Request,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let digest = request_digest_with_limit(request, request_limit(request))
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
    let response = match answer {
        Ok(payload) => {
            json!({"schema":"guard-context-assistance-result.v1", "request_id":request.request_id,
            "request_sha256":digest, "status":"ok", "code":"ok", "payload":payload})
        }
        Err(code) => {
            json!({"schema":"guard-context-assistance-result.v1", "request_id":request.request_id,
            "request_sha256":digest, "status":"error", "code":code, "payload":null})
        }
    };
    crate::encode_response(&response)
}

#[cfg(test)]
#[path = "context_assistance_op_tests.rs"]
mod tests;

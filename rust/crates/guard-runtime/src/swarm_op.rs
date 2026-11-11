//! Authenticated, Guard-home-bound resident endpoint for local agent discovery.
use crate::package_authority_op::request_digest_with_limit;
use crate::policy_store::PolicySnapshotStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Mutex;
#[cfg(test)]
#[path = "swarm_op_tests.rs"]
mod tests;

pub(crate) const FEATURE: &str = "swarm-v1";

#[derive(Default)]
pub(crate) struct ResidentSwarm {
    service: guard_swarm::Service,
    checkpoint: Mutex<Checkpoint>,
}

impl ResidentSwarm {
    pub(crate) fn shutdown(&self) {
        self.service.shutdown();
    }

    pub(crate) fn has_active_runs(&self) -> bool {
        self.service.has_active_runs()
    }
}

#[derive(Default)]
struct Checkpoint {
    initialized: bool,
    bytes: Vec<u8>,
}

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
    pub(crate) guard_home: String,
    cli_path: String,
    pub(crate) input: Input,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Input {
    Snapshot {},
    Launch { launch: guard_swarm::Launch },
    Direct { request: guard_swarm::Action },
    Events { run_id: String },
}

pub(crate) fn evaluate(request: &Request, store: &PolicySnapshotStore) -> Result<Vec<u8>, String> {
    let digest =
        request_digest_with_limit(request, 32_768).map_err(|_| "native_swarm_request_too_large")?;
    let answer = (|| {
        if request.schema != "guard-swarm-request.v1" || !guard_swarm::valid_id(&request.request_id)
        {
            return Err("native_swarm_request_invalid".to_owned());
        }
        store.require_guard_home(&request.query.guard_home)?;
        let swarm = store.swarm();
        swarm
            .service
            .configure_cli_path(&request.query.cli_path)
            .map_err(str::to_owned)?;
        let mut checkpoint = swarm.checkpoint.lock().map_err(|_| "swarm_unavailable")?;
        let home = std::path::Path::new(&request.query.guard_home);
        let history_path = home.join("swarm-history.v1.json");
        if !checkpoint.initialized {
            if let Some(bytes) = crate::policy_store::read_private_file(
                &history_path,
                524_288,
                "swarm_history",
                home,
            )? {
                let history: Vec<guard_swarm::Agent> =
                    serde_json::from_slice(&bytes).map_err(|_| "swarm_history_invalid")?;
                swarm
                    .service
                    .restore_history(history)
                    .map_err(str::to_owned)?;
            }
            checkpoint.initialized = true;
        }
        let payload = match &request.query.input {
            Input::Snapshot {} => {
                json!({"snapshot": swarm.service.snapshot().map_err(str::to_owned)?})
            }
            Input::Launch { launch } => {
                json!({"agent": swarm.service.launch(launch.clone()).map_err(str::to_owned)?})
            }
            Input::Direct { request } => {
                json!({"agent": swarm.service.action(request.clone()).map_err(str::to_owned)?})
            }
            Input::Events { run_id } => {
                json!({"events": swarm.service.events(run_id).map_err(str::to_owned)?})
            }
        };
        let history = swarm.service.history().map_err(str::to_owned)?;
        let bytes = serde_json::to_vec(&history).map_err(|_| "swarm_history_invalid")?;
        if !history.is_empty() && bytes != checkpoint.bytes {
            crate::policy_store::persist_private_bytes(
                &history_path,
                &bytes,
                524_288,
                "swarm_history",
                home,
            )?;
            checkpoint.bytes = bytes;
        }
        Ok(payload)
    })();
    let (status, code, payload) = match answer {
        Ok(payload) => ("ok", "ok".to_owned(), payload),
        Err(code) => ("error", code, serde_json::Value::Null),
    };
    crate::encode_response(
        &json!({"schema":"guard-swarm-result.v1", "request_id":request.request_id,
        "request_sha256":digest, "status":status, "code":code, "payload":payload}),
    )
}

//! `POST /v1/hooks/<harness>/readiness`, kept beside the hook route it
//! prepares for.

use serde_json::{json, Map, Value};

use super::admission::{truthy, Rejection};
use super::Hook;

impl Hook<'_> {
    /// `POST /v1/hooks/<harness>/readiness`: prepares the workspace's policy
    /// before a host's timed hook starts.
    pub(super) fn readiness(&self, payload: &Map<String, Value>) -> (u16, Value, bool) {
        let not_ready = (
            503,
            json!({ "ready": false, "reason_code": "native_policy_not_ready" }),
            true,
        );
        let invalid = |rejection: &Rejection| {
            (
                400,
                json!({
                    "ready": false,
                    "reason_code": format!("invalid_{}", rejection.parameter.replace('-', "_")),
                }),
                true,
            )
        };
        let guard_home = self.settle(&[("guard-home", self.param("guard-home"), None)]);
        if let Err(rejection) = guard_home.require("guard-home") {
            self.audit_rejection(&rejection.to_value());
            return invalid(&rejection);
        }
        let candidate = self.raw_param("workspace").or_else(|| {
            let named = payload.get("workspace");
            if truthy(named) {
                named
            } else {
                payload.get("cwd")
            }
            .and_then(Value::as_str)
            .map(str::to_owned)
        });
        let directories = self.settle(&[("workspace", candidate, Some("hook-workspace"))]);
        let (workspace, rejection) = match directories.require("workspace") {
            Ok(workspace) => (workspace, None),
            Err(rejection) => (None, Some(rejection)),
        };
        // An unmanaged app's hooks never reach a workspace, so its refused
        // workspace is not audited.
        if self.unmanaged(&self.managed_harness(), std::time::Instant::now()) {
            return (
                200,
                json!({
                    "ready": true,
                    "native_required": false,
                    "workspace_acknowledged": false,
                    "worker_ready": true,
                }),
                true,
            );
        }
        if let Some(rejection) = rejection {
            self.audit_rejection(&rejection.to_value());
            return invalid(&rejection);
        }
        let Some(workspace) = workspace else {
            return (
                400,
                json!({ "ready": false, "reason_code": "workspace_required" }),
                true,
            );
        };
        let Some(ready) = self.call("hook.ready", json!({ "workspace": workspace })) else {
            return not_ready;
        };
        if ready.get("prepared") != Some(&Value::Bool(true)) {
            return not_ready;
        }
        (
            200,
            json!({
                "ready": true,
                "native_required": true,
                "native_route": "native_resident",
                "workspace_acknowledged": true,
                "worker_ready": true,
            }),
            true,
        )
    }
}

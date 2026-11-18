//! The Codex install plan, and the `prepare_install` op that reports it
//! without publishing.
//!
//! One request builds both the plan an install publishes and the plan a
//! transition prepares: the captured sources, the authenticated bindings, the
//! mcp servers the managed launches come from, and the generation to write.

use serde_json::{json, Map, Value};

use super::codex_detection::{self, Detection};
use super::codex_managed::{
    baseline, bindings, capture, facts, manifest_text, pairs, raised, spec_of, text, Facts,
};
use super::dispatch;
use crate::harness_adapter::managed_install_target::{stopped, Owned, INVALID};
use crate::harness_adapter::{Ctx, Failure, Spec, Step};
use crate::transition_files::OwnedFailure;

/// The `install_plan` (or whole `install`) request over a capture. `enroll`
/// may create the hook key and checks every active handler's owner.
pub(super) fn plan_fields(
    request: &Map<String, Value>,
    facts: &Facts<'_>,
    previous: &Option<Value>,
    owned: &[Value],
    contents: Map<String, Value>,
    artifacts: &[Value],
    enroll: bool,
) -> Owned<Map<String, Value>> {
    let mut fields = facts.transition_now();
    fields.insert("launch".into(), Value::Object(facts.launch.clone()));
    fields.insert("contents".into(), Value::Object(contents));
    fields.insert(
        "owned".into(),
        json!(serde_json::to_string(owned).map_err(|_| INVALID)?),
    );
    fields.insert("require_owners".into(), json!(enroll));
    fields.insert(
        "artifacts".into(),
        Value::Array(
            artifacts
                .iter()
                .filter(|artifact| {
                    artifact.get("artifact_type").and_then(Value::as_str) == Some("mcp_server")
                })
                .cloned()
                .collect(),
        ),
    );
    fields.insert(
        "generation".into(),
        json!({ "previous_manifest": previous, "create_key": enroll }),
    );
    fields.insert(
        "interpreter".into(),
        request.get("interpreter").cloned().unwrap_or(Value::Null),
    );
    fields.insert(
        "package_root".into(),
        facts.codex.get("package_root").cloned().ok_or(INVALID)?,
    );
    Ok(fields)
}

fn prepared(spec: &Spec, ctx: &Ctx, request: &Map<String, Value>) -> Owned<Value> {
    let facts = facts(ctx, request).map_err(|_| INVALID)?;
    let spec_value = spec_of(ctx, &facts)?;
    let previous = baseline(ctx, &facts, &spec_value)?;
    let owned = bindings(previous.as_ref());
    let contents = capture(ctx, &facts, &pairs(ctx))?;
    let Detection {
        artifacts,
        found_paths,
        ..
    } = codex_detection::detect(ctx, &facts.launch, &owned, Some(&contents)).map_err(stopped)?;
    let fields = plan_fields(
        request, &facts, &previous, &owned, contents, &artifacts, false,
    )?;
    let plan = dispatch(spec, "install_plan", ctx, &fields).map_err(stopped)?;
    if let Some(failure) = raised(&plan) {
        return Err(failure);
    }
    let files = plan.get("files").ok_or(INVALID)?;
    let manifest_path = files
        .get(1)
        .and_then(|file| file.get("path"))
        .cloned()
        .ok_or(INVALID)?;
    let list = |key: &str| plan.get(key).cloned().ok_or(INVALID);
    let explicit = facts
        .launch
        .get("workspace_explicit")
        .and_then(Value::as_bool)
        == Some(true);
    let manifest = manifest_text(
        spec,
        ctx,
        "prepare",
        &text(&plan, "shim_manifest")?,
        explicit,
        &[
            ("manifest_path", manifest_path),
            ("integrity", json!("authenticated")),
            ("backup_path", text(&plan, "backup_path")?),
            ("managed", list("managed_servers")?),
            ("migrated", list("migrated")?),
            ("skipped", list("skipped_servers")?),
            ("source_config_paths", json!(found_paths)),
        ],
    )?;
    Ok(json!({ "files": files, "manifest": manifest }))
}

/// `CodexHarnessAdapter.prepare_install`: the plan's files and manifest.
pub(super) fn prepare_install(spec: &Spec, ctx: &Ctx, request: &Map<String, Value>) -> Step<Value> {
    match prepared(spec, ctx, request) {
        Ok(answer) => Ok(answer),
        Err(OwnedFailure::Untrusted(untrusted)) => Ok(json!({ "untrusted": untrusted })),
        Err(OwnedFailure::Integrity(reason, message)) => {
            Ok(json!({ "untrusted": { "reason": reason, "message": message } }))
        }
        Err(OwnedFailure::Fault(fault)) => Ok(json!({ "fault": fault })),
        Err(_) => Err(Failure::Invalid),
    }
}

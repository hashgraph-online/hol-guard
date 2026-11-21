//! The observation of a configured Codex hook, ported from
//! `_observe_configured_codex_hook`.
//!
//! An observer proves protection by running the exact pre-tool command the
//! authenticated manifest registered, twice: a command the policy allows and
//! one it denies. Both launches must show the expected decision in the hook's
//! output and in a receipt the runtime accepts, under one policy, while the
//! signed config and manifest stay what the binding authenticated. The caller
//! keeps the facts only its process knows (which transaction owner it holds,
//! its environment) and seals the admission this answers.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::publication::Call;
use super::publication_observe_check::{canonical_uuid, digest, mapping, strings};
use super::publication_observe_legacy::{expired, Legacy};
use super::publication_observe_run::{agreed, Run};
use super::publication_observer::{invalid, observed, sha256, syntax_of, MISSING};
use super::{Fault, Step};
use crate::hook_process_spawn::{
    desktop_hook_proxy_context, isolated_hook_environment, private_hook_runtime_cwd,
};
use crate::pyjson::PyVal;

const MAX_DEADLINE_MS: u64 = 600_000;
const CHANGED: &str = "admission_hook_binding_changed";

/// Request, besides the binding's: `operation_id`, `artifact_generation`,
/// `runtime_sha256`, `owned` (the caller holds the transaction owner),
/// `workspace`, `environ`, `deadline_ms` and, for a legacy package,
/// `legacy_store` (`home`, `path`, `source`).
pub(super) fn observe(call: &mut Call<'_>) -> Step<Value> {
    let budget = call.args.get("deadline_ms").and_then(Value::as_u64);
    let deadline = Instant::now()
        + Duration::from_millis(
            budget
                .ok_or(Fault::Transition("files_invalid"))?
                .min(MAX_DEADLINE_MS),
        );
    expired(deadline)?;
    let operation_id = call.text("operation_id")?.to_owned();
    if !canonical_uuid(&operation_id) || call.text("artifact_generation")?.is_empty() {
        return Err(Fault::Transition("admission_identity_invalid"));
    }
    if call.args.get("owned").and_then(Value::as_bool) != Some(true) {
        return Err(Fault::Integrity(
            "codex_hook_transaction_owner_missing".to_owned(),
            "Codex mutation requires exclusive installation ownership.".to_owned(),
        ));
    }
    let home = call.home()?;
    let config_path = call.path("config")?;
    let (manifest_path, _) = Call::targets(&home, &call.canonical(&config_path)?);
    let before_config = call.snapshot(&config_path)?;
    let before_manifest = call.snapshot(&manifest_path)?;
    expired(deadline)?;
    let (Some(before_config), Some(before_manifest)) = (before_config, before_manifest) else {
        return Err(Fault::Transition(MISSING));
    };
    let mut syntax = syntax_of(call)?;
    let launch = observed(call, &mut syntax)?;
    if launch.config_sha256 != sha256(&before_config)
        || launch.manifest_sha256 != sha256(&before_manifest)
    {
        return Err(Fault::Transition(CHANGED));
    }
    let cwd = private_hook_runtime_cwd(Path::new(&launch.manifest_path)).map_err(|_| invalid())?;
    let environment = launch_environment(call, &launch.environment)?;
    expired(deadline)?;
    let legacy = if launch.modern {
        None
    } else {
        Some(Legacy::open(call, &home, deadline)?)
    };
    let recheck = |legacy: &Option<Legacy>| -> Step<()> {
        expired(deadline)?;
        legacy.as_ref().map_or(Ok(()), Legacy::recheck)
    };
    let signed = [
        (config_path.as_path(), before_config.as_slice()),
        (manifest_path.as_path(), before_manifest.as_slice()),
    ];
    intact(call, &signed)?;
    let workspace = call.text("workspace")?.to_owned();
    let runtime = call.text("runtime_sha256")?.to_owned();
    let run = Run {
        argv: &launch.argv,
        modern: launch.modern,
        cwd: &cwd,
        environment: &environment,
        workspace: &workspace,
        operation_id: &operation_id,
        runtime: &runtime,
        deadline,
        legacy: legacy.as_ref(),
    };
    let probed = run.probes(&|| Ok(format!("transition-hook-{}", random_hex()?)))?;
    expired(deadline)?;
    recheck(&legacy)?;
    intact(call, &signed)?;
    expired(deadline)?;
    let (generation, policy) = agreed(&probed.receipts)?;
    let (allow, deny) = (&probed.receipts[0], &probed.receipts[1]);
    let outputs = probed.outputs;
    let channel = if launch.modern {
        "probe-envelope"
    } else {
        "persisted-receipt"
    };
    let evidence = json!({
        "schema": "hol-guard.installed-hook-evidence.v1",
        "harness": "codex",
        "observation_channel": channel,
        "config_sha256": sha256(&before_config),
        "manifest_sha256": sha256(&before_manifest),
        "argv_sha256": digest(&strings(&launch.argv)),
        "environment_sha256": digest(&environment_text(&launch.environment)),
        "output_sha256": outputs,
    });
    Ok(json!({
        "allow": allow,
        "deny": deny,
        "generation": generation,
        "policy_digest": policy,
        "evidence": evidence,
    }))
}

/// The signed config and manifest still hold the bytes the binding authenticated.
pub(super) fn intact(call: &Call<'_>, files: &[(&Path, &[u8])]) -> Step<()> {
    for (path, bytes) in files {
        if call.snapshot(path)?.as_deref() != Some(*bytes) {
            return Err(Fault::Transition(CHANGED));
        }
    }
    Ok(())
}

/// The binding's environment as the digest names it: strings only.
fn environment_text(environment: &Map<String, Value>) -> PyVal {
    let pairs: Vec<(String, String)> = environment
        .iter()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
        .collect();
    mapping(pairs.iter().map(|(key, value)| (key, value)))
}

/// What the hook runs under: the caller's allow-listed environment, the
/// binding's own variables, and the signed Desktop proxy selectors last.
fn launch_environment(
    call: &Call<'_>,
    binding: &Map<String, Value>,
) -> Step<BTreeMap<String, String>> {
    let source = call
        .args
        .get("environ")
        .and_then(Value::as_object)
        .ok_or(Fault::Transition("files_invalid"))?;
    let source: BTreeMap<String, String> = source
        .iter()
        .map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
        .collect::<Option<_>>()
        .ok_or(Fault::Transition("files_invalid"))?;
    let mut environment = isolated_hook_environment(&source);
    for (key, value) in binding {
        if let Some(value) = value.as_str() {
            environment.insert(key.clone(), value.to_owned());
        }
    }
    environment.extend(desktop_hook_proxy_context(&source));
    Ok(environment)
}

fn random_hex() -> Step<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| Fault::Transition("files_invalid"))?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
#[path = "tests_publication_observe.rs"]
mod tests;

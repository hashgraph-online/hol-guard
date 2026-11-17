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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::publication::Call;
use super::publication_observe_check::{
    canonical_uuid, digest, mapping, modern_receipt, protects, strings, PROBE_FIELD, PROBE_SCHEMA,
};
use super::publication_observe_legacy::{Legacy, EXPIRED};
use super::publication_observer::{invalid, observed, sha256, syntax_of, MISSING};
use super::{Fault, Step};
use crate::hook_evidence_correlation::derive_proven_request_correlation;
use crate::hook_process_spawn::{
    desktop_hook_proxy_context, isolated_hook_environment, private_hook_runtime_cwd,
    run_isolated_hook_process,
};
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::pyjson::{self, PyVal};

const MAX_DEADLINE_MS: u64 = 600_000;
const OUTPUT_LIMIT: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(25);
const CHANGED: &str = "admission_hook_binding_changed";
const PROTECTION: &str = "admission_protection_failed";
/// The two probes, in order: the command is a classification input only.
const PROBES: [(&str, &str); 2] = [("pwd", "allow"), ("rm -rf /", "deny")];

fn expired(deadline: Instant) -> Step<()> {
    if Instant::now() >= deadline {
        return Err(Fault::Transition(EXPIRED));
    }
    Ok(())
}

fn protection<T>() -> Step<T> {
    Err(Fault::Transition(PROTECTION))
}

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
    let unchanged = |call: &Call<'_>| -> Step<bool> {
        Ok(call.snapshot(&config_path)? == Some(before_config.clone())
            && call.snapshot(&manifest_path)? == Some(before_manifest.clone()))
    };
    if !unchanged(call)? {
        return Err(Fault::Transition(CHANGED));
    }
    let workspace = call.text("workspace")?.to_owned();
    let runtime = call.text("runtime_sha256")?.to_owned();
    let mut receipts: Vec<Value> = Vec::new();
    let mut outputs: Vec<String> = Vec::new();
    for (command, decision) in PROBES {
        expired(deadline)?;
        let request_id = format!("transition-hook-{}", random_hex()?);
        let mut payload = Map::new();
        payload.insert("hook_event_name".to_owned(), json!("PreToolUse"));
        payload.insert("tool_name".to_owned(), json!("Bash"));
        payload.insert("tool_input".to_owned(), json!({ "command": command }));
        payload.insert("cwd".to_owned(), json!(workspace));
        if launch.modern {
            payload.insert(
                PROBE_FIELD.to_owned(),
                json!({
                    "schema": PROBE_SCHEMA,
                    "operation_id": operation_id,
                    "request_id": request_id,
                }),
            );
        } else {
            payload.insert("tool_call_id".to_owned(), json!(request_id));
        }
        recheck(&legacy)?;
        let since = now_isoformat()?;
        // The manifest-authenticated command is the launch target; frozen
        // Desktop bridge routing happens only after that exact configured
        // command has parsed and validated this probe.
        let result = run_isolated_hook_process(
            &launch.argv,
            &Value::Object(payload.clone()).to_string(),
            &cwd,
            &environment,
            None,
            Some(OUTPUT_LIMIT),
            None,
            Some(deadline),
        );
        expired(deadline)?;
        if result.returncode != Some(0)
            || result.timed_out
            || result.containment_failed
            || result.output_limit_exceeded
        {
            return Err(Fault::Transition("admission_hook_launch_failed"));
        }
        let Some(output) = pyjson::parse(&result.stdout)
            .ok()
            .filter(|output| output.as_dict().is_some())
        else {
            return protection();
        };
        let Some(json_output) = output.to_json() else {
            return protection();
        };
        let receipt = if let Some(legacy) = &legacy {
            let correlation =
                derive_proven_request_correlation("codex", "PreToolUse", &payload, legacy.key());
            let Ok(Some(correlation)) = correlation else {
                return protection();
            };
            loop {
                legacy.recheck()?;
                if let Some(receipt) = legacy.receipt(&correlation, &since)? {
                    break receipt;
                }
                expired(deadline)?;
                std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
        } else {
            match modern_receipt(&result.stderr, &operation_id, &request_id) {
                Some(receipt) => receipt,
                None => return protection(),
            }
        };
        if !protects(&receipt, &json_output, decision, &runtime) {
            return protection();
        }
        receipts.push(receipt);
        outputs.push(digest(&output));
    }
    expired(deadline)?;
    recheck(&legacy)?;
    if !unchanged(call)? {
        return Err(Fault::Transition(CHANGED));
    }
    expired(deadline)?;
    let (allow, deny) = (&receipts[0], &receipts[1]);
    let generation = allow
        .get("policy_generation")
        .cloned()
        .unwrap_or(Value::Null);
    let policy = allow.get("policy_digest").cloned().unwrap_or(Value::Null);
    if !(generation.is_i64() || generation.is_u64()) || !policy.is_string() {
        return Err(Fault::Transition("admission_policy_mismatch"));
    }
    if Some(&generation) != deny.get("policy_generation")
        || Some(&policy) != deny.get("policy_digest")
        || allow.get("request_digest") == deny.get("request_digest")
    {
        return Err(Fault::Transition("admission_policy_mismatch"));
    }
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

/// `datetime.now(timezone.utc).isoformat()`.
fn now_isoformat() -> Step<String> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_micros()).ok())
        .ok_or(Fault::Transition("files_invalid"))?;
    micros_to_utc_isoformat(micros, "+00:00").ok_or(Fault::Transition("files_invalid"))
}

#[cfg(test)]
#[path = "tests_publication_observe.rs"]
mod tests;

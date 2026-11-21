//! `transition_files` - the file transaction behind a runtime transition and
//! an adapter install publish.
//!
//! Ported from `RuntimeTransition._compare`, `RuntimeTransition._write_file`
//! and `PreparedHarnessInstall.publish`. A change names one absolute file, the
//! bytes and mode it held before and should hold after, and how it is
//! replaced. `compare` proves every file still holds one generation, `write`
//! publishes one generation of one file, and `publish` runs the whole plan:
//! compare, write each file after re-comparing it, compare the result, and on
//! failure restore what it wrote.
//!
//! Each write hands back the Codex mutation identity record, in order,
//! interleaved with the index of every file written so the caller's
//! `on_write` sees the same sequence; `journal` appends those records to the
//! owning transaction's journal. One fact stays with the asking interpreter:
//! which directories are its own package roots (`package_roots`).

mod config_scope;
mod digest_cache;
mod inspect;
mod journal;
mod lease;
mod lock_files;
mod merge_dependency;
mod output;
mod owned;
mod owned_locks;
mod owned_ops;
mod publication;
mod publication_abort;
mod publication_artifact_generation;
mod publication_authorize;
mod publication_baseline;
mod publication_commit;
mod publication_coordinate;
mod publication_files;
mod publication_generation;
mod publication_inspect_runtime;
mod publication_inverse_pinned;
mod publication_inverse_plan;
mod publication_inverse_prepare;
mod publication_inverse_publish;
mod publication_inverse_registry;
mod publication_io;
mod publication_lean;
mod publication_observe;
mod publication_observe_check;
mod publication_observe_legacy;
mod publication_observe_run;
mod publication_observer;
mod publication_pin_executable;
mod publication_pin_stamp;
mod publication_prepare_request;
mod publication_proof;
mod publication_receipt;
mod publication_repair_files;
mod publication_repair_plan;
mod publication_repair_prepare;
mod publication_repair_request;
mod publication_request;
mod publication_request_policy;
mod publication_runtime_compare;
mod publication_short_replies;
mod publication_target;
mod python_equal;
mod repair_claims;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_owned;
#[cfg(test)]
mod tests_owned_locks;
#[cfg(test)]
mod tests_publication_artifact_generation;
#[cfg(test)]
mod tests_publication_authorize;
#[cfg(test)]
mod tests_publication_inspect_runtime;
#[cfg(test)]
mod tests_publication_inverse_plan;
#[cfg(test)]
mod tests_publication_pin_executable;
#[cfg(test)]
mod tests_publication_prepare_request;
#[cfg(test)]
mod tests_publication_proof;
#[cfg(test)]
mod tests_publication_repair_plan;
#[cfg(test)]
mod tests_publication_repair_request;
#[cfg(test)]
mod tests_publication_request_policy;
#[cfg(test)]
mod tests_publication_runtime_compare;
#[cfg(test)]
mod tests_publication_target;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) use config_scope::{within as within_config_scope, HeldDirectory};
pub(crate) use inspect::resolve_lenient;
pub(crate) use lease::{hold_install_lock, hold_opencode_lock};
pub(crate) use output::{managed_write, remove_no_follow, write_no_follow};
pub(crate) use owned::{recover as recover_publication, with_owned, Owner, Spec as OwnedSpec};
pub(crate) use owned_locks::Failure as OwnedFailure;
pub(crate) use owned_ops::with_registered;
pub(crate) use publication_short_replies::first_ask_due as short_replies_first_ask_due;

/// The plan sizes `_record_files` accepts, with room for an install that
/// publishes beside them.
const MAX_FILES: usize = 256;
const MAX_BUDGET_MS: u64 = 600_000;

/// Why a step stopped, in the exception the Python caller raises for it.
#[derive(Debug)]
pub(crate) enum Fault {
    /// `TransitionError(reason)`.
    Transition(&'static str),
    /// `CodexHookIntegrityError(code, message)`.
    Integrity(String, String),
    /// `TransitionError(reason, detail)` for a change no transition may record.
    Refused(String, Option<String>),
    /// `OSError`, with its errno when the platform reported one.
    Os(std::io::Error),
    /// `RuntimeError(message)`, as a retained config's TOML parse raises it.
    Runtime(String),
}

impl From<std::io::Error> for Fault {
    fn from(error: std::io::Error) -> Self {
        Self::Os(error)
    }
}

impl Fault {
    fn to_json(&self) -> Value {
        match self {
            Self::Transition(reason) => json!({ "transition": reason }),
            Self::Refused(reason, None) => json!({ "transition": reason }),
            Self::Refused(reason, Some(detail)) => {
                json!({ "transition": reason, "detail": detail })
            }
            Self::Integrity(code, message) => json!({ "integrity": code, "message": message }),
            Self::Os(error) => json!({ "os": error.to_string(), "errno": error.raw_os_error() }),
            Self::Runtime(message) => json!({ "runtime": message }),
            // Asked once a write has started, the question can no longer be
            // answered before the plan is published, so it refuses the file.
        }
    }
}

pub(crate) type Step<T> = Result<T, Fault>;

/// The deadlines the caller's context carried, as remaining milliseconds.
#[derive(Clone, Copy)]
pub(crate) struct Budget {
    inverse: Option<Instant>,
    forward: Option<Instant>,
    hook: Option<Instant>,
}

impl Budget {
    pub(crate) fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
        let fields = match value {
            None | Some(Value::Null) => return Ok(Self::none()),
            Some(Value::Object(fields)) => fields,
            Some(_) => return Err(ERR_INVALID),
        };
        let now = Instant::now();
        let deadline = |key: &str| -> Result<Option<Instant>, &'static str> {
            match fields.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => {
                    let millis = value.as_u64().ok_or(ERR_INVALID)?;
                    Ok(Some(now + Duration::from_millis(millis.min(MAX_BUDGET_MS))))
                }
            }
        };
        Ok(Self {
            inverse: deadline("inverse_ms")?,
            forward: deadline("forward_ms")?,
            hook: deadline("hook_ms")?,
        })
    }

    pub(crate) fn none() -> Self {
        Self {
            inverse: None,
            forward: None,
            hook: None,
        }
    }

    fn expired(deadline: Option<Instant>) -> bool {
        deadline.is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// `_check_inverse_deadline`.
    pub(crate) fn inverse(&self) -> Step<()> {
        if Self::expired(self.inverse) {
            return Err(Fault::Transition("deadline_exceeded"));
        }
        Ok(())
    }

    /// The inverse budget, then the active transition's forward grant.
    pub(crate) fn forward(&self) -> Step<()> {
        self.inverse()?;
        if Self::expired(self.forward) {
            return Err(Fault::Transition("forward_authorization_expired"));
        }
        Ok(())
    }

    /// `check_hook_validation_deadline`.
    pub(crate) fn hook(&self) -> Step<()> {
        if Self::expired(self.hook) {
            return Err(Fault::Integrity(
                "codex_hook_validation_deadline_expired".to_owned(),
                "Codex hook identity validation exhausted the operation deadline.".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Everything one request carries besides the plan itself.
pub(crate) struct Ask {
    pub(crate) budget: Budget,
    pub(crate) package_roots: Vec<PathBuf>,
}

impl Ask {
    fn parse(args: &Map<String, Value>) -> Result<Self, &'static str> {
        let package_roots = match args.get("package_roots") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(PathBuf::from).ok_or(ERR_INVALID))
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(ERR_INVALID),
        };
        Ok(Self {
            budget: Budget::parse(args.get("budget"))?,
            package_roots,
        })
    }
}

/// `runner_authority` kind `transition_files`.
pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args.as_object().ok_or(ERR_INVALID)?;
    let ask = Ask::parse(args)?;
    let generation = |key: &str| match args.get(key).and_then(Value::as_str) {
        Some(value @ ("before" | "after")) => Ok(value),
        _ => Err(ERR_INVALID),
    };
    let flag = |key: &str| args.get(key).and_then(Value::as_bool).unwrap_or(false);
    let files = || -> Result<&Vec<Value>, &'static str> {
        let files = args
            .get("files")
            .and_then(Value::as_array)
            .ok_or(ERR_INVALID)?;
        if files.len() > MAX_FILES {
            return Err(ERR_INVALID);
        }
        Ok(files)
    };
    match args.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)? {
        "compare" => {
            if let Err(fault) = checked(files()?) {
                return Ok(settle(Err(fault)));
            }
            let compared = compare(files()?, generation("generation")?, flag("inverse"), &ask);
            Ok(settle(compared.map(|()| Vec::new())))
        }
        "write" => {
            let change = args
                .get("change")
                .and_then(Value::as_object)
                .ok_or(ERR_INVALID)?;
            let generation = generation("generation")?;
            let written = checked([&Value::Object(change.clone())])
                .and_then(|()| write(change, generation, &ask));
            Ok(settle(written))
        }
        "publish" => {
            if let Err(fault) = checked(files()?) {
                return Ok(settle(Err(fault)));
            }
            Ok(publish(files()?, flag("removals"), flag("rollback"), &ask))
        }
        "journal" => journal::dispatch(args),
        op if op.starts_with("owned_") => owned_ops::dispatch(op, args, &ask.budget),
        op @ ("lease_acquire" | "lease_release" | "lease_check") => lease::dispatch(op, args),
        op => publication_commit::dispatch(op, args, &ask.budget),
    }
}

/// Every change on its own meets the shape `TransitionFile.payload` checks.
fn checked<'a>(files: impl IntoIterator<Item = &'a Value>) -> Step<()> {
    for change in files {
        let change = change
            .as_object()
            .ok_or(Fault::Transition("files_invalid"))?;
        crate::runtime_transition_record::check_change(change)
            .map_err(|(reason, detail)| Fault::Refused(reason, detail))?;
    }
    Ok(())
}

fn settle(step: Step<Vec<Value>>) -> Value {
    match step {
        Ok(events) => json!({ "ok": true, "events": events }),
        Err(fault) => json!({ "error": fault.to_json(), "events": [] }),
    }
}

pub(crate) fn change_path(change: &Map<String, Value>) -> Step<PathBuf> {
    change
        .get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or(Fault::Transition("files_invalid"))
}

fn mode_field(change: &Map<String, Value>, key: &str) -> Option<u32> {
    change
        .get(key)
        .and_then(Value::as_i64)
        .and_then(|mode| u32::try_from(mode).ok())
}

/// `RuntimeTransition._compare`.
pub(crate) fn compare(files: &[Value], generation: &str, inverse: bool, ask: &Ask) -> Step<()> {
    for change in files {
        ask.budget.inverse()?;
        let change = change
            .as_object()
            .ok_or(Fault::Transition("files_invalid"))?;
        let target = change_path(change)?;
        if !target.is_absolute() || inspect::resolve_lenient(&target) != target {
            return Err(Fault::Transition("file_target_changed"));
        }
        if change.contains_key("expected_digest") {
            inspect::validate_digest_dependency(change)?;
            compare_dependency(change, &target, ask)?;
            continue;
        }
        let current = inspect::snapshot(&target, &ask.budget)?;
        let expected = inspect::decode(change.get(generation))?;
        let after = if inverse {
            Some(inspect::decode(change.get("after"))?)
        } else {
            None
        };
        if current != expected && after.as_ref().is_none_or(|after| current != *after) {
            return Err(Fault::Transition("generation_changed"));
        }
        if current.is_some() && cfg!(unix) {
            let mode = inspect::mode_of(&target)?;
            let expected = mode_field(change, &format!("{generation}_mode"));
            let after = mode_field(change, "after_mode");
            if Some(mode) != expected && !(inverse && Some(mode) == after) {
                return Err(Fault::Transition("file_mode_changed"));
            }
        }
    }
    Ok(())
}

/// A pinned authority file or artifact: compared by digest, never written.
fn compare_dependency(change: &Map<String, Value>, target: &Path, ask: &Ask) -> Step<()> {
    let expected = change.get("expected_digest").and_then(Value::as_str);
    let before_mode = mode_field(change, "before_mode");
    if let Some(identity) = change.get("artifact_identity") {
        let invocation = change
            .get("invocation_identity")
            .filter(|value| !value.is_null());
        let before = invocation
            .map(|invocation| inspect::invocation_generation(target, invocation, &ask.budget))
            .transpose()?;
        let digest = inspect::artifact_digest(target, identity, before_mode, ask)?;
        if Some(digest.as_str()) != expected {
            return Err(Fault::Transition("generation_changed"));
        }
        if let (Some(invocation), Some(before)) = (invocation, before) {
            if inspect::invocation_generation(target, invocation, &ask.budget)? != before {
                return Err(Fault::Transition("invocation_generation_changed"));
            }
        }
        return Ok(());
    }
    match inspect::snapshot(target, &ask.budget)? {
        Some(bytes) if Some(inspect::sha256_hex(&bytes).as_str()) == expected => {}
        _ => return Err(Fault::Transition("generation_changed")),
    }
    if cfg!(unix) && Some(inspect::mode_of(target)?) != before_mode {
        return Err(Fault::Transition("file_mode_changed"));
    }
    Ok(())
}

/// `RuntimeTransition._write_file`: the mutation records it produced.
pub(crate) fn write(change: &Map<String, Value>, generation: &str, ask: &Ask) -> Step<Vec<Value>> {
    ask.budget.inverse()?;
    if change.get("before") == change.get("after")
        && change.get("before_mode") == change.get("after_mode")
    {
        // Retained backups are compared as dependencies, never replaced.
        return Ok(Vec::new());
    }
    let target = change_path(change)?;
    let data = inspect::decode(change.get(generation))?;
    let mode = mode_field(change, &format!("{generation}_mode"))
        .ok_or(Fault::Transition("file_mode_invalid"))?;
    let no_follow = change.get("no_follow").and_then(Value::as_bool) == Some(true);
    let mut events = Vec::new();
    match (no_follow, data) {
        (true, None) => output::remove_no_follow(&target)?,
        (true, Some(data)) => output::write_no_follow(&target, &data, mode)?,
        (false, None) => events.push(output::restore_absent(&target)?),
        (false, Some(data)) => events.push(output::managed_write(&target, &data, mode)?),
    }
    ask.budget.inverse()?;
    Ok(events)
}

fn plan_invalid(files: &[Value], removals: bool) -> bool {
    files.iter().any(|change| {
        let Some(change) = change.as_object() else {
            return true;
        };
        let removes = change.get("after").is_none_or(Value::is_null);
        change.get("kind").and_then(Value::as_str) != Some("binding")
            || (!removals && removes && change.get("before") != change.get("after"))
    })
}

fn write_one(change: &Value, from: &str, to: &str, ask: &Ask) -> Step<Vec<Value>> {
    compare(std::slice::from_ref(change), from, false, ask)?;
    let object = change
        .as_object()
        .ok_or(Fault::Transition("files_invalid"))?;
    write(object, to, ask)
}

/// `PreparedHarnessInstall.publish`.
fn publish(files: &[Value], removals: bool, rollback: bool, ask: &Ask) -> Value {
    if plan_invalid(files, removals) {
        return settle(Err(Fault::Transition("adapter_install_plan_invalid")));
    }
    if let Err(fault) = compare(files, "before", false, ask) {
        return settle(Err(fault));
    }
    let mut events = Vec::new();
    let mut written = Vec::new();
    let forward = (|| -> Step<()> {
        for (index, change) in files.iter().enumerate() {
            events.extend(write_one(change, "before", "after", ask)?);
            written.push(index);
            events.push(json!({ "written": index }));
        }
        compare(files, "after", false, ask)
    })();
    let Err(fault) = forward else {
        return json!({ "ok": true, "events": events });
    };
    let mut answer = json!({ "error": fault.to_json() });
    if rollback {
        let mut restore_fault = None;
        for index in written.into_iter().rev() {
            match write_one(&files[index], "after", "before", ask) {
                Ok(records) => events.extend(records),
                Err(failure) => restore_fault = Some(failure),
            }
        }
        if let Some(failure) = restore_fault {
            answer["restore_error"] = failure.to_json();
        }
    }
    answer["events"] = Value::Array(events);
    answer
}

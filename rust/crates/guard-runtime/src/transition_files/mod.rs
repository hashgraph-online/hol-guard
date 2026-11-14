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
//! Two facts stay with the asking interpreter. The Codex mutation journal is
//! appended by the process that owns the install transaction, so each write
//! hands back the identity record it would append, in order, interleaved
//! with the index of every file written so the caller's `on_write` sees the
//! same sequence. Whether a POSIX group is private to its owner means
//! enumerating the account database, so an answer that turns on it asks
//! back with `reply.private_group` before anything is written.

mod inspect;
mod output;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::runner_authority_op::{KindResult, ERR_INVALID};

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
    /// `OSError`, with its errno when the platform reported one.
    Os(std::io::Error),
    /// The private-group fact this answer needs.
    PrivateGroup { owner_uid: u32, group_gid: u32 },
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
            Self::Integrity(code, message) => json!({ "integrity": code, "message": message }),
            Self::Os(error) => json!({ "os": error.to_string(), "errno": error.raw_os_error() }),
            // Asked once a write has started, the question can no longer be
            // answered before the plan is published, so it refuses the file.
            Self::PrivateGroup { .. } => json!({ "transition": "artifact_permissions_invalid" }),
        }
    }
}

pub(crate) type Step<T> = Result<T, Fault>;

/// The deadlines the caller's context carried, as remaining milliseconds.
pub(crate) struct Budget {
    inverse: Option<Instant>,
    forward: Option<Instant>,
    hook: Option<Instant>,
}

impl Budget {
    fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
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
    pub(crate) package_files: Vec<PathBuf>,
    pub(crate) private_groups: Vec<(u32, u32, bool)>,
}

impl Ask {
    fn parse(args: &Map<String, Value>) -> Result<Self, &'static str> {
        let package_files = match args.get("package_files") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(PathBuf::from).ok_or(ERR_INVALID))
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(ERR_INVALID),
        };
        let private_groups = match args.get("private_groups") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(private_group_answer)
                .collect::<Result<_, &'static str>>()?,
            Some(_) => return Err(ERR_INVALID),
        };
        Ok(Self {
            budget: Budget::parse(args.get("budget"))?,
            package_files,
            private_groups,
        })
    }

    pub(crate) fn private_group(&self, owner_uid: u32, group_gid: u32) -> Option<bool> {
        self.private_groups
            .iter()
            .find(|(owner, group, _)| *owner == owner_uid && *group == group_gid)
            .map(|(_, _, private)| *private)
    }
}

fn private_group_answer(item: &Value) -> Result<(u32, u32, bool), &'static str> {
    let number = |key: &str| {
        item.get(key)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(ERR_INVALID)
    };
    let private = item
        .get("private")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    Ok((number("owner_uid")?, number("group_gid")?, private))
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
            let compared = compare(files()?, generation("generation")?, flag("inverse"), &ask);
            Ok(settle(compared.map(|()| Vec::new())))
        }
        "write" => {
            let change = args
                .get("change")
                .and_then(Value::as_object)
                .ok_or(ERR_INVALID)?;
            Ok(settle(write(change, generation("generation")?, &ask)))
        }
        "publish" => Ok(publish(files()?, flag("removals"), flag("rollback"), &ask)),
        _ => Err(ERR_INVALID),
    }
}

fn settle(step: Step<Vec<Value>>) -> Value {
    match step {
        Ok(events) => json!({ "ok": true, "events": events }),
        Err(Fault::PrivateGroup {
            owner_uid,
            group_gid,
        }) => json!({ "reply": { "private_group": {
            "owner_uid": owner_uid, "group_gid": group_gid,
        } } }),
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

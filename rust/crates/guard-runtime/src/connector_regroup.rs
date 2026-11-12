//! `connector_regroup` runner-authority kind: which pending connector setup
//! reviews the local CLI store migration moves to their connector group.
//!
//! A review held only because Guard did not recognise the local CLI it launches
//! is queued under `connector:<identity_hash>:<action digest>`, so the Inbox
//! shows one setup card per connector. Reviews queued before that grouping
//! existed sit under their per-action group, and the store's v14 migration asks
//! this kind which of them tie to one observed CLI with no decision yet.
//!
//! The tie is deliberately narrow. The stored command must be a plain
//! `program [argument ...]` of safe ASCII tokens (no quoting, expansion,
//! redirection or compound operators), the program's name must match exactly
//! one plain executable observation, and that CLI must not already be allowed
//! or blocked. A program written with a path must be that observation's own
//! recorded executable path, so two binaries that share a name are never
//! merged; a bare name carries no path to contradict. A review keeps its
//! workspace, not the directory the hook ran in, so a row without a workspace
//! keeps its group.
//!
//! Request, all rows positional:
//! - `reviews`: `[[request_id, command, queue_group_id, workspace], ...]`, the
//!   pending non-recognition reviews in queue order.
//! - `observations`: `[[cli_id, identity_hash, name, source_path], ...]`, the
//!   plain executable observations.
//! - `decided`: `[[cli_id, identity_hash], ...]`, the allowed or blocked grants.
//!
//! Answer: `{"moves": [[request_id, queue_group_id], ...]}` in review order,
//! only for reviews whose group changes.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::connector_setup::queue_group_id;
use crate::cursor_hook_command::py_space;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_COMMAND_CHARS: usize = 4096;
/// Runners launch another program, so their name is not the connector.
const RUNNERS: [&str; 6] = ["npx", "bunx", "pnpm", "pnpx", "yarn", "npm"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let reviews = rows(args, "reviews", 4)?;
    let observations = rows(args, "observations", 4)?;
    let decided = rows(args, "decided", 2)?;
    let mut identities: BTreeMap<(&str, Option<&str>), Option<&str>> = BTreeMap::new();
    let mut moves = Vec::new();
    for review in reviews {
        let (Some(command), Some(workspace)) = (review[1].as_str(), review[3].as_str()) else {
            continue;
        };
        if workspace.is_empty() {
            continue;
        }
        let Some(name) = program_name(command) else {
            continue;
        };
        let path = program_path(command);
        let identity = *identities
            .entry((name, path))
            .or_insert_with(|| undecided_identity(&observations, &decided, name, path));
        let Some(identity_hash) = identity else {
            continue;
        };
        let target = queue_group_id(identity_hash, workspace, command);
        if review[2].as_str() != Some(target.as_str()) {
            moves.push(json!([review[0], target]));
        }
    }
    Ok(json!({ "moves": moves }))
}

/// The `key` array of `width`-item rows; any other shape is refused.
fn rows<'a>(
    args: &'a Map<String, Value>,
    key: &str,
    width: usize,
) -> Result<Vec<&'a [Value]>, &'static str> {
    args.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|row| {
            row.as_array()
                .map(Vec::as_slice)
                .filter(|row| row.len() == width)
                .ok_or(ERR_INVALID)
        })
        .collect()
}

/// Python's `str.split()`.
fn tokens(command: &str) -> impl Iterator<Item = &str> + '_ {
    command.split(py_space).filter(|token| !token.is_empty())
}

/// `[A-Za-z0-9._/@:+=%,-]+`.
fn is_simple_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/@:+=%,-".contains(&byte))
}

/// The program a plain command launches, or `None` for any other shape.
fn program_name(command: &str) -> Option<&str> {
    if command.is_empty() || command.len() > MAX_COMMAND_CHARS || !command.is_ascii() {
        return None;
    }
    if !tokens(command).all(is_simple_token) {
        return None;
    }
    let program = tokens(command).next()?;
    if program.contains('=') || program.ends_with('/') {
        return None;
    }
    let name = program.rsplit('/').next().unwrap_or(program);
    (!name.is_empty() && !RUNNERS.contains(&name) && !name.starts_with('.')).then_some(name)
}

/// The program token when it is written with a path; `None` for a bare name.
fn program_path(command: &str) -> Option<&str> {
    tokens(command)
        .next()
        .filter(|program| program.contains('/'))
}

/// The identity hash of the one plain executable called `name`, while it has
/// no decision. A program written with a path ties only to the observation
/// recorded at that exact path; an observation without a path cannot vouch
/// for one.
fn undecided_identity<'a>(
    observations: &[&'a [Value]],
    decided: &[&[Value]],
    name: &str,
    path: Option<&str>,
) -> Option<&'a str> {
    let mut found = observations
        .iter()
        .filter(|row| row[2].as_str() == Some(name));
    let row = *found.next()?;
    if found.next().is_some() {
        return None;
    }
    let (cli_id, identity_hash) = (row[0].as_str()?, row[1].as_str()?);
    if path.is_some_and(|path| row[3].as_str() != Some(path)) {
        return None;
    }
    let decided = decided
        .iter()
        .any(|grant| grant[0].as_str() == Some(cli_id) && grant[1].as_str() == Some(identity_hash));
    (!decided).then_some(identity_hash)
}

#[cfg(test)]
#[path = "connector_regroup_tests.rs"]
mod tests;

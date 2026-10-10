//! Lazy fact context for the daemon lifecycle decisions.
//!
//! The resident never touches the process table, the filesystem or the Windows
//! command-line parser for these decisions. A decision asks the context for a
//! fact; a missing fact is recorded and answered with a neutral placeholder so
//! the decision keeps walking and every fact it needs is requested in one
//! round. The caller supplies the requested facts and repeats the request; a
//! result is only ever produced from a run that found every fact present.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::DaemonPlatformV1;
use serde_json::{json, Value};

use crate::daemon_lifecycle_text::{lexical_equal, norm_path, ntpath_basename, shlex_split};

/// The argument the frozen launcher uses to serve the daemon.
pub(crate) const FROZEN_DAEMON_SERVE_ARG: &str = "--_hol-guard-daemon-serve";
pub(crate) const LAUNCHER_NAMES: [&str; 4] = [
    "hol-guard",
    "hol-guard.exe",
    "plugin-guard",
    "plugin-guard.exe",
];

pub(crate) struct Ctx<'a> {
    pub(crate) nt: bool,
    facts: &'a BTreeMap<String, Value>,
    missing: RefCell<BTreeSet<String>>,
}

impl<'a> Ctx<'a> {
    pub(crate) fn new(platform: DaemonPlatformV1, facts: &'a BTreeMap<String, Value>) -> Self {
        Self {
            nt: platform == DaemonPlatformV1::Nt,
            facts,
            missing: RefCell::new(BTreeSet::new()),
        }
    }

    /// The supplied fact, or `None` after recording that it is needed.
    pub(crate) fn fact(&self, key: String) -> Option<&'a Value> {
        let found = self.facts.get(&key);
        if found.is_none() {
            self.missing.borrow_mut().insert(key);
        }
        found
    }

    pub(crate) fn boolean(&self, prefix: &str, pid: i64) -> bool {
        self.fact(format!("{prefix}:{pid}"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    /// Either the result of a complete run or the facts still required.
    pub(crate) fn finish(self, result: Value) -> Value {
        let missing = self.missing.into_inner();
        if missing.is_empty() {
            return result;
        }
        json!({"need": "facts", "keys": missing.into_iter().collect::<Vec<_>>()})
    }

    /// Python's `Path(value)` text on the host the facts were gathered on.
    pub(crate) fn path_text(&self, raw: &str) -> String {
        norm_path(raw)
    }

    /// `Path(path).resolve()` as supplied by the caller; `None` is a failure.
    pub(crate) fn resolve(&self, path: &str) -> Option<String> {
        let resolved = self.fact(format!("resolve:{}", norm_path(path)))?;
        resolved.as_str().map(str::to_owned)
    }

    /// `resolve() == resolve()` with the lexical fallback taken on failure.
    pub(crate) fn same_path(&self, left: &str, right: &str) -> bool {
        match (self.resolve(left), self.resolve(right)) {
            (Some(left), Some(right)) => lexical_equal(&left, &right, self.nt),
            _ => lexical_equal(left, right, self.nt),
        }
    }

    /// `_split_process_command`: `None` when the command line cannot be parsed.
    pub(crate) fn split_command(&self, command: &str) -> Option<Vec<String>> {
        if !self.nt {
            return shlex_split(command);
        }
        let argv = self.fact(format!("argv:{command}"))?.as_array()?;
        argv.iter()
            .map(|part| part.as_str().map(str::to_owned))
            .collect()
    }

    /// `_frozen_daemon_serve_context`: the guard home and port it names.
    pub(crate) fn frozen_context(&self, parts: &[String]) -> Option<(String, i64)> {
        if parts.len() != 3 || parts[1] != FROZEN_DAEMON_SERVE_ARG {
            return None;
        }
        if !is_launcher(&parts[0]) {
            return None;
        }
        let decoded = self.fact(format!("frozen:{}", parts[2]))?.as_object()?;
        let home = decoded.get("guard_home")?.as_str()?;
        let port = decoded.get("port")?.as_i64()?;
        Some((norm_path(home), port))
    }
}

pub(crate) fn is_launcher(command: &str) -> bool {
    let name = ntpath_basename(command).to_lowercase();
    LAUNCHER_NAMES.contains(&name.as_str())
}

/// `isinstance(value, int) and not bool` for a JSON value.
pub(crate) fn as_int(value: &Value) -> Option<i64> {
    value.as_i64()
}

/// `value == GUARD_DAEMON_COMPATIBILITY_VERSION` (`2 == 2.0` in Python).
pub(crate) fn is_compatible(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_f64)
        .is_some_and(|number| number == 2.0)
}

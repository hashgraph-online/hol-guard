//! What Python answers between Cursor ops: the facts about the attested
//! Guard CLI and the native hook bridge, the long form of 8.3 names, Windows
//! hook command lines, Guard's proxy relaunches and the managed servers.

use serde_json::{json, Map, Value};

use super::cursor::{get, malformed, runtime, BRIDGE_UNAVAILABLE};
use super::{Ctx, Failure, Step};
use crate::pyjson::{self, PyVal};
/// The Python interpreter the attested Guard CLI runs on.
pub(super) struct HookPython {
    pub(super) executable: String,
    pub(super) target: String,
    pub(super) import_roots: Vec<String>,
}

pub(super) struct Attestation {
    pub(super) command: Vec<String>,
    pub(super) identity: PyVal,
    pub(super) python: Option<HookPython>,
}

/// What the Guard process answered for `facts`.
pub(super) struct Facts {
    /// The native hook bridge, `None` under the suite's Python pin.
    pub(super) bridge: Option<String>,
    pub(super) pinned: bool,
    pub(super) attestation: Result<Attestation, String>,
    pub(super) interpreter: Option<String>,
    pub(super) frozen: bool,
    pub(super) frozen_launcher: Option<String>,
    pub(super) executable: String,
    pub(super) frozen_recovery: Option<Vec<String>>,
    pub(super) can_rebind: bool,
}

impl Facts {
    /// `require_cursor_hook_bridge`: refuse when nothing can answer the hooks.
    pub(super) fn require_bridge(&self) -> Step<()> {
        if self.bridge.is_none() && !self.pinned {
            return Err(runtime(BRIDGE_UNAVAILABLE));
        }
        Ok(())
    }

    pub(super) fn attestation(&self) -> Step<&Attestation> {
        self.attestation
            .as_ref()
            .map_err(|error| runtime(error.clone()))
    }
}

fn strings(value: Option<&PyVal>) -> Step<Vec<String>> {
    value
        .and_then(PyVal::as_list)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or(Failure::Invalid))
        .collect()
}

fn optional_text(value: Option<&PyVal>) -> Step<Option<String>> {
    match value {
        None | Some(PyVal::Null) => Ok(None),
        Some(PyVal::Str(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Failure::Invalid),
    }
}

fn attestation(value: Option<&PyVal>) -> Step<Result<Attestation, String>> {
    let entries = value.and_then(PyVal::as_dict).ok_or(Failure::Invalid)?;
    if let Some(error) = get(entries, "error") {
        return Ok(Err(error.as_str().ok_or(Failure::Invalid)?.to_owned()));
    }
    let python = match get(entries, "python") {
        None | Some(PyVal::Null) => None,
        Some(PyVal::Dict(python)) => Some(HookPython {
            executable: optional_text(get(python, "executable"))?.ok_or(Failure::Invalid)?,
            target: optional_text(get(python, "target"))?.ok_or(Failure::Invalid)?,
            import_roots: strings(get(python, "import_roots"))?,
        }),
        Some(_) => return Err(Failure::Invalid),
    };
    Ok(Ok(Attestation {
        command: strings(get(entries, "command"))?,
        identity: get(entries, "identity").cloned().ok_or(Failure::Invalid)?,
        python,
    }))
}

/// One op's request and the facts Python merged into it.
pub(super) struct Ask<'a> {
    pub(super) ctx: &'a Ctx,
    pub(super) fields: &'a Map<String, Value>,
}

impl Ask<'_> {
    pub(super) fn reply(key: &str, value: Value) -> Failure {
        Failure::Reply(json!({ key: value }))
    }

    pub(super) fn facts(&self) -> Step<Facts> {
        let Some(raw) = self.fields.get("facts") else {
            return Err(Self::reply("facts", Value::Null));
        };
        let raw = raw.as_str().ok_or(Failure::Invalid)?;
        let Ok(PyVal::Dict(facts)) = pyjson::parse(raw) else {
            return Err(Failure::Invalid);
        };
        let flag = |key: &str| match get(&facts, key) {
            None => Ok(false),
            Some(PyVal::Bool(value)) => Ok(*value),
            Some(_) => Err(Failure::Invalid),
        };
        let pinned = self.ctx.env("HOL_GUARD_CURSOR_HOOK_BRIDGE") == Some("python")
            && self.ctx.env("HOL_GUARD_TEST_MODE") == Some("1");
        let bridge = optional_text(get(&facts, "bridge"))?.filter(|_| !pinned);
        let frozen_recovery = match get(&facts, "frozen_recovery") {
            None | Some(PyVal::Null) => None,
            value => Some(strings(value)?),
        };
        Ok(Facts {
            bridge,
            pinned,
            attestation: attestation(get(&facts, "attestation"))?,
            interpreter: optional_text(get(&facts, "interpreter"))?,
            frozen: flag("frozen")?,
            frozen_launcher: optional_text(get(&facts, "frozen_launcher"))?,
            executable: optional_text(get(&facts, "executable"))?.ok_or(Failure::Invalid)?,
            frozen_recovery,
            can_rebind: flag("can_rebind")?,
        })
    }

    /// The long path Python resolved for each 8.3 name it was asked about.
    fn long_paths(&self) -> Step<Map<String, Value>> {
        match self.fields.get("long_paths") {
            None => Ok(Map::new()),
            Some(Value::Object(paths)) => Ok(paths.clone()),
            Some(_) => Err(Failure::Invalid),
        }
    }

    /// One `cursor_hook_config` request; an unseen short name is asked about.
    pub(super) fn hook_config(&self, op: &str, mut request: Map<String, Value>) -> Step<Value> {
        let asked = self.long_paths()?;
        let known: Map<String, Value> = asked
            .iter()
            .filter(|(token, long)| {
                long.as_str()
                    .is_some_and(|long| !long.is_empty() && long != *token)
            })
            .map(|(token, long)| (token.clone(), long.clone()))
            .collect();
        request.insert("op".into(), json!(op));
        request.insert("windows".into(), json!(self.ctx.windows));
        request.insert("long_paths".into(), Value::Object(known));
        let mut answer = crate::cursor_hook_config::dispatch(&Value::Object(request))
            .map_err(|error| runtime(format!("Cursor hook config request failed: {error}")))?;
        let tokens = answer
            .as_object_mut()
            .and_then(|answer| answer.remove("short_tokens"))
            .ok_or_else(malformed)?;
        let unseen: Vec<Value> = tokens
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .filter(|token| {
                token
                    .as_str()
                    .is_some_and(|token| !asked.contains_key(token))
            })
            .cloned()
            .collect();
        if !unseen.is_empty() {
            return Err(Self::reply("expand", json!(unseen)));
        }
        Ok(answer)
    }

    /// `render_hook_command` of each argv: POSIX quoting here, Windows by
    /// Python. A line Windows cannot carry fails only its own command.
    pub(super) fn render(&self, argvs: &[Vec<String>]) -> Step<Vec<Step<String>>> {
        if !self.ctx.windows {
            return Ok(argvs
                .iter()
                .map(|argv| Ok(crate::mcp_proxy_shlex::join(argv)))
                .collect());
        }
        let known = self
            .fields
            .get("rendered")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let lookup = |argv: &Vec<String>| {
            known
                .iter()
                .find(|pair| pair.get(0) == Some(&json!(argv)))
                .and_then(|pair| pair.get(1))
        };
        let missing: Vec<&Vec<String>> =
            argvs.iter().filter(|argv| lookup(argv).is_none()).collect();
        if !missing.is_empty() {
            return Err(Self::reply("render", json!(missing)));
        }
        argvs
            .iter()
            .map(|argv| {
                match lookup(argv) {
                Some(Value::String(line)) => Ok(Ok(line.clone())),
                Some(Value::Null) => Ok(Err(Failure::Refusal(
                    "Codex hook arguments cannot be empty or contain line breaks or NUL on Windows."
                        .into(),
                ))),
                _ => Err(Failure::Invalid),
            }
            })
            .collect()
    }

    /// Guard's MCP proxy launch `(command, args)` for each set of proxy args.
    pub(super) fn relaunch(&self, sets: &[Vec<String>]) -> Step<Vec<(String, Vec<String>)>> {
        if sets.is_empty() {
            return Ok(Vec::new());
        }
        let known = self
            .fields
            .get("relaunch")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let lookup = |args: &Vec<String>| {
            known
                .iter()
                .find(|pair| pair.get(0) == Some(&json!(args)))
                .and_then(|pair| pair.get(1))
        };
        let missing: Vec<&Vec<String>> =
            sets.iter().filter(|args| lookup(args).is_none()).collect();
        if !missing.is_empty() {
            return Err(Self::reply("relaunch", json!(missing)));
        }
        sets.iter()
            .map(|args| {
                let launch = lookup(args).ok_or(Failure::Invalid)?;
                let command = launch
                    .get(0)
                    .and_then(Value::as_str)
                    .ok_or(Failure::Invalid)?
                    .to_owned();
                let args = launch
                    .get(1)
                    .and_then(Value::as_array)
                    .ok_or(Failure::Invalid)?
                    .iter()
                    .map(|arg| arg.as_str().map(str::to_owned).ok_or(Failure::Invalid))
                    .collect::<Step<_>>()?;
                Ok((command, args))
            })
            .collect()
    }

    /// The detected servers Guard manages, as Python derived them from `detect`.
    pub(super) fn servers(&self, detected: &Value) -> Step<Value> {
        let answered = match self.fields.get("servers") {
            Some(Value::String(raw)) => {
                serde_json::from_str::<Value>(raw).map_err(|_| Failure::Invalid)?
            }
            Some(_) => return Err(Failure::Invalid),
            None => Value::Null,
        };
        if answered.get("detect") != Some(detected) {
            return Err(Self::reply("servers", detected.clone()));
        }
        Ok(answered)
    }
}

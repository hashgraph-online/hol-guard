//! What Python answers between Cursor ops: the facts about the attested
//! Guard CLI and the native hook bridge, the long form of 8.3 names, Windows
//! the 8.3 names of hook command paths, Guard's proxy relaunches and the managed servers.

use serde_json::{json, Map, Value};

use super::cursor::{get, malformed, runtime, BRIDGE_UNAVAILABLE};
use super::{caller, hook_render, proxy_launch, Ctx, Failure, Step};
use crate::pyjson::{self, PyVal};
const BRIDGE_FEATURE: &str = "cursor-hook-bridge-v1";

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
        let pinned = self.ctx.env("HOL_GUARD_CURSOR_HOOK_BRIDGE") == Some("python")
            && self.ctx.env("HOL_GUARD_TEST_MODE") == Some("1");
        let bridge = proxy_launch::bridge(self.ctx, BRIDGE_FEATURE, Some(&self.ctx.guard_home))?
            .filter(|_| !pinned);
        let frozen_recovery = match get(&facts, "frozen_recovery") {
            None | Some(PyVal::Null) => None,
            value => Some(strings(value)?),
        };
        Ok(Facts {
            bridge,
            pinned,
            attestation: attestation(get(&facts, "attestation"))?,
            interpreter: optional_text(get(&facts, "interpreter"))?,
            frozen: caller::frozen(self.ctx)?,
            frozen_launcher: caller::optional_frozen_launcher(self.ctx)?.map(str::to_owned),
            executable: caller::executable(self.ctx)?.to_owned(),
            frozen_recovery,
            can_rebind: caller::can_rebind(self.ctx)?,
        })
    }

    /// The long path the caller named for an 8.3 name; the rest this host expands.
    fn long_paths(&self) -> Step<Map<String, Value>> {
        match self.fields.get("long_paths") {
            None => Ok(Map::new()),
            Some(Value::Object(paths)) => Ok(paths.clone()),
            Some(_) => Err(Failure::Invalid),
        }
    }

    /// One `cursor_hook_config` request.
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
        // The runtime expanded every short name itself.
        answer
            .as_object_mut()
            .and_then(|answer| answer.remove("short_tokens"))
            .ok_or_else(malformed)?;
        Ok(answer)
    }

    /// `render_hook_command` of each argv. A Windows path's 8.3 name is looked
    /// up first; a line Windows cannot carry fails only its own
    /// command.
    pub(super) fn render(&self, argvs: &[Vec<String>]) -> Step<Vec<Step<String>>> {
        let names = hook_render::names_for(
            self.fields,
            argvs.iter().map(Vec::as_slice),
            self.ctx.windows,
        )?;
        Ok(argvs
            .iter()
            .map(|argv| hook_render::render(argv, self.ctx.windows, &names))
            .collect())
    }

    /// Guard's MCP proxy launch `(command, args)` for each set of proxy args:
    /// a relay launch unwrapped to its Python proxy argv, then launched again
    /// through Guard's launcher and the relay this runtime can serve.
    pub(super) fn relaunch(&self, sets: &[Vec<String>]) -> Step<Vec<(String, Vec<String>)>> {
        let launcher = caller::launcher(self.ctx)?;
        sets.iter()
            .map(|args| {
                let (_, python_args) = proxy_launch::python_launch(None, args);
                proxy_launch::relay_launch(self.ctx, launcher, &python_args)
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

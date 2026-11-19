//! What a Cursor op reads about the Guard process: the attested Guard CLI and
//! the native hook bridge, the long form of 8.3 names, the 8.3 names of hook
//! command paths, and Guard's proxy relaunches.

use serde_json::{json, Map, Value};

use super::cursor::{malformed, runtime, BRIDGE_UNAVAILABLE};
use super::{attested_cli, caller, hook_render, isolated_python, proxy_launch, Ctx, Failure, Step};
use crate::claude_hook_bridge_recovery::frozen_recovery_command;
const BRIDGE_FEATURE: &str = "cursor-hook-bridge-v1";

pub(super) use super::attested_cli::Attested as Attestation;

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

/// One op's request.
pub(super) struct Ask<'a> {
    pub(super) ctx: &'a Ctx,
    pub(super) fields: &'a Map<String, Value>,
    /// Whether the op only prepares an install, so an attestation probe runs
    /// in a directory the op owns (`disposable_guard_hook_probe`).
    pub(super) preparing: bool,
}

impl Ask<'_> {
    /// The attested Guard CLI, the isolated hook interpreter and the frozen
    /// recovery command (`_facts`), with the native hook bridge.
    pub(super) fn facts(&self) -> Step<Facts> {
        let ctx = self.ctx;
        let pinned = ctx.env("HOL_GUARD_CURSOR_HOOK_BRIDGE") == Some("python")
            && ctx.env("HOL_GUARD_TEST_MODE") == Some("1");
        let bridge =
            proxy_launch::bridge(ctx, BRIDGE_FEATURE, Some(&ctx.guard_home))?.filter(|_| !pinned);
        let attestation = attested_cli::attested(ctx, self.preparing)?;
        let frozen_recovery = match &attestation {
            Ok(attested) if attested.python.is_none() => {
                let launcher = caller::frozen_launcher(ctx)?;
                Some(
                    frozen_recovery_command(launcher, &ctx.guard_home, &ctx.home)
                        .ok_or(Failure::Invalid)?,
                )
            }
            _ => None,
        };
        Ok(Facts {
            bridge,
            pinned,
            attestation,
            interpreter: isolated_python::for_root(ctx.env("SYSTEMROOT")),
            frozen: caller::frozen(ctx)?,
            frozen_launcher: caller::optional_frozen_launcher(ctx)?.map(str::to_owned),
            executable: caller::executable(ctx)?.to_owned(),
            frozen_recovery,
            can_rebind: caller::can_rebind(ctx)?,
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
}

//! Codex: the verdict on the config and manifest a sealed authority receipt
//! retained, for the repair that restores a missing manifest.
//!
//! The transition files runtime loads the receipt; this parses the retained
//! config strictly, refuses one that disables hooks, authenticates the
//! retained manifest under the runtime's own key and verifies it against the
//! installation the caller expects, as `verify_manifest` does for a live one.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::codex_live_state::{hooks_wire, settled, spec_text, verified_state};
use super::codex_migration::read_toml;
use super::{Ctx, Failure, Step};
use crate::codex_hook_manifest_auth as manifest_auth;
use crate::codex_toml_read;
use crate::pyjson::PyVal;

/// What the retained generation says.
pub(crate) enum Verdict {
    /// The retained config turns Codex hooks off.
    HooksDisabled,
    /// The integrity state of the retained manifest against the installation.
    State(Map<String, Value>),
}

/// The verdict for `config_bytes` and `manifest_text`. Request fields:
/// `context`, `spec`, `config` (the resolved config path, for messages),
/// `package_roots`, and optionally `windows` and `long_paths`.
pub(crate) fn verify_captured(
    request: &Map<String, Value>,
    config_bytes: &[u8],
    manifest_text: &str,
) -> Step<Verdict> {
    let ctx = Ctx::parse(request.get("context")).map_err(|_| Failure::Invalid)?;
    let spec = request
        .get("spec")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let config = Path::new(
        request
            .get("config")
            .and_then(Value::as_str)
            .ok_or(Failure::Invalid)?,
    );
    let entries = read_toml(Some(config_bytes), config, "Codex config file")?;
    let (payload, tokens) = codex_toml_read::wire(&entries);
    let hooks_off = matches!(payload.get("features"), Some(features @ PyVal::Dict(_))
        if matches!(features.get("hooks"), Some(PyVal::Bool(false))));
    if hooks_off {
        return Ok(Verdict::HooksDisabled);
    }
    let hooks = payload.get("hooks").map(|hooks| hooks_wire(hooks, &tokens));
    let guard_home = ctx.absolute(Path::new(spec_text(spec, "guard_home")?));
    let home = guard_home.to_str().ok_or(Failure::Invalid)?;
    let loaded = settled(manifest_auth::authenticate_text(
        home,
        manifest_text,
        None,
        None,
    ));
    let mut fields = request.clone();
    fields
        .entry("windows")
        .or_insert_with(|| json!(ctx.windows));
    fields.entry("long_paths").or_insert_with(|| json!({}));
    let installed = PathBuf::from(spec_text(spec, "config_path")?);
    let state = verified_state(&ctx, spec, &installed, loaded, hooks.flatten(), &fields)?;
    Ok(Verdict::State(state))
}

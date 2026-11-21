//! Codex install and uninstall under the owner of the Guard home, as
//! `CodexHarnessAdapter.install` and `uninstall` ran them from Python.
//!
//! The owner holds the Guard home's locks; this adds the Codex configuration
//! directory's lifecycle lock (and, for an install, the hook key's), refuses a
//! pending runtime transition, recovers an interrupted hook publication, and
//! then runs the whole install in the runtime: the authenticated baseline,
//! the captured sources, the detection the managed servers come from, the
//! publication, and the manifest it reports.
//!
//! The caller's process supplies only what it alone knows, in the request's
//! `facts.codex`: `launch` (`home_is_current`, `runtime_guard_home`,
//! `workspace_explicit`, `long_timeout`), and `package_root`.
//! `held_dirs` names the configuration directories
//! its process already holds, each `{identity, lease}`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::codex_detection::{self, Detection};
use super::codex_prepare::plan_fields;
use crate::harness_adapter::codex_install::transition;
use crate::harness_adapter::codex_spec::{self, spelled};
use crate::harness_adapter::managed_install_target::{stopped, Owned, INVALID};
use crate::harness_adapter::paseo_paths::abspath;
use crate::harness_adapter::{path_text, Ctx, Spec};
use crate::transition_files::{
    recover_publication, resolve_lenient, within_config_scope, Budget, HeldDirectory, OwnedFailure,
    Owner,
};

use super::{config_path, dispatch, paths, HOOK_UNAVAILABLE};

/// How long the configuration directory's lock may stay busy.
const SCOPE_WAIT: Duration = Duration::from_secs(5);

const KEY_UNAVAILABLE: &str =
    "Guard's native runtime did not answer for the Codex hook key; run `hol-guard repair`.";
const KEY_MISSING: &str =
    "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it.";
const KEY_UNUSABLE: &str =
    "The private Codex hook authentication key is not usable; repair the Codex installation.";
const SHELL_HOOK_UNAVAILABLE: &str = "Guard refused to launch Codex because the managed PreToolUse and \
PermissionRequest hooks are missing or disabled. Run `hol-guard install codex` or `hol-guard update` \
to repair the native-hook enforcement boundary.";

/// What the request carries for Codex.
pub(super) struct Facts<'a> {
    pub(super) codex: &'a Map<String, Value>,
    pub(super) launch: Map<String, Value>,
    /// `package_roots` and `budget`, as every transition op takes them.
    pub(super) transition: Map<String, Value>,
    held: Vec<HeldDirectory>,
    budget: Budget,
    /// When the budgets were read: a step sees what is left of them, not a fresh grant.
    started: Instant,
}

impl Facts<'_> {
    /// The transition fields for the next step, with each budget reduced by
    /// the time this request has already spent.
    pub(super) fn transition_now(&self) -> Map<String, Value> {
        let spent = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut fields = self.transition.clone();
        if let Some(Value::Object(budget)) = fields.get_mut("budget") {
            for value in budget.values_mut() {
                if let Some(millis) = value.as_u64() {
                    *value = json!(millis.saturating_sub(spent));
                }
            }
        }
        fields
    }
}

pub(super) fn facts<'a>(ctx: &Ctx, request: &'a Map<String, Value>) -> Owned<Facts<'a>> {
    let codex = request
        .get("facts")
        .and_then(Value::as_object)
        .and_then(|facts| facts.get("codex"))
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let mut launch = codex
        .get("launch")
        .and_then(Value::as_object)
        .ok_or(INVALID)?
        .clone();
    let runtime_home = launch
        .get("runtime_guard_home")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let manifest = crate::codex_hook_paths_op::manifest_path(
        Path::new(runtime_home),
        &abspath(ctx, &config_path(ctx)),
    );
    launch.insert("manifest_path".into(), json!(path_text(&manifest)));
    let sent = request
        .get("transition")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let mut transition = Map::new();
    for key in ["package_roots", "budget"] {
        if let Some(value) = sent.get(key) {
            transition.insert(key.into(), value.clone());
        }
    }
    Ok(Facts {
        codex,
        launch,
        held: HeldDirectory::parse(request.get("held_dirs")).ok_or(INVALID)?,
        budget: Budget::parse(sent.get("budget")).map_err(|_| INVALID)?,
        transition,
        started: Instant::now(),
    })
}

fn fault(value: Value) -> OwnedFailure {
    OwnedFailure::Fault(value)
}

/// One transition op on the caller's home: its value.
fn ask(facts: &Facts<'_>, request: Map<String, Value>) -> Owned<Value> {
    transition(&facts.transition_now(), request, &mut Vec::new()).map_err(fault)
}

fn op_request(op: &str, fields: &[(&str, Value)]) -> Map<String, Value> {
    let mut request = Map::new();
    request.insert("op".into(), json!(op));
    for (key, value) in fields {
        request.insert((*key).to_owned(), value.clone());
    }
    request
}

/// The spec the publication expects, with whether a workspace may rebind.
pub(super) fn spec_of(ctx: &Ctx, facts: &Facts<'_>) -> Owned<Value> {
    let mut spec = codex_spec::build(ctx, &facts.launch, &Map::new()).map_err(stopped)?;
    let rebinding = facts
        .launch
        .get("workspace_explicit")
        .and_then(Value::as_bool)
        != Some(true);
    spec["workspace_rebinding_allowed"] = json!(rebinding);
    Ok(spec)
}

/// `load_hook_manifest_baseline`: the prior authenticated manifest, `None`
/// for a clean install.
pub(super) fn baseline(ctx: &Ctx, facts: &Facts<'_>, spec: &Value) -> Owned<Option<Value>> {
    let home = path_text(&abspath(ctx, Path::new(&spelled(ctx, &ctx.guard_home))));
    let value = ask(
        facts,
        op_request(
            "publication_baseline",
            &[("home", json!(home)), ("spec", spec.clone())],
        ),
    )?;
    if let Some(untrusted) = value.get("untrusted") {
        for key in ["reason", "message"] {
            untrusted.get(key).and_then(Value::as_str).ok_or(INVALID)?;
        }
        return Err(OwnedFailure::Untrusted(untrusted.clone()));
    }
    match value.get("manifest") {
        Some(Value::Null) => Ok(None),
        Some(manifest @ Value::Object(_)) => Ok(Some(manifest.clone())),
        _ => Err(INVALID),
    }
}

/// The `events` bindings of a manifest, as `manifest_bindings` reads them.
pub(super) fn bindings(manifest: Option<&Value>) -> Vec<Value> {
    manifest
        .and_then(|manifest| manifest.get("events"))
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter(|event| event.is_object())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn pairs(ctx: &Ctx) -> Vec<(String, String)> {
    paths(ctx)["pairs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| {
            Some((
                pair["config"].as_str()?.to_owned(),
                pair["hooks"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// `_snapshot` of every config and hooks file, in pair order.
pub(super) fn capture(
    ctx: &Ctx,
    facts: &Facts<'_>,
    pairs: &[(String, String)],
) -> Owned<Map<String, Value>> {
    let mut contents = Map::new();
    for path in pairs.iter().flat_map(|(config, hooks)| [config, hooks]) {
        if contents.contains_key(path) {
            continue;
        }
        let target = path_text(&abspath(ctx, Path::new(&spelled(ctx, Path::new(path)))));
        let value = ask(
            facts,
            op_request(
                "publication_snapshot",
                &[("home", json!(target)), ("path", json!(target))],
            ),
        )?;
        contents.insert(path.clone(), value);
    }
    Ok(contents)
}

pub(super) fn manifest_text(
    spec: &Spec,
    ctx: &Ctx,
    kind: &str,
    shim: &Value,
    explicit: bool,
    extra: &[(&str, Value)],
) -> Owned<String> {
    let located = paths(ctx);
    let mut fields = Map::new();
    fields.insert("kind".into(), json!(kind));
    fields.insert("shim".into(), shim.clone());
    fields.insert("config_path".into(), located["config"].clone());
    fields.insert("hook_config_path".into(), located["config"].clone());
    fields.insert("workspace_explicit".into(), json!(explicit));
    fields.insert("hooks_path".into(), located["hooks"].clone());
    for (key, value) in extra {
        fields.insert((*key).to_owned(), value.clone());
    }
    let answer = dispatch(spec, "manifest", ctx, &fields).map_err(stopped)?;
    answer
        .get("manifest")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(INVALID)
}

/// `_raise_publication_error`: the failure an answer names in `raise`. A
/// rollback that failed beside it, and the cause of a retirement that left
/// the sources unrestored, travel in the fault for the caller to chain.
pub(super) fn raised(answer: &Value) -> Option<OwnedFailure> {
    let raise = answer.get("raise")?.as_object()?;
    if let Some(runtime) = raise.get("runtime").and_then(Value::as_str) {
        let cause = raise.get("cause").cloned().unwrap_or(Value::Null);
        return Some(fault(json!({ "runtime": runtime, "cause": cause })));
    }
    let failure = raise.get("fault")?.clone();
    match raise.get("rollback").filter(|rollback| !rollback.is_null()) {
        None => Some(fault(failure)),
        Some(rollback) => Some(fault(
            json!({ "rollback": { "failure": failure, "rollback": rollback } }),
        )),
    }
}

fn key_refusal(reason: &str) -> OwnedFailure {
    match reason {
        "runtime_unavailable" | "invalid" => OwnedFailure::Integrity(
            "codex_hook_manifest_verification_unavailable".to_owned(),
            KEY_UNAVAILABLE.to_owned(),
        ),
        "codex_hook_manifest_secret_missing" => {
            OwnedFailure::Integrity(reason.to_owned(), KEY_MISSING.to_owned())
        }
        _ => OwnedFailure::Integrity(reason.to_owned(), KEY_UNUSABLE.to_owned()),
    }
}

pub(super) fn text(value: &Value, key: &str) -> Owned<Value> {
    match value.get(key) {
        Some(found @ Value::String(_)) => Ok(found.clone()),
        _ => Err(INVALID),
    }
}

/// `_require_codex_authoritative_shell_hook`.
fn require_shell_hook(spec: &Spec, ctx: &Ctx, facts: &Facts<'_>) -> Owned<()> {
    let mut fields = Map::new();
    fields.insert("launch".into(), Value::Object(facts.launch.clone()));
    for (key, value) in &facts.transition_now() {
        if key == "package_roots" {
            fields.insert(key.clone(), value.clone());
        }
    }
    fields.insert("budget_spent".into(), json!(false));
    let answer = dispatch(spec, "live_hook_state", ctx, &fields).map_err(stopped)?;
    let state: Value = answer
        .get("state")
        .and_then(Value::as_str)
        .and_then(|state| serde_json::from_str(state).ok())
        .ok_or(INVALID)?;
    if state
        .get("shell_protection_active")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Ok(());
    }
    Err(OwnedFailure::Runtime(format!(
        "{HOOK_UNAVAILABLE}: {SHELL_HOOK_UNAVAILABLE}"
    )))
}

fn config_dir(ctx: &Ctx) -> PathBuf {
    abspath(ctx, &config_path(ctx))
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf)
}

fn install_owned(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    facts: &Facts<'_>,
    owner: &mut Owner,
) -> Owned<String> {
    let spec_value = spec_of(ctx, facts)?;
    let pairs = pairs(ctx);
    // A source that is not a readable regular file refuses before the journal opens.
    let mut asked = Map::new();
    asked.insert(
        "pairs".into(),
        json!(pairs
            .iter()
            .map(|(config, hooks)| [config, hooks])
            .collect::<Vec<_>>()),
    );
    dispatch(spec, "check_sources", ctx, &asked).map_err(stopped)?;
    let previous = baseline(ctx, facts, &spec_value)?;
    let owned = bindings(previous.as_ref());
    let contents = capture(ctx, facts, &pairs)?;
    let Detection {
        artifacts,
        found_paths,
        warnings: _,
        sourced: _,
    } = codex_detection::detect(ctx, &facts.launch, &owned, Some(&contents)).map_err(stopped)?;
    let mut fields = plan_fields(
        request, facts, &previous, &owned, contents, &artifacts, true,
    )?;
    fields.insert("operation_id".into(), json!(owner.operation_id()));
    let answer = dispatch(spec, "install", ctx, &fields).map_err(stopped)?;
    owner.record_events(&answer);
    if let Some(failure) = raised(&answer) {
        return Err(failure);
    }
    let plan = answer.get("plan").ok_or(INVALID)?;
    let state: Value = answer
        .get("state")
        .and_then(Value::as_str)
        .and_then(|state| serde_json::from_str(state).ok())
        .filter(Value::is_object)
        .ok_or(INVALID)?;
    require_shell_hook(spec, ctx, facts)?;
    let list = |key: &str| plan.get(key).cloned().ok_or(INVALID);
    let explicit = facts
        .launch
        .get("workspace_explicit")
        .and_then(Value::as_bool)
        == Some(true);
    manifest_text(
        spec,
        ctx,
        "install",
        &text(plan, "shim_manifest")?,
        explicit,
        &[
            ("manifest_path", text(&state, "manifest_path")?),
            ("integrity", text(&state, "integrity_status")?),
            ("backup_path", text(plan, "backup_path")?),
            ("managed", list("managed_servers")?),
            ("migrated", list("migrated")?),
            ("skipped", list("skipped_servers")?),
            ("source_config_paths", json!(found_paths)),
        ],
    )
}

/// `CodexHarnessAdapter.install`: the manifest text of the installed Codex.
pub(in crate::harness_adapter) fn install(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
) -> Owned<String> {
    let facts = facts(ctx, request)?;
    let key_dir = crate::codex_hook_paths_op::key_path(&ctx.guard_home)
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    let config = config_dir(ctx);
    within_config_scope(
        owner,
        &facts.budget,
        &[config.as_path(), key_dir.as_path()],
        &facts.held,
        SCOPE_WAIT,
        |owner| {
            // Recovery runs under the configuration locks, so no other
            // lifecycle call can edit the config it inspects.
            recover_publication(owner, &facts.budget)?;
            install_owned(spec, ctx, request, &facts, owner)
        },
    )
}

fn uninstall_owned(spec: &Spec, ctx: &Ctx, facts: &Facts<'_>, owner: &mut Owner) -> Owned<String> {
    let spec_value = spec_of(ctx, facts)?;
    let owned = bindings(baseline(ctx, facts, &spec_value)?.as_ref());
    let config = abspath(ctx, &config_path(ctx));
    let home = crate::codex_hook_paths_op::manifest_path(&ctx.guard_home, &config);
    let receipt = crate::codex_hook_paths_op::receipt_path(&ctx.guard_home, &config);
    let located = |path: &Path| -> String {
        let name = path.file_name().map(Path::new).unwrap_or(path);
        let parent = path.parent().map_or_else(PathBuf::new, resolve_lenient);
        path_text(&parent.join(name))
    };
    let mut fields = facts.transition_now();
    fields.insert(
        "owned".into(),
        json!(serde_json::to_string(&owned).map_err(|_| INVALID)?),
    );
    fields.insert(
        "authority_files".into(),
        json!([located(&receipt), located(&home)]),
    );
    fields.insert(
        "home".into(),
        json!(path_text(&abspath(ctx, &ctx.guard_home))),
    );
    fields.insert("launch".into(), Value::Object(facts.launch.clone()));
    fields.insert(
        "package_root".into(),
        facts.codex.get("package_root").cloned().ok_or(INVALID)?,
    );
    let answer = dispatch(spec, "uninstall", ctx, &fields).map_err(stopped)?;
    owner.record_events(&answer);
    if let Some(failure) = raised(&answer) {
        return Err(failure);
    }
    if let Some(reason) = answer.get("key_error") {
        return Err(key_refusal(reason.as_str().unwrap_or_default()));
    }
    let located_paths = paths(ctx);
    let explicit = facts
        .launch
        .get("workspace_explicit")
        .and_then(Value::as_bool)
        == Some(true);
    manifest_text(
        spec,
        ctx,
        "uninstall",
        &text(&answer, "manifest")?,
        explicit,
        &[("backup_path", located_paths["backup"].clone())],
    )
}

/// `CodexHarnessAdapter.uninstall`: the manifest text of the removed Codex.
pub(in crate::harness_adapter) fn uninstall(
    spec: &Spec,
    ctx: &Ctx,
    request: &Map<String, Value>,
    owner: &mut Owner,
) -> Owned<String> {
    let facts = facts(ctx, request)?;
    let config = config_dir(ctx);
    within_config_scope(
        owner,
        &facts.budget,
        &[config.as_path()],
        &facts.held,
        SCOPE_WAIT,
        |owner| {
            recover_publication(owner, &facts.budget)?;
            uninstall_owned(spec, ctx, &facts, owner)
        },
    )
}

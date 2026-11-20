//! Codex: a whole install as one plan (`CodexHarnessAdapter._prepare_plan`):
//! the main config's plan, managed MCP servers, the hook generation, each
//! alternate config, shell cleanup, launchers and a pin per packaged file.
//! Every file must still hold what the caller captured; no path is planned
//! twice (a file named by two roles becomes one pin, stronger contract).
//! Request fields: `pairs` (`[[config, hooks], ...]`, the main pair first),
//! `contents` (`{path: base64 | null}` the caller captured for every path in
//! `pairs`), the owner fields `main_plan` reads, `owned` and `managed`,
//! `require_owners`, `artifacts` (the detection's artifacts, private MCP
//! metadata included), `relaunch` once the caller answered it,
//! `generation` (the `publication_generation` request without its rendered
//! config), `package_roots`, `budget` and `interpreter` (the launcher's).
//!
//! Answer: `{"files" (led by authority, manifest, receipt and config),
//! "rendered_config", "backups", "shim_manifest",
//! "backup_path", "migrated", "managed_servers", "skipped_servers", "events"}`, `{"conflict": true}` when a file
//! changed after the caller read it, `{"fault": ..., "events"}` for a
//! transition fault, or a `reply` the caller answers before asking again.

use serde_json::{json, Map, Value};

use super::codex::compact;
use super::codex_alternate_plan::alternate_plan;
use super::codex_files::shell_cleanup;
use super::codex_main_plan::main_plan;
use super::codex_migration::{read_toml, render};
use super::codex_servers::managed_mcp;
use super::guard_shim;
use super::managed_servers;
use super::{Ctx, Failure, Step};
use crate::codex_toml_read;

const INVALID: &str = "native_transition_invalid";
const CONFLICT: &str = "adapter_preparation_generation_conflict";
/// The proxy subcommand each managed Codex server launches through.
const PROXY: &str = "codex-mcp-proxy";

/// Why a plan stopped short of an answer.
enum Stop {
    /// A file changed after the caller read it.
    Conflict,
    /// A transition fault the runtime sent.
    Fault(Value),
    /// A failure the adapter answers as it does for any op.
    Failed(Failure),
}

impl From<Failure> for Stop {
    fn from(failure: Failure) -> Self {
        Stop::Failed(failure)
    }
}

type Planned<T> = Result<T, Stop>;

fn fault(reason: &str) -> Stop {
    Stop::Fault(json!({ "transition": reason }))
}

/// The transition ops this plan asks on the caller's home, with the journal
/// records they return.
struct Transitions<'a> {
    fields: &'a Map<String, Value>,
    events: Vec<Value>,
}

impl Transitions<'_> {
    fn ask(&mut self, op: &str, mut request: Map<String, Value>) -> Planned<Value> {
        request.insert("op".into(), json!(op));
        for key in ["package_roots", "budget"] {
            if let Some(value) = self.fields.get(key) {
                request.insert(key.into(), value.clone());
            }
        }
        let answer = crate::transition_files::dispatch(&Value::Object(request))
            .map_err(|_| fault(INVALID))?;
        if let Some(events) = answer.get("events").and_then(Value::as_array) {
            self.events.extend(events.iter().cloned());
        }
        if let Some(error) = answer.get("restore_error").or_else(|| answer.get("error")) {
            return Err(Stop::Fault(error.clone()));
        }
        if answer.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(fault(INVALID));
        }
        Ok(answer.get("value").cloned().unwrap_or(Value::Null))
    }

    /// `RuntimeTransition._compare(files, "before")`.
    fn compare(&mut self, files: &[Value]) -> Planned<()> {
        let mut request = Map::new();
        request.insert("files".into(), json!(files));
        request.insert("generation".into(), json!("before"));
        request.insert("inverse".into(), json!(false));
        self.ask("compare", request).map(drop)
    }
}

fn files_of(answer: &Value) -> Planned<Vec<Value>> {
    if answer.get("conflict").and_then(Value::as_bool) == Some(true) {
        return Err(Stop::Conflict);
    }
    answer
        .get("files")
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|change| Ok(wire_file(change)?))
        .collect()
}

/// A prepared change as `planned_files` builds its `TransitionFile`: the
/// five recorded fields, a binding kind, and `no_follow` as planned.
pub(super) fn wire_file(change: &Value) -> Step<Value> {
    let change = change.as_object().ok_or(Failure::Invalid)?;
    let mut file = Map::new();
    for key in ["path", "before", "after", "before_mode", "after_mode"] {
        file.insert(
            key.into(),
            change.get(key).cloned().ok_or(Failure::Invalid)?,
        );
    }
    // `TransitionFile.__post_init__`: an existing user file that changes keeps
    // its mode minus the group/world write bits Guard never publishes.
    let changed = file["before"] != file["after"] || file["before_mode"] != file["after_mode"];
    if cfg!(unix) && !file["before"].is_null() && changed {
        if let Some(mode) = file["after_mode"]
            .as_u64()
            .filter(|mode| *mode & !0o777 == 0)
        {
            file.insert("after_mode".into(), json!(mode & !0o022));
        }
    }
    file.insert("kind".into(), json!("binding"));
    file.insert(
        "no_follow".into(),
        json!(change
            .get("no_follow")
            .and_then(Value::as_bool)
            .unwrap_or(false)),
    );
    Ok(Value::Object(file))
}

/// One captured pair: its request fields over the shared owner fields.
fn pair_request(
    fields: &Map<String, Value>,
    contents: &Map<String, Value>,
    config: &str,
    hooks: &str,
) -> Step<Map<String, Value>> {
    let mut request = fields.clone();
    for (key, path) in [("config", config), ("hooks", hooks)] {
        request.insert(key.into(), json!(path));
        let captured = contents.get(path).ok_or(Failure::Invalid)?;
        request.insert(format!("before_{key}"), captured.clone());
    }
    Ok(request)
}

/// The workspace config's payload, which shadows a managed server of the
/// same name; `null` without a workspace.
fn workspace_payload(fields: &Map<String, Value>, contents: &Map<String, Value>) -> Step<Value> {
    let path = match fields.get("workspace_config") {
        Some(Value::String(path)) => path,
        Some(Value::Null) => return Ok(Value::Null),
        _ => return Err(Failure::Invalid),
    };
    let data = super::codex_alternate_plan::decoded(contents.get(path.as_str()))?;
    let entries = read_toml(
        data.as_deref(),
        std::path::Path::new(path),
        "Codex config file",
    )?;
    let (payload, _) = codex_toml_read::wire(&entries);
    Ok(json!(compact(&payload, false)))
}

/// A pin on one packaged file, as `TransitionFile.artifact_dependency` makes
/// it without comparing.
fn artifact_dependency(identity: &Value, invocation: Option<&Value>) -> Planned<Value> {
    let path = identity.get("path").and_then(Value::as_str);
    let mode = identity.get("mode").and_then(Value::as_u64);
    let digest = identity.get("sha256").and_then(Value::as_str);
    let (Some(path), Some(mode), Some(digest)) = (path, mode, digest) else {
        return Err(fault("artifact_dependency_invalid"));
    };
    let mut change = json!({
        "path": path,
        "before": null,
        "after": null,
        "before_mode": mode,
        "after_mode": mode,
        "kind": "binding",
        "no_follow": true,
        "expected_digest": digest,
        "artifact_identity": {
            "size": identity.get("size").cloned().unwrap_or(Value::Null),
            "owner_uid": identity.get("owner_uid").cloned().unwrap_or(Value::Null),
            "role": identity.get("role").cloned().unwrap_or(Value::Null),
        },
    });
    if let Some(invocation) = invocation {
        let field = |key: &str| invocation.get(key).cloned().unwrap_or(Value::Null);
        change["invocation_identity"] = json!({
            "path": field("invocation_path"),
            "mode": field("invocation_mode"),
            "owner_uid": field("invocation_owner_uid"),
            "link_target": field("link_target"),
        });
    }
    Ok(change)
}

/// The generation's pins: each packaged file, then the interpreter's target
/// with the invocation that reaches it.
fn dependencies(manifest: &Value) -> Planned<Vec<Value>> {
    let identities = manifest.get("packaged_files").and_then(Value::as_array);
    let interpreter = manifest
        .get("interpreter")
        .filter(|value| value.is_object());
    let (Some(identities), Some(interpreter)) = (identities, interpreter) else {
        return Err(fault(CONFLICT));
    };
    let mut pins = Vec::new();
    for identity in identities {
        if identity.get("path").and_then(Value::as_str).is_none() {
            return Err(fault(CONFLICT));
        }
        pins.push(artifact_dependency(identity, None)?);
    }
    let target = interpreter
        .get("target")
        .filter(|value| value.is_object())
        .ok_or_else(|| fault(CONFLICT))?;
    pins.push(artifact_dependency(target, Some(interpreter))?);
    Ok(pins)
}

/// The authenticated generation for `rendered`: the four captured changes
/// (config, manifest, authority, receipt) with their prior bytes, and the
/// signed manifest.
fn generation(transitions: &mut Transitions<'_>, rendered: &str) -> Planned<(Vec<Value>, Value)> {
    let mut request = transitions
        .fields
        .get("generation")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?
        .clone();
    request.insert("rendered_config".into(), json!(rendered));
    let answer = transitions.ask("publication_generation", request.clone())?;
    let mut changes = match answer.get("files").and_then(Value::as_array) {
        Some(changes) if changes.len() == 4 => changes.clone(),
        _ => return Err(fault(INVALID)),
    };
    // The prior bytes come in a second answer, which keeps each under the
    // resident's response cap; the runtime refuses any that changed since.
    let named: Vec<usize> = (0..changes.len())
        .filter(|index| changes[*index].get("before_sha256").is_some())
        .collect();
    let wanted: Vec<Value> = named
        .iter()
        .map(|index| {
            let change = &changes[*index];
            json!({ "path": change.get("path"), "sha256": change.get("before_sha256") })
        })
        .collect();
    let mut before = Map::new();
    before.insert(
        "home".into(),
        request.get("home").cloned().unwrap_or(Value::Null),
    );
    before.insert("files".into(), json!(wanted));
    let prior = transitions.ask("publication_generation_before", before)?;
    let befores = match prior.get("before").and_then(Value::as_array) {
        Some(befores) if befores.len() == named.len() => befores.clone(),
        _ => return Err(fault(INVALID)),
    };
    for (index, before) in named.into_iter().zip(befores) {
        changes[index]["before"] = before;
    }
    let mut files = Vec::new();
    for change in &changes {
        let object = change.as_object().ok_or_else(|| fault(INVALID))?;
        let mut file = object.clone();
        file.remove("before_sha256");
        file.insert("no_follow".into(), json!(true));
        file.entry("kind").or_insert_with(|| json!("binding"));
        file.entry("expected_digest").or_insert(Value::Null);
        if file.get("expected_digest") == Some(&Value::Null) {
            file.remove("expected_digest");
        }
        files.push(Value::Object(file));
    }
    let manifest_bytes = super::codex_alternate_plan::decoded(files[1].get("after"))?;
    let manifest: Value = manifest_bytes
        .as_deref()
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .filter(Value::is_object)
        .ok_or_else(|| fault(INVALID))?;
    Ok((files, manifest))
}

/// One planned file per path; a packaged file two roles name is one pin.
fn unique(transitions: &mut Transitions<'_>, files: Vec<Value>) -> Planned<Vec<Value>> {
    let mut merged: Vec<Value> = Vec::new();
    for change in files {
        let path = change.get("path").cloned();
        let Some(index) = merged
            .iter()
            .position(|kept| kept.get("path").cloned() == path)
        else {
            merged.push(change);
            continue;
        };
        let mut request = Map::new();
        request.insert("previous".into(), merged[index].clone());
        request.insert("change".into(), change);
        let value = transitions.ask("publication_merge_dependency", request)?;
        if value.get("same").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let artifact = value
            .get("artifact_identity")
            .filter(|value| value.is_object());
        let invocation = value
            .get("invocation_identity")
            .cloned()
            .unwrap_or(Value::Null);
        let (Some(artifact), true) = (artifact, invocation.is_null() || invocation.is_object())
        else {
            return Err(fault(INVALID));
        };
        merged[index]["artifact_identity"] = artifact.clone();
        if invocation.is_null() {
            if let Some(kept) = merged[index].as_object_mut() {
                kept.remove("invocation_identity");
            }
        } else {
            merged[index]["invocation_identity"] = invocation;
        }
    }
    Ok(merged)
}

fn pairs(fields: &Map<String, Value>) -> Step<Vec<(String, String)>> {
    let Some(Value::Array(items)) = fields.get("pairs") else {
        return Err(Failure::Invalid);
    };
    items
        .iter()
        .map(|item| match item.as_array().map(Vec::as_slice) {
            Some([Value::String(config), Value::String(hooks)]) => {
                Ok((config.clone(), hooks.clone()))
            }
            _ => Err(Failure::Invalid),
        })
        .collect()
}

/// The planned files other than the pins compared before them, unchanged.
fn not_yet_compared(files: &[Value], pins: &[Value]) -> Vec<Value> {
    files
        .iter()
        .filter(|change| !pins.contains(change))
        .cloned()
        .collect()
}

fn plan(ctx: &Ctx, transitions: &mut Transitions<'_>) -> Planned<Value> {
    let fields = transitions.fields;
    let pairs = pairs(fields)?;
    let contents = fields
        .get("contents")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    let (servers, managed_names, skipped) = managed_servers::wired(ctx, fields, PROXY)?;
    let ((main_config, main_hooks), alternates) = pairs.split_first().ok_or(Failure::Invalid)?;

    let main = main_plan(
        ctx,
        &pair_request(fields, contents, main_config, main_hooks)?,
    )?;
    if main.get("conflict").and_then(Value::as_bool) == Some(true) {
        return Err(Stop::Conflict);
    }
    let backup = wire_file(main.get("backup").ok_or(Failure::Invalid)?)?;
    let migration = files_of(&main)?;
    let tokens = main.get("tokens").cloned().ok_or(Failure::Invalid)?;

    let mut mcp = Map::new();
    mcp.insert(
        "payload".into(),
        main.get("config").cloned().ok_or(Failure::Invalid)?,
    );
    mcp.insert(
        "workspace_payload".into(),
        workspace_payload(fields, contents)?,
    );
    let wired: Vec<Value> = servers
        .iter()
        .map(|server| {
            json!({
                "name": server.get("name"),
                "source_scope": server.get("source_scope"),
                "entry": server.get("entry"),
            })
        })
        .collect();
    mcp.insert("servers".into(), json!(wired));
    let managed = managed_mcp(ctx, &mcp)?;
    let migrated = managed.get("migrated").cloned().ok_or(Failure::Invalid)?;

    // Every alternate config is planned before the generation, so a reply
    // asked here never repeats a generation that may enroll the hook key.
    let mut alternate_files = Vec::new();
    let mut backups = vec![backup.get("path").cloned().ok_or(Failure::Invalid)?];
    backups.extend(
        migration
            .iter()
            .skip(1)
            .filter_map(|change| change.get("path").cloned()),
    );
    for (config, hooks) in alternates {
        let names: Vec<&Value> = servers
            .iter()
            .filter(|server| server.get("config_path").and_then(Value::as_str) == Some(config))
            .filter_map(|server| server.get("name"))
            .collect();
        let mut request = pair_request(fields, contents, config, hooks)?;
        request.insert("managed_server_names".into(), json!(names));
        let planned = files_of(&alternate_plan(ctx, &request)?)?;
        backups.extend(
            planned
                .iter()
                .skip(2)
                .filter_map(|change| change.get("path").cloned()),
        );
        alternate_files.extend(planned);
    }
    let cleanup = files_of(&shell_cleanup(ctx)?)?;
    let mut shim_request = Map::new();
    shim_request.insert("harness".into(), json!("codex"));
    shim_request.insert(
        "interpreter".into(),
        fields.get("interpreter").cloned().ok_or(Failure::Invalid)?,
    );
    let shim = guard_shim::prepare(ctx, &shim_request)?;
    let shim_files = files_of(&shim)?;

    let original = super::codex_alternate_plan::decoded(contents.get(main_config.as_str()))?;
    let tokens = tokens.as_object().ok_or(Failure::Invalid)?;
    let rendered = managed
        .get("rendered")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let rendered = render(rendered, tokens, original.as_deref())?;
    let (publication, manifest) = generation(transitions, &rendered)?;
    if publication[0].get("before") != contents.get(main_config.as_str()) {
        return Err(Stop::Conflict);
    }
    let mut pins = dependencies(&manifest)?;
    super::codex_files::canonical(ctx, &mut pins, &mut [])?;
    transitions.compare(&pins)?;

    let mut files = Vec::new();
    // The generation's order: authority, manifest, receipt, config.
    for index in [2, 1, 3, 0] {
        files.push(publication[index].clone());
    }
    files.push(backup.clone());
    files.extend(migration);
    files.extend(alternate_files);
    files.extend(cleanup);
    files.extend(shim_files);
    files.extend(pins.iter().cloned());
    super::codex_files::canonical(ctx, &mut files, &mut backups)?;
    let files = unique(transitions, files)?;
    // A pin `unique` kept unchanged was compared above, after every step that
    // reads the home; hashing it again costs a pass over the pinned runtime
    // and its packaged files. A pin two roles merged is compared again here,
    // under the merged role.
    transitions.compare(&not_yet_compared(&files, &pins))?;
    Ok(json!({
        "files": files,
        "rendered_config": rendered,
        "backups": backups,
        "backup_path": backup.get("path"),
        "migrated": migrated,
        "managed_servers": managed_names,
        "skipped_servers": skipped,
        "shim_manifest": shim.get("manifest"),
    }))
}

pub(super) fn install_plan(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let mut transitions = Transitions {
        fields,
        events: Vec::new(),
    };
    let planned = plan(ctx, &mut transitions);
    let events = json!(transitions.events);
    match planned {
        Ok(mut answer) => {
            answer["events"] = events;
            Ok(answer)
        }
        Err(Stop::Conflict) => Ok(json!({ "conflict": true, "events": events })),
        Err(Stop::Fault(fault)) => Ok(json!({ "fault": fault, "events": events })),
        Err(Stop::Failed(failure)) => Err(failure),
    }
}

#[cfg(test)]
mod compared_pins_tests {
    use serde_json::json;

    #[test]
    fn only_pins_compared_unchanged_are_skipped() {
        let pin = json!({"path": "/runtime", "expected_digest": "aa", "role": "runtime"});
        let merged = json!({"path": "/runtime", "expected_digest": "aa", "role": "artifact"});
        let config = json!({"path": "/config.toml", "before": null});
        let pins = [pin.clone()];

        let skipped = super::not_yet_compared(&[config.clone(), pin], &pins);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0], config);
        let kept = super::not_yet_compared(&[config.clone(), merged.clone()], &pins);
        assert_eq!(kept, vec![config, merged]);
    }
}

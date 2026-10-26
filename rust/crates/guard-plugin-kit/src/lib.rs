//! The HOL Guard Plugin Kit: check a plugin source, package it for every
//! agent runtime that can load it, and print its install links.
//!
//! The Kit reads only the repository it is pointed at, plus the record of
//! what `plugin install` added under the Guard home. It runs no commands and
//! makes no network calls. `hol-guard plugin` sends one JSON request on stdin
//! to `hol-guard-runtime plugin-kit --stdin` and gets one response back:
//! `{"ok": true, "result": ...}` or `{"ok": false, "error": <code>}`.

mod agent_plugins;
mod card;
mod check;
mod config;
mod detect;
mod emit;
mod init;
mod install;
mod ledger;
mod links;
mod model;
mod output;
mod reference;
mod walk;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

pub use emit::{Output, Runtime};

pub const COMMAND: &str = "plugin-kit";
pub const FEATURE: &str = "plugin-kit-v1";
pub const PROVENANCE_FILE: &str = "hol.provenance.json";
pub const PROVENANCE_SCHEMA: &str = "hol.plugin-kit.provenance.v1";

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
enum Request {
    Check {
        root: String,
        #[serde(default)]
        strict: bool,
    },
    /// Conformance to a published plugin format; see `agent_plugins.rs`.
    Conformance {
        root: String,
        spec: String,
        #[serde(default)]
        strict: bool,
    },
    Package {
        root: String,
        #[serde(default)]
        out_dir: Option<String>,
        #[serde(default)]
        runtimes: Vec<String>,
        #[serde(default)]
        force: bool,
        #[serde(default)]
        strict: bool,
    },
    Links {
        root: String,
        #[serde(default)]
        block: bool,
        #[serde(default)]
        slug: Option<String>,
    },
    /// A draft `.well-known` card; see `card.rs`.
    Card {
        root: String,
        #[serde(default)]
        slug: Option<String>,
    },
    Init {
        root: String,
        #[serde(default)]
        name: Option<String>,
    },
    /// The spec is the registry's untrusted answer; see `install.rs`.
    /// `slug` and `version` are what the user asked for; the spec must match.
    Install {
        spec: Value,
        #[serde(default)]
        available: Vec<String>,
        #[serde(default)]
        runtimes: Vec<String>,
        #[serde(default)]
        slug: Option<String>,
        #[serde(default)]
        version: Option<String>,
    },
    /// Plans from what Guard recorded installing; see `ledger.rs`.
    Uninstall {
        guard_home: String,
        slug: String,
        #[serde(default)]
        available: Vec<String>,
        #[serde(default)]
        runtimes: Vec<String>,
    },
    Record {
        guard_home: String,
        slug: String,
        runtime: String,
        installed: bool,
        #[serde(default)]
        spec: Option<Value>,
    },
    Installs {
        guard_home: String,
    },
}

/// Runs one request and wraps the outcome in the native response envelope.
pub fn run_request(bytes: &[u8]) -> Value {
    match serde_json::from_slice::<Request>(bytes)
        .map_err(|_| "plugin_kit_request_invalid".to_owned())
        .and_then(handle)
    {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    }
}

fn handle(request: Request) -> Result<Value, String> {
    match request {
        Request::Check { root, strict } => {
            let root = resolve_root(&root)?;
            check_report(&root, strict)
        }
        Request::Conformance { root, spec, strict } => {
            let root = resolve_root(&root)?;
            match spec.as_str() {
                agent_plugins::SPEC => Ok(agent_plugins::check(&root, strict)),
                _ => Err("plugin_kit_spec_unsupported".to_owned()),
            }
        }
        Request::Links { root, block, slug } => {
            let root = resolve_root(&root)?;
            let detection = detect::detect(&root)?;
            serde_json::to_value(links::links(&detection, block, slug.as_deref())?)
                .map_err(|_| "plugin_kit_encode_failed".to_owned())
        }
        Request::Card { root, slug } => {
            let root = resolve_root(&root)?;
            let detection = detect::detect(&root)?;
            serde_json::to_value(card::card(&detection, slug.as_deref())?)
                .map_err(|_| "plugin_kit_encode_failed".to_owned())
        }
        Request::Init { root, name } => {
            let root = resolve_root(&root)?;
            let detection = detect::detect(&root)?;
            let outputs = init::plan(&root, &detection, name.as_deref())?;
            let written = output::write(&root, &outputs, output::Mode::Exclusive)?;
            Ok(json!({"written": written, "scaffolded": detection.sources.is_empty()}))
        }
        Request::Install {
            spec,
            available,
            runtimes,
            slug,
            version,
        } => {
            let plan = install::plan(spec, install::Action::Install, &available, &runtimes)?;
            if slug.is_some_and(|slug| slug != plan.slug) {
                return Err("plugin_kit_install_spec_mismatch".to_owned());
            }
            if version.is_some_and(|version| plan.version.as_ref() != Some(&version)) {
                return Err("plugin_kit_install_version_unavailable".to_owned());
            }
            encode(&plan)
        }
        Request::Uninstall {
            guard_home,
            slug,
            available,
            runtimes,
        } => {
            let spec = ledger::spec(&guard_home, &slug)?;
            let plan = install::plan(spec, install::Action::Uninstall, &available, &runtimes)
                .map_err(|error| match error.as_str() {
                    "plugin_kit_install_runtime_not_offered" => ledger::NOT_RECORDED.to_owned(),
                    "plugin_kit_install_runtime_unknown" => error,
                    _ => ledger::INVALID.to_owned(),
                })?;
            encode(&plan)
        }
        Request::Record {
            guard_home,
            slug,
            runtime,
            installed,
            spec,
        } => ledger::record(&guard_home, &slug, &runtime, installed, spec),
        Request::Installs { guard_home } => ledger::installs(&guard_home),
        Request::Package {
            root,
            out_dir,
            runtimes,
            force,
            strict,
        } => {
            let root = resolve_root(&root)?;
            package(&root, out_dir.as_deref(), &runtimes, force, strict)
        }
    }
}

fn encode(plan: &install::Plan) -> Result<Value, String> {
    serde_json::to_value(plan).map_err(|_| "plugin_kit_encode_failed".to_owned())
}

fn resolve_root(root: &str) -> Result<PathBuf, String> {
    let path = Path::new(root);
    if !path.is_absolute() {
        return Err("plugin_kit_root_invalid".to_owned());
    }
    let resolved = path.canonicalize().map_err(|_| "plugin_kit_root_invalid")?;
    if !resolved.is_dir() {
        return Err("plugin_kit_root_invalid".to_owned());
    }
    Ok(resolved)
}

fn check_report(root: &Path, strict: bool) -> Result<Value, String> {
    let detection = detect::detect(root)?;
    let diagnostics = check::diagnostics(&detection);
    let summary = check::summary(&detection.plugin, &diagnostics);
    let passed = summary.errors == 0 && (!strict || summary.warnings == 0);
    Ok(json!({
        "passed": passed,
        "plugin": detection.plugin,
        "sources": detection.sources,
        "diagnostics": diagnostics,
        "summary": summary,
        "runtimes": check::runtimes(&detection.plugin),
    }))
}

/// Everything `package` would write, relative to the output directory,
/// without writing it. Golden tests compare this plan.
pub fn package_plan(root: &Path, requested: &[String]) -> Result<Vec<Output>, String> {
    let detection = detect::detect(root)?;
    let runtimes = select_runtimes(root, &detection.plugin, requested)?;
    let mut copied = BTreeSet::new();
    let mut outputs = emit::plan(
        root,
        &detection.plugin,
        &detection.excludes,
        &runtimes,
        &mut copied,
    )?;
    let mut inputs: BTreeSet<PathBuf> = detection.inputs.iter().cloned().collect();
    inputs.extend(copied);
    let inputs: Vec<PathBuf> = inputs.into_iter().collect();
    let files: Vec<Value> = outputs
        .iter()
        .map(|output| {
            json!({
                "path": output.path,
                "sha256": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&output.content)),
            })
        })
        .collect();
    let emitted: Vec<&str> = runtimes
        .iter()
        .filter(|runtime| emit::supports(**runtime, &detection.plugin))
        .map(|runtime| runtime.id())
        .collect();
    let provenance = json!({
        "schema": PROVENANCE_SCHEMA,
        "generator": {"name": "hol-guard plugin-kit", "version": env!("CARGO_PKG_VERSION")},
        "plugin": {"name": detection.plugin.name, "version": detection.plugin.version},
        "repository": detection.plugin.github_repository().map(|full_name| format!("https://github.com/{full_name}")),
        "source_digest": emit::source_digest(root, &inputs),
        "runtimes": emitted,
        "files": files,
    });
    outputs.push(Output {
        path: PROVENANCE_FILE.to_owned(),
        content: emit::json_bytes(&provenance),
    });
    Ok(outputs)
}

fn select_runtimes(
    root: &Path,
    plugin: &model::Plugin,
    requested: &[String],
) -> Result<Vec<Runtime>, String> {
    let configured = config(root)
        .and_then(|config| config.get("runtimes").cloned())
        .and_then(|runtimes| serde_json::from_value::<Vec<String>>(runtimes).ok())
        .unwrap_or_default();
    let names = if requested.is_empty() {
        &configured
    } else {
        requested
    };
    if names.is_empty() {
        return Ok(Runtime::ALL
            .into_iter()
            .filter(|runtime| emit::supports(*runtime, plugin))
            .collect());
    }
    let mut runtimes = names
        .iter()
        .map(|name| {
            Runtime::parse(name.trim()).ok_or_else(|| "plugin_kit_unknown_runtime".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    runtimes.sort();
    runtimes.dedup();
    // A runtime named on the command line must be packaged; one from
    // hol.json stays best effort, so a shared config can list them all.
    if !requested.is_empty()
        && runtimes
            .iter()
            .any(|runtime| !emit::supports(*runtime, plugin))
    {
        return Err("plugin_kit_runtime_unsupported".to_owned());
    }
    Ok(runtimes)
}

fn config(root: &Path) -> Option<Value> {
    let text = walk::read_text(&root.join(init::CONFIG_FILE))?;
    let value: Value = serde_json::from_str(&text).ok()?;
    (value.get("schema").and_then(Value::as_str) == Some(init::CONFIG_SCHEMA)).then_some(value)
}

fn package(
    root: &Path,
    out_dir: Option<&str>,
    requested: &[String],
    force: bool,
    strict: bool,
) -> Result<Value, String> {
    let report = check_report(root, strict)?;
    if report.get("passed") != Some(&Value::Bool(true)) {
        return Ok(json!({"packaged": false, "check": report}));
    }
    let out = match out_dir {
        Some(out_dir) if Path::new(out_dir).is_absolute() => PathBuf::from(out_dir),
        Some(_) => return Err("plugin_kit_output_path_invalid".to_owned()),
        None => {
            let configured = config(root)
                .and_then(|config| config.get("out").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| init::DEFAULT_OUT_DIR.to_owned());
            output::inside_root(root, &configured)?
        }
    };
    let detection = detect::detect(root)?;
    output::reject_source_overlap(root, &out, &detection.plugin)?;
    let outputs = package_plan(root, requested)?;
    let mode = if force {
        output::clear_previous(&out)?;
        output::Mode::Replace
    } else {
        output::require_empty(&out)?;
        output::Mode::Exclusive
    };
    let written = output::write(&out, &outputs, mode)?;
    let emitted = select_runtimes(root, &detection.plugin, requested)?;
    let runtimes: Vec<_> = check::runtimes(&detection.plugin)
        .into_iter()
        .filter(|support| support.supported && emitted.contains(&support.runtime))
        .collect();
    Ok(json!({
        "packaged": true,
        "out_dir": out.to_string_lossy(),
        "files": written,
        "runtimes": runtimes,
        "check": report,
    }))
}

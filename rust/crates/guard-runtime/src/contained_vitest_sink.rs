//! The native sink's read-only Vitest run.
//!
//! Guard's own sink asks the resident about the planned argv from every
//! directory the run touches, copies the project's esbuild into a private
//! image the sandbox may start once the resident allows its service ping,
//! and preloads a fixed `localhost` answer into every Node runtime the run
//! starts, so tests reach a local server without opening the OS resolver.
//! This replays those steps for a Vitest run of the plain shape.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;

use super::readonly::{self, ReadonlyPlan};
use super::*;

/// The note for a failed run whose output names a denied write.
const READ_ONLY_WRITE_NOTE: &str = "This run hit a denied file operation (EPERM or EROFS). HOL Guard runs these tests with the project read-only; only $TMPDIR is writable. If a test writes reports, caches or other files into the project, point that output at $TMPDIR and run the same command again.";

/// The fixed `localhost` answer each Node runtime of the run loads first.
/// It supplies a local address, not a DNS or network grant: other names
/// still use Node's ordinary resolver under the unchanged OS deny boundary.
const LOCALHOST_RESOLUTION: &str = r#"
const dns = require('node:dns');
const originalLookup = dns.lookup.bind(dns);
const originalPromiseLookup = dns.promises.lookup.bind(dns.promises);
function local(hostname, options) {
  if (hostname !== 'localhost' && hostname !== 'localhost.') return null;
  const value = typeof options === 'number' ? {family: options} : (options || {});
  const family = value.family === 6 || value.family === 'IPv6' ? 6 : 4;
  const address = family === 6 ? '::1' : '127.0.0.1';
  return value.all ? [{address, family}] : {address, family};
}
dns.lookup = function(hostname, options, callback) {
  if (typeof options === 'function') {callback = options; options = undefined;}
  const result = local(hostname, options);
  if (!result) return originalLookup(hostname, options, callback);
  if (typeof callback !== 'function') throw new TypeError('lookup requires callback');
  queueMicrotask(() => Array.isArray(result) ? callback(null, result) : callback(null, result.address, result.family));
};
dns.promises.lookup = async function(hostname, options) {
  return local(hostname, options) || originalPromiseLookup(hostname, options);
};
// Worker threads can supply execArgv that omits the parent's fixed preload.
const threads = require('node:worker_threads');
const OriginalWorker = threads.Worker;
threads.Worker = class extends OriginalWorker {
  constructor(filename, options = {}) {
    const execArgv = [...(options.execArgv || process.execArgv)];
    if (!execArgv.includes(__filename)) execArgv.push('--require', __filename);
    super(filename, {...options, execArgv});
  }
};
require('node:module').syncBuiltinESMExports();
"#;

/// Run `plan`, the Vitest run Guard's own sink planned for `payload`.
pub(super) fn run(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    mut plan: ReadonlyPlan,
    timeout: u64,
    signals: &process::Signals,
) -> Outcome<i32> {
    let route = readonly::VITEST_ROUTE;
    readonly::authorize_route(authority, payload, route)?;
    // Check the planned Node run too, from every directory it touches:
    // selecting another directory cannot shed the original project's denies.
    let mut contexts = vec![path_text(workspace)?];
    if !contexts.contains(&plan.cwd) {
        contexts.push(plan.cwd.clone());
    }
    for directory in &contexts {
        let asked = readonly::with_command(payload, &plan.command, Some(directory));
        readonly::authorize_route(authority, &asked, route)?;
    }
    let private = readonly::private_root()?;
    signals.clean_up(private.path.clone());
    let images = Images::create()?;
    signals.clean_up(images.path.clone());
    let anchor = tsx_package_dir(&plan.command).unwrap_or_else(|| PathBuf::from(&plan.cwd));
    let project = native(
        "nearest_project_root",
        json!({
            "cwd": wire_path(&anchor),
            "workspace": plan.workspace,
            "value": "node_modules/esbuild/package.json",
        }),
    )?;
    let Value::String(project) = project else {
        return Err(unavailable("invalid_reply"));
    };
    let image = esbuild_image::snapshot(Path::new(&project), &images.path)?;
    if let Some(image) = &image {
        let ping = [
            path_text(&image.source)?,
            format!("--service={}", image.version),
            "--ping".to_owned(),
        ];
        for directory in &contexts {
            let asked = readonly::with_command(payload, &ping, Some(directory));
            let response = authority
                .authorize(&asked)
                .ok_or_else(Failure::unauthorized)?;
            if !capability_allowed(&response, route) {
                return Err(Failure::unauthorized());
            }
        }
        plan.allowed_executables.push(path_text(&image.image)?);
    }
    let mut environment = readonly::environment(&plan, &private)?;
    if let Some(image) = &image {
        environment.insert("ESBUILD_BINARY_PATH".into(), path_text(&image.image)?);
    }
    let preload = path_text(&write_preload(&private.path)?)?;
    plan.command
        .splice(1..1, ["--require".to_owned(), preload.clone()]);
    // Vitest supplies its own worker execArgv. Only Guard-owned options,
    // not the caller's NODE_OPTIONS or NODE_PATH, may reach those runtimes.
    let quoted = serde_json::to_string(&preload).map_err(|_| unavailable("invalid_reply"))?;
    environment.remove("NODE_PATH");
    environment.insert("NODE_OPTIONS".into(), format!("--require {quoted}"));
    readonly::launch(
        &plan,
        &private,
        &environment,
        signals,
        timeout,
        process::Notes::ReadOnly(READ_ONLY_WRITE_NOTE),
    )
}

/// Whether the resident lets the run start the transform image: allowed
/// outright, or read as a capability of this read-only Vitest run.
fn capability_allowed(response: &Map<String, Value>, route: readonly::Route) -> bool {
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    response.get("observe_mode") != Some(&Value::Bool(true))
        && ((text("decision") == Some("allow") && text("policy_action") == Some("allow"))
            || readonly::readonly_route(response) == Some(route))
}

/// The tsx package a contained `--import` loader names, read as
/// `urllib.parse` reads its `file:` URL.
fn tsx_package_dir(command: &[String]) -> Option<PathBuf> {
    command.windows(2).find_map(|pair| {
        let value = pair[1]
            .strip_prefix("file:")
            .filter(|_| pair[0] == "--import")?;
        let value = value.split(['#', '?']).next().unwrap_or_default();
        let path = match value.strip_prefix("//") {
            Some(authority) => authority.find('/').map_or("", |at| &authority[at..]),
            None => value,
        };
        let path = PathBuf::from(guard_command::local_supply_chain::unquote(path));
        let dist = path.parent()?;
        let package = dist.parent()?;
        (path.file_name()? == "loader.mjs"
            && dist.file_name()? == "dist"
            && package.file_name()? == "tsx")
            .then(|| package.to_path_buf())
    })
}

/// Write the `localhost` preload, read-only, into the run's private root.
fn write_preload(private: &Path) -> Outcome<PathBuf> {
    let source = private.join("localhost-resolution.cjs");
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&source)
        .and_then(|mut file| file.write_all(LOCALHOST_RESOLUTION.as_bytes()));
    written.map_err(|_| {
        Failure::new(
            SANDBOX_UNAVAILABLE,
            "The read-only sandbox directory is unavailable.",
        )
    })?;
    Ok(source)
}

/// The directory that holds the run's transform image, apart from its
/// writable scratch, removed when dropped.
struct Images {
    path: PathBuf,
}

impl Images {
    fn create() -> Outcome<Self> {
        let unavailable = || {
            Failure::new(
                SANDBOX_UNAVAILABLE,
                "The read-only sandbox directory is unavailable.",
            )
        };
        let template = std::env::temp_dir().join("hol-guard-vitest-images-XXXXXX");
        let created = nix::unistd::mkdtemp(&template).map_err(|_| unavailable())?;
        let Ok(path) = std::fs::canonicalize(&created) else {
            let _ = std::fs::remove_dir(&created);
            return Err(unavailable());
        };
        Ok(Self { path })
    }
}

impl Drop for Images {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
#[path = "contained_vitest_sink_tests.rs"]
mod tests;

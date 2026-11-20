//! `InventoryScanTargets` - resident op choosing what a Cisco inventory scan
//! reads.
//!
//! The selection used to run in `inventory_cisco.py`: which `.mcp.json` files
//! a pass opens, which directory each one is scanned under, what each target
//! is called in a finding, and which skill collections the skill scanner
//! walks. None of it is presentation. A configuration left out of the list is
//! a configuration no scanner opens, and a skill collection the walk misses
//! is instructions that never reach a finding, so the answer decides what the
//! inventory can possibly report.
//!
//! It is also filesystem work the resident should own: `is_file` and `is_dir`
//! on every candidate, a recursive search for `SKILL.md` under every
//! plausible collection, and `Path.resolve()` on everything that is
//! deduplicated, compared against the workspace, or labelled.
//!
//! One request covers a whole inventory pass, because
//! `run_cisco_inventory_scans` is called once per pass.
//!
//! Paths travel as the caller holds them and are resolved against the
//! request's `cwd`, not the resident's own working directory.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::{
    InventoryScanTargetArtifactV1, InventoryScanTargetsRequestV1, InventoryScanTargetsResultV1,
    INVENTORY_SCAN_TARGETS_MAX_ARTIFACTS, INVENTORY_SCAN_TARGETS_MAX_BYTES,
    INVENTORY_SCAN_TARGETS_MAX_VISITED_ENTRIES, INVENTORY_SCAN_TARGETS_REQUEST_SCHEMA,
    INVENTORY_SCAN_TARGETS_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::aibom_paths::{is_dir, is_file};
use crate::claude_hook_bridge_url::resolve_absolute;
use crate::package_authority_op::request_digest_with_limit;
use crate::zcode_detect::sort_key;

const SKILL_DOCUMENT: &str = "SKILL.md";
const SKILL_COLLECTION_DIR: &str = "skills";
const ERR_WALK: &str = "native_inventory_scan_targets_walk_too_large";

pub(crate) fn evaluate_inventory_scan_targets_request(
    request: &InventoryScanTargetsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, INVENTORY_SCAN_TARGETS_MAX_BYTES)
        .map_err(|_| "native_inventory_scan_targets_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code.to_owned(), None),
        None => match evaluate_request(request) {
            Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
            Err(code) => ("error", code.to_owned(), None),
        },
    };
    crate::encode_response(&InventoryScanTargetsResultV1 {
        schema: INVENTORY_SCAN_TARGETS_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &InventoryScanTargetsRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != INVENTORY_SCAN_TARGETS_REQUEST_SCHEMA {
        return Some("native_inventory_scan_targets_schema_mismatch");
    }
    if request.artifacts.len() > INVENTORY_SCAN_TARGETS_MAX_ARTIFACTS {
        return Some("native_inventory_scan_targets_too_many_artifacts");
    }
    None
}

/// The directories one request is answered against, and the walk budget it
/// shares across every skill collection it searches.
struct Scan<'a> {
    cwd: &'a Path,
    home: PathBuf,
    workspace: Option<PathBuf>,
    budget: Cell<usize>,
    /// What each collection already walked holds, by its resolved path.
    ///
    /// One collection is reached once per skill that lives in it: the
    /// `skill_root` probe and the walk up from the skill's own path both land
    /// on the same directory. Charging the same entries again for every
    /// artifact spends the request's budget as the square of an ordinary
    /// install's skill count, so a shared answer is kept instead.
    walked: RefCell<HashMap<String, Vec<String>>>,
}

impl Scan<'_> {
    /// The bases an artifact-relative path is tried under, workspace first,
    /// which is the order `_artifact_skill_root` and `_mcp_scan_targets` read
    /// them in.
    fn bases(&self) -> Vec<&Path> {
        let mut bases: Vec<&Path> = Vec::new();
        if let Some(workspace) = self.workspace.as_deref() {
            bases.push(workspace);
        }
        bases.push(self.home.as_path());
        bases
    }

    /// The path the caller's own process would have stat'ed.
    fn absolute(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        }
    }

    /// `Path(path).resolve()`: symlinks followed as far as they exist, the
    /// remainder kept lexically. The Python callers wrap this in
    /// `except OSError`, which a lenient resolve never reaches.
    fn resolve(&self, path: &Path) -> String {
        resolve_absolute(&self.absolute(path).to_string_lossy())
    }

    fn is_file(&self, path: &Path) -> bool {
        is_file(&self.absolute(path))
    }

    fn is_dir(&self, path: &Path) -> bool {
        is_dir(&self.absolute(path))
    }

    /// Charges one directory entry against the request's walk budget.
    fn spend(&self) -> Result<(), &'static str> {
        let left = self.budget.get();
        if left == 0 {
            return Err(ERR_WALK);
        }
        self.budget.set(left - 1);
        Ok(())
    }
}

fn evaluate_request(request: &InventoryScanTargetsRequestV1) -> Result<Value, &'static str> {
    let cwd = PathBuf::from(&request.cwd);
    let scan = Scan {
        cwd: cwd.as_path(),
        home: PathBuf::from(&request.home_dir),
        workspace: request.workspace_dir.as_deref().map(PathBuf::from),
        budget: Cell::new(INVENTORY_SCAN_TARGETS_MAX_VISITED_ENTRIES),
        walked: RefCell::new(HashMap::new()),
    };
    Ok(json!({
        "mcp_targets": mcp_targets(request, &scan),
        "skill_roots": skill_roots(request, &scan)?,
    }))
}

/// `_mcp_scan_targets`: the workspace's and the home's own `.mcp.json`, then
/// every configuration a detected MCP server names.
fn mcp_targets(request: &InventoryScanTargetsRequestV1, scan: &Scan<'_>) -> Vec<Value> {
    let mut targets: Vec<Value> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for base in scan.bases() {
        let config = base.join(".mcp.json");
        if scan.is_file(&config) {
            push_unique(&mut targets, &mut seen, base, &config, scan);
        }
    }
    for artifact in &request.artifacts {
        if artifact.artifact_type != "mcp_server" {
            continue;
        }
        let Some(raw) = artifact.config_path.as_deref() else {
            continue;
        };
        if raw.trim().is_empty() {
            continue;
        }
        let config = PathBuf::from(raw);
        if !scan.is_file(&config) {
            continue;
        }
        let root = mcp_scan_root_for_config(&config, scan);
        push_unique(&mut targets, &mut seen, &root, &config, scan);
    }
    targets
}

/// `_extend_unique_mcp_targets`: one entry per distinct pair of resolved root
/// and resolved configuration, keeping the first spelling that reached it.
fn push_unique(
    targets: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    root: &Path,
    config: &Path,
    scan: &Scan<'_>,
) {
    let key = format!("{}::{}", scan.resolve(root), scan.resolve(config));
    if !seen.insert(key) {
        return;
    }
    targets.push(json!({
        "root": root.to_string_lossy(),
        "config_path": config.to_string_lossy(),
        "label": mcp_target_label(root, config, scan),
    }));
}

/// `_mcp_scan_root_for_config`: a configuration inside the workspace is
/// scanned with the whole workspace as its root, and anything else only with
/// its own directory, so a scan never reads a tree the context did not name.
fn mcp_scan_root_for_config(config: &Path, scan: &Scan<'_>) -> PathBuf {
    let parent = config.parent().unwrap_or(Path::new("")).to_path_buf();
    let Some(workspace) = scan.workspace.as_deref() else {
        return parent;
    };
    match relative_to(&scan.resolve(config), &scan.resolve(workspace)) {
        Some(_) => workspace.to_path_buf(),
        None => parent,
    }
}

/// `_safe_mcp_target_label`: what a finding calls this target. The workspace
/// name is preferred, then the scan root's, then the bare file name, so a
/// label never spells out a directory above the scan.
fn mcp_target_label(root: &Path, config: &Path, scan: &Scan<'_>) -> String {
    let resolved = scan.resolve(config);
    let under_workspace = scan
        .workspace
        .as_deref()
        .and_then(|workspace| relative_to(&resolved, &scan.resolve(workspace)));
    if let Some(relative) = under_workspace {
        return relative;
    }
    if let Some(relative) = relative_to(&resolved, &scan.resolve(root)) {
        return relative;
    }
    config
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `Path(path).relative_to(base).as_posix()`, where `None` is the `ValueError`
/// Python raises for a path that is not under `base`. The comparison is
/// component-wise, so `/w/abc` is not under `/w/ab`, and names are folded
/// where the platform folds them, which is what `relative_to` does on
/// Windows.
pub(crate) fn relative_to(path: &str, base: &str) -> Option<String> {
    let mut components = Path::new(path).components();
    for expected in Path::new(base).components() {
        let actual = components.next()?;
        if sort_key(&actual.as_os_str().to_string_lossy())
            != sort_key(&expected.as_os_str().to_string_lossy())
        {
            return None;
        }
    }
    let relative: Vec<String> = components
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if relative.is_empty() {
        // `Path.relative_to` answers `Path(".")` for a path that is its own
        // base, and an empty string would name the containing directory.
        return Some(".".to_owned());
    }
    Some(relative.join("/"))
}

/// `_skill_scan_roots`: Hermes keeps its skills in one place and that place
/// wins whenever it holds any, because a detection's artifacts describe
/// individual skill files rather than the collection the scanner walks.
fn skill_roots(
    request: &InventoryScanTargetsRequestV1,
    scan: &Scan<'_>,
) -> Result<Vec<String>, &'static str> {
    let mut roots: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if request.harness == "hermes" {
        let hermes = scan.home.join(".hermes").join(SKILL_COLLECTION_DIR);
        for candidate in skill_dirs_under(&hermes, scan)? {
            if seen.insert(scan.resolve(Path::new(&candidate))) {
                roots.push(candidate);
            }
        }
        if !roots.is_empty() {
            return Ok(roots);
        }
    }
    for artifact in &request.artifacts {
        if artifact.artifact_type != "skill" && artifact.artifact_type != "skill_file" {
            continue;
        }
        let Some(root) = artifact_skill_root(artifact, scan)? else {
            continue;
        };
        if seen.insert(scan.resolve(&root)) {
            roots.push(root.to_string_lossy().into_owned());
        }
    }
    Ok(roots)
}

/// `_artifact_skill_root`: the collection one detected skill belongs to.
///
/// A recorded `skill_root` is tried first, under the workspace and then the
/// home, and is accepted when it is a skill itself or holds skills. Otherwise
/// the artifact's own path is walked upwards: the nearest `skills` directory
/// that holds skills, then the nearest directory holding a `SKILL.md`, then
/// the artifact's own directory when it is one.
fn artifact_skill_root(
    artifact: &InventoryScanTargetArtifactV1,
    scan: &Scan<'_>,
) -> Result<Option<PathBuf>, &'static str> {
    if let Some(skill_root) = artifact.skill_root.as_deref() {
        for base in scan.bases() {
            let Some(candidate) = contained_skill_root(base, skill_root, scan) else {
                continue;
            };
            if !scan.is_dir(&candidate) {
                continue;
            }
            if scan.is_file(&candidate.join(SKILL_DOCUMENT))
                || !skill_dirs_under(&candidate, scan)?.is_empty()
            {
                return Ok(Some(candidate));
            }
        }
    }
    let Some(raw) = artifact.config_path.as_deref() else {
        return Ok(None);
    };
    let skill_path = PathBuf::from(raw);
    let collection =
        nearest_skill_collection_dir(&skill_path, scan)?.filter(|path| scan.is_dir(path));
    if let Some(collection) = collection {
        return Ok(Some(collection));
    }
    let nearest = nearest_skill_dir(&skill_path, scan).filter(|path| scan.is_dir(path));
    if let Some(nearest) = nearest {
        return Ok(Some(nearest));
    }
    if scan.is_dir(&skill_path) && scan.is_file(&skill_path.join(SKILL_DOCUMENT)) {
        return Ok(Some(skill_path));
    }
    Ok(None)
}

/// A recorded `skill_root` resolved under one base, or `None` when it names a
/// directory outside it.
///
/// The value reaches the request through a detection's metadata, which the
/// workspace's own files can write. An absolute root, or one that climbs out
/// with `..`, or one reached through a symlink that leaves the base, would
/// otherwise aim the skill scanner at any directory on the host: its files
/// would be read into findings, and a root as wide as `/` would spend the
/// whole walk budget and leave the pass reporting no inventory at all. A root
/// that does not stay inside the base it was named against is left unused, and
/// the artifact's own path decides the collection, which is where the skill
/// was actually found.
fn contained_skill_root(base: &Path, skill_root: &str, scan: &Scan<'_>) -> Option<PathBuf> {
    let candidate = PathBuf::from(scan.resolve(&base.join(skill_root)));
    relative_to(&candidate.to_string_lossy(), &scan.resolve(base))?;
    Some(candidate)
}

/// `_skill_dirs_under`: `sorted({path.parent.resolve() for path in
/// root.rglob("SKILL.md") if path.is_file()})`.
///
/// The walk never descends a directory symlink, which is what `rglob` does,
/// and an unreadable directory is skipped rather than refused, which is what
/// `rglob` does too. Each visited entry is charged against the request's
/// budget so one looping or enormous tree cannot hold the resident.
fn skill_dirs_under(root: &Path, scan: &Scan<'_>) -> Result<Vec<String>, &'static str> {
    let key = scan.resolve(root);
    if let Some(walked) = scan.walked.borrow().get(&key) {
        return Ok(walked.clone());
    }
    let walked = walk_skill_dirs(root, scan)?;
    scan.walked.borrow_mut().insert(key, walked.clone());
    Ok(walked)
}

fn walk_skill_dirs(root: &Path, scan: &Scan<'_>) -> Result<Vec<String>, &'static str> {
    if !scan.is_dir(root) {
        return Ok(Vec::new());
    }
    let mut found: Vec<(Vec<String>, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut pending: Vec<PathBuf> = vec![scan.absolute(root)];
    while let Some(directory) = pending.pop() {
        let Ok(listing) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in listing.filter_map(Result::ok) {
            scan.spend()?;
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if sort_key(&name) != sort_key(SKILL_DOCUMENT) || !is_file(&path) {
                continue;
            }
            let Some(parent) = path.parent() else {
                continue;
            };
            let resolved = scan.resolve(parent);
            if seen.insert(resolved.clone()) {
                found.push((path_sort_key(&resolved), resolved));
            }
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// How Python orders two paths: component by component, case-folded where the
/// platform folds names. Sorting the strings instead would put `/a-b` before
/// `/a/b`, because `-` sorts below the separator.
fn path_sort_key(path: &str) -> Vec<String> {
    Path::new(path)
        .components()
        .map(|component| sort_key(&component.as_os_str().to_string_lossy()))
        .collect()
}

/// `_nearest_skill_dir`: the directory whose `SKILL.md` this path belongs to.
fn nearest_skill_dir(path: &Path, scan: &Scan<'_>) -> Option<PathBuf> {
    if path.file_name().is_some_and(|name| name == SKILL_DOCUMENT) {
        return path.parent().map(Path::to_path_buf);
    }
    path.ancestors()
        .skip(1)
        .find(|parent| scan.is_file(&parent.join(SKILL_DOCUMENT)))
        .map(Path::to_path_buf)
}

/// `_nearest_skill_collection_dir`: the closest `skills` directory above this
/// path that actually holds skills.
fn nearest_skill_collection_dir(
    path: &Path,
    scan: &Scan<'_>,
) -> Result<Option<PathBuf>, &'static str> {
    for parent in path.ancestors().skip(1) {
        if parent
            .file_name()
            .is_none_or(|name| name != SKILL_COLLECTION_DIR)
        {
            continue;
        }
        if !skill_dirs_under(parent, scan)?.is_empty() {
            return Ok(Some(parent.to_path_buf()));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "inventory_scan_targets_op_tests.rs"]
mod tests;

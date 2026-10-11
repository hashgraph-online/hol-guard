//! `WorkspaceInventory` — resident op owning the workspace audit inventory
//! that `local_supply_chain.py` used to derive in Python: manifest and lockfile
//! discovery, the dependency inventory (manifests, lockfiles, SBOMs), the
//! before/after manifest diff and the lockfile warnings. The caller supplies
//! only the workspace paths; every derived field is decided here.

use std::collections::HashMap;
use std::path::Path;

use guard_command::dep_map::DepMap;
use guard_command::package_manifest_diff::{
    parse_manifest_dependencies_ordered, parse_manifest_dependency_changes,
};
use guard_command::workspace_inventory::{
    inventory_from_sbom_payload, merge_inventory_item, python_strip, split_namespace_name,
    InventoryMap, ECOSYSTEM_BY_LOCKFILE, ECOSYSTEM_BY_MANIFEST,
};
use guard_contracts::{
    SupplyChainEvalResultV1, WorkspaceInventoryRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::request_digest;
use crate::workspace_inventory_files::{
    basename, expanduser, read_sbom_text, read_text, read_workspace_audit_text, resolve_sbom_paths,
    workspace_files,
};

const MANIFEST_BYTE_LIMIT: usize = 2_097_152;
const MANIFEST_DEADLINE_MS: u64 = 50;

fn invalid() -> String {
    "native_workspace_inventory_invalid".to_owned()
}

fn item(
    ecosystem: &str,
    namespace: Option<String>,
    name: String,
    direct: bool,
    range: Option<String>,
    version: Option<String>,
) -> Map<String, Value> {
    let mut entry = Map::new();
    entry.insert("ecosystem".into(), json!(ecosystem));
    entry.insert("namespace".into(), json!(namespace));
    entry.insert("name".into(), json!(name));
    entry.insert("direct".into(), json!(direct));
    entry.insert("range".into(), json!(range));
    entry.insert("version".into(), json!(version));
    entry
}

fn stripped_or_none(version: &str) -> Option<String> {
    let stripped = python_strip(version);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// Dependency maps keyed by workspace-relative path, parsed at most once.
struct DependencyReader<'a> {
    workspace: &'a Path,
    cache: HashMap<String, Option<DepMap>>,
}

impl<'a> DependencyReader<'a> {
    fn new(workspace: &'a Path) -> Self {
        Self {
            workspace,
            cache: HashMap::new(),
        }
    }

    /// `None` when the file cannot be read for audit; otherwise the parse.
    fn dependencies(&mut self, path: &str) -> Option<&DepMap> {
        let workspace = self.workspace;
        self.cache
            .entry(path.to_owned())
            .or_insert_with(|| {
                let text = read_workspace_audit_text(workspace, path)?;
                Some(parse_manifest_dependencies_ordered(
                    path,
                    &text,
                    MANIFEST_BYTE_LIMIT,
                    MANIFEST_DEADLINE_MS,
                ))
            })
            .as_ref()
    }
}

fn merge_dependencies(
    inventory: &mut InventoryMap,
    reader: &mut DependencyReader<'_>,
    path: &str,
    ecosystem: &str,
    direct: bool,
) {
    let Some(dependencies) = reader.dependencies(path) else {
        return;
    };
    for (package_name, version) in dependencies.iter() {
        let (namespace, name) = split_namespace_name(package_name);
        let stripped = stripped_or_none(version);
        let (range, version) = if direct {
            (stripped, None)
        } else {
            (None, stripped)
        };
        merge_inventory_item(
            inventory,
            &item(ecosystem, namespace, name, direct, range, version),
        );
    }
}

/// `_workspace_inventory_from_paths`.
fn inventory_from_paths(
    reader: &mut DependencyReader<'_>,
    manifest_paths: &[String],
    lockfile_paths: &[String],
) -> InventoryMap {
    let mut inventory = InventoryMap::new();
    for path in manifest_paths {
        if let Some(ecosystem) = ECOSYSTEM_BY_MANIFEST.get(basename(path)) {
            merge_dependencies(&mut inventory, reader, path, ecosystem, true);
        }
    }
    for path in lockfile_paths {
        if let Some(ecosystem) = ECOSYSTEM_BY_LOCKFILE.get(basename(path)) {
            merge_dependencies(&mut inventory, reader, path, ecosystem, false);
        }
    }
    inventory
}

fn merge_sboms(inventory: &mut InventoryMap, workspace_dir: &str, sbom_paths: &[String]) {
    for sbom_path in sbom_paths {
        let Some(text) = read_sbom_text(&Path::new(workspace_dir).join(sbom_path)) else {
            continue;
        };
        let Ok(payload) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Ok(items) = inventory_from_sbom_payload(&payload) else {
            continue;
        };
        for parsed in &items {
            merge_inventory_item(inventory, parsed);
        }
    }
}

/// `_workspace_diff_audit_inventory`: the inventory of dependencies changed
/// between the two workspaces plus the change summary.
fn diff_inventory(
    before_dir: &str,
    after_dir: &str,
    manifest_paths: &[String],
    lockfile_paths: &[String],
) -> Result<(InventoryMap, Value), String> {
    let mut inventory = InventoryMap::new();
    let mut changed_paths: Vec<String> = Vec::new();
    let mut changed_packages: Vec<String> = Vec::new();
    for relative in manifest_paths.iter().chain(lockfile_paths) {
        let before = read_existing(&Path::new(before_dir).join(relative))?;
        let after = read_existing(&Path::new(after_dir).join(relative))?;
        if before.is_none() && after.is_none() {
            continue;
        }
        let result = parse_manifest_dependency_changes(
            relative,
            before.as_deref(),
            after.as_deref(),
            MANIFEST_BYTE_LIMIT,
            MANIFEST_DEADLINE_MS,
        );
        if result.changes.is_empty() {
            continue;
        }
        changed_paths.push(relative.clone());
        let name = basename(relative);
        let direct = ECOSYSTEM_BY_MANIFEST.contains_key(name);
        let Some(ecosystem) = ECOSYSTEM_BY_MANIFEST
            .get(name)
            .or_else(|| ECOSYSTEM_BY_LOCKFILE.get(name))
        else {
            continue;
        };
        for change in &result.changes {
            let Some(after_value) = &change.after else {
                continue;
            };
            let (namespace, package) = split_namespace_name(&change.package_name);
            changed_packages.push(change.package_name.clone());
            let (range, version) = if direct {
                (Some(after_value.clone()), None)
            } else {
                (None, Some(after_value.clone()))
            };
            merge_inventory_item(
                &mut inventory,
                &item(ecosystem, namespace, package, direct, range, version),
            );
        }
    }
    changed_packages.sort();
    changed_packages.dedup();
    let summary = json!({
        "changed_package_count": changed_packages.len(),
        "changed_paths": changed_paths,
    });
    Ok((inventory, summary))
}

/// `path.read_text() if path.exists() else None`; an unreadable existing file
/// fails the request instead of being treated as absent.
fn read_existing(path: &Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }
    read_text(path).map(Some).ok_or_else(invalid)
}

/// `_audit_lockfile_warnings`.
fn lockfile_warnings(
    reader: &mut DependencyReader<'_>,
    workspace: &Path,
    lockfiles: &[String],
) -> Vec<Value> {
    let mut warnings = Vec::new();
    for path in lockfiles {
        let name = basename(path);
        if !workspace.join(path).exists() {
            continue;
        }
        let warning =
            |code: &str, message: String| json!({"code": code, "message": message, "path": path});
        if name == "bun.lockb" {
            warnings.push(warning(
                "bun_lockfile_binary_fallback",
                "Guard detected bun.lockb but Bun stores it as a binary lockfile, so audit fell back to manifest-only monitoring.".to_owned(),
            ));
            continue;
        }
        if !ECOSYSTEM_BY_LOCKFILE.contains_key(name) {
            continue;
        }
        match reader.dependencies(path) {
            None => warnings.push(warning(
                "lockfile_unreadable",
                format!("Guard could not read {name} for workspace audit."),
            )),
            Some(map) if map.is_empty() => warnings.push(warning(
                "lockfile_parse_warning",
                format!("Guard could not parse {name} for workspace audit."),
            )),
            Some(_) => {}
        }
    }
    warnings
}

/// Largest serialized inventory slice per reply. The resident reply is capped
/// at 2 MiB, so the slice leaves room for the paths, diff and warnings.
const INVENTORY_PAGE_BYTES: usize = 1_048_576;

fn snapshot_digest(material: &Value) -> Result<String, String> {
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(material, &mut bytes, usize::MAX)
        .map_err(|_| invalid())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

/// One page of the inventory starting at `offset` plus the offset of the next
/// page, or `None` when the page reaches the end. A single item that cannot
/// fit in a resident reply is an error. It is not omitted, and an offset past
/// the inventory is not reported as an empty success.
fn inventory_page(items: &[Value], offset: usize) -> Result<(Vec<Value>, Option<usize>), String> {
    let total = items.len();
    if offset > total || (offset == total && total > 0) {
        return Err(invalid());
    }
    let mut page = Vec::new();
    let mut bytes = 0usize;
    let mut index = offset;
    for entry in items.iter().skip(offset) {
        let encoded = serde_json::to_vec(entry).map_err(|_| invalid())?;
        if encoded.len() >= crate::MAX_NATIVE_RESPONSE_BYTES {
            return Err("workspace_inventory_exceeds_resident_response".to_owned());
        }
        let size = encoded.len() + 1;
        if !page.is_empty() && bytes + size > INVENTORY_PAGE_BYTES {
            break;
        }
        bytes += size;
        page.push(entry.clone());
        index += 1;
    }
    Ok((page, (index < total).then_some(index)))
}

fn inventory_payload(request: &WorkspaceInventoryRequestV1) -> Result<Value, String> {
    let after_dir = request.workspace_dir.as_str();
    let (manifest_paths, lockfile_paths) = workspace_files(after_dir);
    if request.files_only {
        if request.inventory_offset > 0 {
            return Err(invalid());
        }
        let digest = snapshot_digest(&json!({
            "manifest_paths": manifest_paths,
            "lockfile_paths": lockfile_paths,
            "sbom_paths": [],
            "inventory": [],
            "diff": null,
            "lockfile_warnings": [],
        }))?;
        return Ok(json!({
            "manifest_paths": manifest_paths,
            "lockfile_paths": lockfile_paths,
            "sbom_paths": [],
            "inventory": [],
            "inventory_digest": digest,
            "next_offset": null,
            "diff": null,
            "lockfile_warnings": [],
        }));
    }
    let sbom_paths = resolve_sbom_paths(after_dir, &request.sbom_paths);
    let workspace = expanduser(after_dir);
    let mut reader = DependencyReader::new(&workspace);
    let (mut inventory, diff) = match request.before_workspace_dir.as_deref() {
        Some(before_dir) => {
            let (map, summary) =
                diff_inventory(before_dir, after_dir, &manifest_paths, &lockfile_paths)?;
            (map, summary)
        }
        None => (
            inventory_from_paths(&mut reader, &manifest_paths, &lockfile_paths),
            Value::Null,
        ),
    };
    merge_sboms(&mut inventory, after_dir, &sbom_paths);
    let warnings = if request.include_lockfile_warnings {
        lockfile_warnings(&mut reader, &workspace, &lockfile_paths)
    } else {
        Vec::new()
    };
    let items: Vec<Value> = inventory
        .into_values()
        .into_iter()
        .map(Value::Object)
        .collect();
    let digest = snapshot_digest(&json!({
        "manifest_paths": manifest_paths,
        "lockfile_paths": lockfile_paths,
        "sbom_paths": sbom_paths,
        "inventory": items,
        "diff": diff,
        "lockfile_warnings": warnings,
    }))?;
    if request.inventory_offset > 0 && request.inventory_digest.as_deref() != Some(digest.as_str())
    {
        return Err(invalid());
    }
    let (page, next_offset) = inventory_page(&items, request.inventory_offset)?;
    Ok(json!({
        "manifest_paths": manifest_paths,
        "lockfile_paths": lockfile_paths,
        "sbom_paths": sbom_paths,
        "inventory": page,
        "inventory_digest": digest,
        "next_offset": next_offset,
        "diff": diff,
        "lockfile_warnings": warnings,
    }))
}

pub(crate) fn evaluate_workspace_inventory(
    request: &WorkspaceInventoryRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_workspace_inventory_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty()
        || request.guard_home.is_empty()
        || request.workspace_dir.is_empty()
        || !expanduser(&request.workspace_dir).is_absolute()
        || request
            .before_workspace_dir
            .as_deref()
            .is_some_and(|path| !expanduser(path).is_absolute())
    {
        return Err(invalid());
    }
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(inventory_payload(request)?),
    })
}

#[cfg(test)]
#[path = "workspace_inventory_op_tests.rs"]
mod tests;

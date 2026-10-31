//! Dependency maps of workspace manifests and lockfiles, and the inventory
//! rows they contribute.

use std::collections::HashMap;
use std::path::Path;

use guard_command::dep_map::DepMap;
use guard_command::js_semver::highest_js_version_for_selector;
use guard_command::package_manifest_diff::{
    installs_every_version, try_parse_manifest_dependencies_ordered,
};
use guard_command::workspace_inventory::{
    dependency_name, merge_inventory_item, python_strip, DirectDependencies, InventoryMap,
};
use serde_json::{json, Map, Value};

use crate::workspace_inventory_files::read_workspace_audit_text;

pub(crate) const MANIFEST_BYTE_LIMIT: usize = 2_097_152;
pub(crate) const MANIFEST_DEADLINE_MS: u64 = 50;

pub(crate) fn item(
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

pub(crate) fn stripped_or_none(version: &str) -> Option<String> {
    let stripped = python_strip(version);
    (!stripped.is_empty()).then(|| stripped.to_owned())
}

/// A readable file's dependencies; empty when Guard could not parse it.
struct Parsed {
    dependencies: DepMap,
    parsed: bool,
}

/// Dependency maps keyed by workspace-relative path, parsed at most once.
pub(crate) struct DependencyReader<'a> {
    workspace: &'a Path,
    cache: HashMap<String, Option<Parsed>>,
}

impl<'a> DependencyReader<'a> {
    pub(crate) fn new(workspace: &'a Path) -> Self {
        Self {
            workspace,
            cache: HashMap::new(),
        }
    }

    fn read(&mut self, path: &str) -> Option<&Parsed> {
        let workspace = self.workspace;
        self.cache
            .entry(path.to_owned())
            .or_insert_with(|| {
                let text = read_workspace_audit_text(workspace, path)?;
                let dependencies = try_parse_manifest_dependencies_ordered(
                    path,
                    &text,
                    MANIFEST_BYTE_LIMIT,
                    MANIFEST_DEADLINE_MS,
                );
                Some(Parsed {
                    parsed: dependencies.is_some(),
                    dependencies: dependencies.unwrap_or_default(),
                })
            })
            .as_ref()
    }

    /// `None` when the file cannot be read for audit; otherwise the parse.
    pub(crate) fn dependencies(&mut self, path: &str) -> Option<&DepMap> {
        self.read(path).map(|parsed| &parsed.dependencies)
    }

    /// `None` when the file cannot be read for audit; otherwise whether Guard
    /// could parse it. A file that parses and lists no dependencies is parsed.
    pub(crate) fn parsed(&mut self, path: &str) -> Option<bool> {
        self.read(path).map(|parsed| parsed.parsed)
    }
}

pub(crate) fn merge_dependencies(
    inventory: &mut InventoryMap,
    reader: &mut DependencyReader<'_>,
    path: &str,
    ecosystem: &str,
    manifest: bool,
    direct_dependencies: &mut DirectDependencies,
) {
    let Some(dependencies) = reader.dependencies(path) else {
        return;
    };
    // Every copy such a lockfile resolves is installed, so each is listed.
    let every_version = !manifest && installs_every_version(path);
    for (package_name, version) in dependencies.iter() {
        let stripped = stripped_or_none(version);
        if manifest {
            direct_dependencies.record(path, ecosystem, package_name, stripped);
            continue;
        }
        let (namespace, name) = dependency_name(ecosystem, package_name);
        let (direct, range) =
            match direct_dependencies.lockfile_range(path, ecosystem, package_name) {
                Some(range) => (true, range),
                None => (false, None),
            };
        let earlier = if every_version {
            dependencies.earlier(package_name)
        } else {
            &[]
        };
        let selected = direct_copy(ecosystem, stripped.as_deref(), earlier, range.as_deref());
        let copies = std::iter::once(stripped).chain(earlier.iter().map(|v| stripped_or_none(v)));
        for copy in copies {
            let chosen = direct && copy == selected;
            let entry = item(
                ecosystem,
                namespace.clone(),
                name.clone(),
                chosen,
                if chosen { range.clone() } else { None },
                copy,
            );
            merge_inventory_item(inventory, &entry);
        }
    }
}

/// The copy a manifest's range installs when one lockfile resolves several:
/// npm takes the highest version the range allows. Without such a match, or
/// outside npm, the version the lockfile names last.
fn direct_copy(
    ecosystem: &str,
    current: Option<&str>,
    earlier: &[String],
    range: Option<&str>,
) -> Option<String> {
    let fallback = current.map(str::to_owned);
    let (Some(range), false) = (range, earlier.is_empty() || ecosystem != "npm") else {
        return fallback;
    };
    let copies: Vec<String> = current
        .map(str::to_owned)
        .into_iter()
        .chain(
            earlier
                .iter()
                .filter_map(|version| stripped_or_none(version)),
        )
        .collect();
    highest_js_version_for_selector(&copies, range)
        .map(str::to_owned)
        .or(fallback)
}

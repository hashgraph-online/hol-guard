//! Bounded installed-package resolution, extending the existing code graph.
//! Unknown export conditions/patterns are uncertainty, never a package verdict.

use super::*;

const MANIFEST: &str = "node_package_manifest_unproven";
const ENTRY: &str = "node_package_entrypoint_unproven";
const EXPORT: &str = "node_package_exports_unproven";

fn literal_segments(value: &str) -> bool {
    !value.is_empty()
        && !value.contains(['\\', ':', '%', '?', '#', '*'])
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".." | "node_modules"))
}

fn manifest(graph: &mut Graph<'_>, path: &str) -> Proof<Value> {
    let (digest, bytes) = graph.digest(path, MAX_MANIFEST_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| MANIFEST)?;
    if !value.is_object()
        || graph.packages.get(path).is_some_and(|old| old != &digest)
        || graph.data.get(path).is_some_and(|old| old != &digest)
    {
        return Err(MANIFEST);
    }
    graph.packages.insert(path.into(), digest);
    Ok(value)
}

fn export_target<'a>(value: &'a Value, subpath: &str) -> Proof<&'a str> {
    let selected = if let Some(map) = value.as_object() {
        if map.keys().any(|key| key.starts_with('.')) {
            if map.keys().any(|key| !key.starts_with('.')) {
                return Err(EXPORT);
            }
            map.get(subpath).ok_or(EXPORT)?
        } else if subpath == "." {
            value
        } else {
            return Err(EXPORT);
        }
    } else if subpath == "." {
        value
    } else {
        return Err(EXPORT);
    };
    // A sole default branch is unconditional. Selecting import/require or
    // custom conditions requires a resolver-kind proof, not a guessed branch.
    let selected = match selected.as_object() {
        Some(map) if map.len() == 1 => map.get("default").ok_or(EXPORT)?,
        Some(_) => return Err(EXPORT),
        None => selected,
    };
    let target = selected.as_str().ok_or(EXPORT)?;
    let suffix = target.strip_prefix("./").ok_or(EXPORT)?;
    if !literal_segments(suffix) {
        return Err(EXPORT);
    }
    Ok(suffix)
}

fn bind_target(graph: &mut Graph<'_>, package: &str, target: &str, exact: bool) -> Proof<()> {
    let path = fs_path::join(package, target);
    if extension(&path) == "node" && fs_path::is_file(&path) {
        return Err("node_package_native_addon_unproven");
    }
    if exact {
        return graph.resolve_exact_file(&path);
    }
    // Legacy main may use extension searching; exports never does. Directory
    // mains and fallback indexes stay unproven until their resolver is bound.
    let selected = REQUIRE_SUFFIXES
        .iter()
        .map(|suffix| format!("{path}{suffix}"))
        .find(|candidate| fs_path::is_file(candidate))
        .ok_or(ENTRY)?;
    if extension(&selected) == "node" {
        return Err("node_package_native_addon_unproven");
    }
    graph.resolve_exact_file(&selected)
}

fn bind_package(graph: &mut Graph<'_>, package: &str, value: &Value, subpath: &str) -> Proof<()> {
    if let Some(exports) = value.get("exports") {
        return bind_target(graph, package, export_target(exports, subpath)?, true);
    }
    if subpath != "." {
        let target = subpath.strip_prefix("./").ok_or(ENTRY)?;
        if !literal_segments(target) {
            return Err(ENTRY);
        }
        // Relative subpaths differ between import and require. Only an exact
        // file is shared by both; do not guess an extension or directory.
        return bind_target(graph, package, target, true);
    }
    let target = match value.get("main") {
        Some(Value::String(main)) if !main.is_empty() => main.strip_prefix("./").unwrap_or(main),
        None | Some(Value::String(_)) => {
            let index = ["index.js", "index.json", "index.node"]
                .into_iter()
                .find(|entry| fs_path::is_file(&fs_path::join(package, entry)))
                .ok_or(ENTRY)?;
            return bind_target(graph, package, index, true);
        }
        _ => return Err(MANIFEST),
    };
    if !literal_segments(target) {
        return Err(ENTRY);
    }
    bind_target(graph, package, target, false)
}

pub(super) fn resolve(
    graph: &mut Graph<'_>,
    importer: &str,
    specifier: &str,
    name: &str,
) -> Proof<()> {
    let tail = specifier.strip_prefix(name).ok_or(ENTRY)?;
    let subpath = if tail.is_empty() {
        ".".to_owned()
    } else {
        let suffix = tail.strip_prefix('/').ok_or(ENTRY)?;
        if !literal_segments(suffix) {
            return Err(ENTRY);
        }
        format!("./{suffix}")
    };
    // Node self-reference precedes node_modules lookup, but requires exports.
    // The nearest scope is already a bound input of the importing module.
    for parent in fs_path::parents(importer) {
        if fs_path::name(&parent) == "node_modules" {
            break;
        }
        let scope = fs_path::join(&parent, "package.json");
        if fs_path::is_file(&scope) {
            let (digest, bytes) = graph.digest(&scope, MAX_MANIFEST_BYTES)?;
            if graph.data.get(&scope) != Some(&digest) {
                return Err(MANIFEST);
            }
            let scope_value: Value = serde_json::from_slice(&bytes).map_err(|_| MANIFEST)?;
            if scope_value.get("name").and_then(Value::as_str) == Some(name)
                && scope_value.get("exports").is_some()
            {
                graph.packages.insert(scope, digest);
                return bind_package(graph, &parent, &scope_value, &subpath);
            }
            break;
        }
    }
    for parent in fs_path::parents(importer) {
        if fs_path::name(&parent) == "node_modules" {
            continue;
        }
        let package = name
            .split('/')
            .fold(fs_path::join(&parent, "node_modules"), |dir, part| {
                fs_path::join(&dir, part)
            });
        let path = fs_path::join(&package, "package.json");
        if fs_path::is_file(&path) {
            let package = fs_path::resolve_strict(&package).ok_or(ENTRY)?;
            let path = fs_path::join(&package, "package.json");
            let value = manifest(graph, &path)?;
            return bind_package(graph, &package, &value, &subpath);
        }
        // Do not silently resolve a farther package when a nearer installed
        // package lacks a manifest; its legacy index may be the real target.
        if Path::new(&package).exists() {
            return Err(MANIFEST);
        }
    }
    Err(ENTRY)
}

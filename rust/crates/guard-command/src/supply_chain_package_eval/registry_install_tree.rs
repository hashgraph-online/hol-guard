//! Git-free proof for installs that do not refuse git dependencies.
//!
//! Without `--allow-git=none`, which only npm 11.9 and later accept, a git
//! dependency anywhere in the tree is cloned and prepared with a nested
//! `npm install` even under `--ignore-scripts`. A tree with no git dependency
//! never takes that path, so `--ignore-scripts` alone keeps package code from
//! running. This module proves that from the project's own manifest and lock
//! and from public registry metadata. It over-approximates: every published
//! release a range admits is checked, not only the one npm would pick, and
//! anything it cannot read, parse or bound keeps the review.

use super::contracts::NPM_REGISTRY_METADATA_BASE_URL;
use super::*;

/// Registry documents fetched for one proof. Larger trees keep the review.
const MAX_TREE_PACKAGES: usize = 128;
/// A project manifest or lock larger than this keeps the review.
const MAX_PROJECT_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// The registry every locked package must come from.
const REGISTRY_TARBALL_PREFIX: &str = "https://registry.npmjs.org/";
/// Manifest fields whose packages npm installs into the project.
const PROJECT_DEPENDENCY_FIELDS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];
/// Fields a registry release installs alongside itself.
const RELEASE_DEPENDENCY_FIELDS: [&str; 3] =
    ["dependencies", "optionalDependencies", "peerDependencies"];

/// Whether installing `requested` (package name, registry selector) in the
/// project at `root` resolves only registry packages, none of which can be a
/// git dependency.
pub(super) fn git_free_install_tree(
    deps: &SupplyChainEvalDeps<'_>,
    root: &Path,
    requested: Vec<(String, String)>,
) -> bool {
    let Some(mut roots) = project_roots(root) else {
        return false;
    };
    roots.extend(requested);
    registry_tree_is_git_free(roots, &mut |name| {
        let url = format!(
            "{}/{}",
            NPM_REGISTRY_METADATA_BASE_URL.trim_end_matches('/'),
            name.replace('@', "%40").replace('/', "%2F")
        );
        deps.registry
            .fetch_registry_metadata(&url, "application/vnd.npm.install-v1+json")
    })
}

/// The project's own dependencies, or `None` when the manifest or a lock
/// names anything other than a registry package, or when npm could install
/// from a workspace root above the project instead.
///
/// A lock never removes a dependency from the walk: npm re-resolves any edge a
/// lock leaves out or no longer satisfies, so each manifest range is checked
/// against every release it admits. Locked packages must be registry tarballs
/// of the package their path names, so a lock cannot substitute another one.
/// npm builds a locked tree's edges from each entry's own dependency fields,
/// so those join the walk too, and any that is not a registry selector keeps
/// the review.
pub(super) fn project_roots(root: &Path) -> Option<Vec<(String, String)>> {
    if !root.is_absolute() || inside_workspace(root) {
        return None;
    }
    let manifest = read_object(&root.join("package.json"))?;
    if manifest.contains_key("overrides") || manifest.contains_key("workspaces") {
        return None;
    }
    let mut roots = Vec::new();
    for name in ["npm-shrinkwrap.json", "package-lock.json"] {
        let path = root.join(name);
        if std::fs::symlink_metadata(&path).is_ok() {
            roots.extend(registry_only_lock(&read_object(&path)?)?);
        }
    }
    for field in PROJECT_DEPENDENCY_FIELDS {
        roots.extend(registry_dependencies(manifest.get(field))?);
    }
    Some(roots)
}

/// npm installs from an ancestor workspace root that lists the project, so any
/// ancestor manifest that declares workspaces, or cannot be read, keeps the
/// review.
fn inside_workspace(root: &Path) -> bool {
    root.ancestors().skip(1).any(|dir| {
        let manifest = dir.join("package.json");
        std::fs::symlink_metadata(&manifest).is_ok()
            && read_object(&manifest).is_none_or(|manifest| manifest.contains_key("workspaces"))
    })
}

/// The dependency edges every lock entry declares, when every locked package
/// is a public registry tarball of the package its `node_modules` path names,
/// or a file bundled inside one, and every edge is a registry selector.
fn registry_only_lock(lock: &Map<String, Value>) -> Option<Vec<(String, String)>> {
    let packages = lock.get("packages").and_then(Value::as_object)?;
    let mut edges = Vec::new();
    for (key, entry) in packages {
        let entry = entry.as_object()?;
        for field in PROJECT_DEPENDENCY_FIELDS {
            edges.extend(registry_dependencies(entry.get(field))?);
        }
        if key.is_empty() {
            continue;
        }
        let name = locked_package_name(key)?;
        if entry
            .get("link")
            .is_some_and(|link| link != &Value::Bool(false))
        {
            return None;
        }
        let registry = match entry.get("resolved") {
            Some(Value::String(resolved)) => registry_tarball_of(resolved, name),
            None => entry.get("inBundle") == Some(&Value::Bool(true)),
            _ => false,
        };
        if !registry {
            return None;
        }
    }
    Some(edges)
}

/// Whether `resolved` is the canonical public registry tarball URL of a
/// release of `name`: `<registry>/<name>/-/<base>-<version>.tgz`. The file
/// name admits only version characters, so no `/`, `..`, percent escape,
/// query or fragment can make the URL name a different package.
fn registry_tarball_of(resolved: &str, name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    resolved
        .strip_prefix(&format!("{REGISTRY_TARBALL_PREFIX}{name}/-/{base}-"))
        .and_then(|rest| rest.strip_suffix(".tgz"))
        .is_some_and(|version| {
            version
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && !version.contains("..")
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
        })
}

/// The package name at the end of a lock's `node_modules` path.
fn locked_package_name(key: &str) -> Option<&str> {
    let path = key.strip_prefix("node_modules/")?;
    let name = path
        .rsplit_once("/node_modules/")
        .map_or(path, |(_, name)| name);
    (plain_registry_spec(name) && !name[1..].contains('@')).then_some(name)
}

/// Walks every registry release the requested selectors can reach. A release
/// that ships its own shrinkwrap, a dependency that is not a plain registry
/// selector, a selector no release satisfies, or an unreadable document keeps
/// the review.
pub(super) fn registry_tree_is_git_free(
    roots: Vec<(String, String)>,
    fetch: &mut dyn FnMut(&str) -> Option<RegistryDocument>,
) -> bool {
    let mut documents: BTreeMap<String, Option<Map<String, Value>>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut queue = roots;
    while let Some((name, selector)) = queue.pop() {
        if !seen.insert((name.clone(), selector.clone())) {
            continue;
        }
        // Names reach the registry URL, so each must be a plain package name.
        if !plain_registry_spec(&name) {
            return false;
        }
        if !documents.contains_key(&name) {
            if documents.len() >= MAX_TREE_PACKAGES {
                return false;
            }
            let document = fetch(&name).map(|document| document.object);
            documents.insert(name.clone(), document);
        }
        let Some(Some(document)) = documents.get(&name) else {
            return false;
        };
        let Some(releases) = admitted_releases(document, &selector) else {
            return false;
        };
        for release in releases {
            if release.get("_hasShrinkwrap") == Some(&Value::Bool(true)) {
                return false;
            }
            for field in RELEASE_DEPENDENCY_FIELDS {
                let Some(dependencies) = registry_dependencies(release.get(field)) else {
                    return false;
                };
                queue.extend(dependencies);
            }
        }
    }
    true
}

/// The releases `selector` admits: the release a dist-tag names, or every
/// release the range matches. `None` when it admits none.
fn admitted_releases<'a>(
    document: &'a Map<String, Value>,
    selector: &str,
) -> Option<Vec<&'a Map<String, Value>>> {
    let releases = document.get("versions")?.as_object()?;
    let tagged = document
        .get("dist-tags")
        .and_then(Value::as_object)
        .and_then(|tags| tags.get(selector));
    let admitted: Vec<&Map<String, Value>> = match tagged {
        Some(version) => vec![releases.get(version.as_str()?)?.as_object()?],
        None => releases
            .iter()
            .filter(|(version, _)| crate::js_semver::version_matches_js_selector(version, selector))
            .map(|(_, release)| release.as_object())
            .collect::<Option<_>>()?,
    };
    (!admitted.is_empty()).then_some(admitted)
}

/// `(name, selector)` for each entry of a dependency field, or `None` when an
/// entry is not a plain registry selector (git, URL, path, alias or tarball).
fn registry_dependencies(field: Option<&Value>) -> Option<Vec<(String, String)>> {
    let entries = match field {
        None | Some(Value::Null) => return Some(Vec::new()),
        Some(Value::Object(entries)) => entries,
        Some(_) => return None,
    };
    entries
        .iter()
        .map(|(name, selector)| {
            let selector = selector.as_str()?.trim();
            let selector = if selector.is_empty() { "*" } else { selector };
            plain_registry_spec(&format!("{name}@{selector}"))
                .then(|| (name.clone(), selector.to_owned()))
        })
        .collect()
}

fn read_object(path: &Path) -> Option<Map<String, Value>> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_PROJECT_FILE_BYTES {
        return None;
    }
    match serde_json::from_slice(&std::fs::read(path).ok()?).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

#[cfg(test)]
#[path = "registry_install_tree_tests.rs"]
mod tests;

//! Bounded attribution of captured Bash code to declared installed packages.
//! No imports, package manager, registry lookup or safety verdict runs here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use guard_contained_process::bound_fs::Directory;
use guard_contracts::{
    NativeBashSubjectV1, NativeScriptInputKindV1, NativeScriptPackageBindingV1,
    NativeScriptPackageStateV1 as State,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_METADATA_BYTES: usize = 256 * 1024;

fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn package_root(code: &Path) -> Option<PathBuf> {
    for root in code.ancestors().skip(1) {
        let (Some(name), Some(parent)) = (root.file_name()?.to_str(), root.parent()) else {
            continue;
        };
        if name.starts_with(['.', '@']) {
            continue;
        }
        if parent
            .file_name()
            .is_some_and(|name| name == "node_modules")
        {
            return Some(root.to_owned());
        }
        if parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('@'))
            && parent
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == "node_modules")
        {
            return Some(root.to_owned());
        }
    }
    None
}

fn declared_identity(value: &Value) -> Option<(String, String)> {
    let name = value.get("name")?.as_str()?;
    let version = value.get("version")?.as_str()?;
    if name.len() > 214
        || version.len() > 128
        || name.trim() != name
        || version.trim() != version
        || name.chars().any(char::is_control)
        || version.chars().any(char::is_control)
        || !guard_command::js_semver::version_matches_js_selector(version, version)
    {
        return None;
    }
    let (namespace, leaf) = if name.starts_with('@') {
        let (scope, leaf) = name.split_once('/')?;
        (Some(scope), leaf)
    } else {
        (None, name)
    };
    let identity = guard_command::supply_chain_package_identity::canonical_package_identity(
        "npm", namespace, leaf, version,
    )
    .ok()?;
    Some((identity.qualified_name(), identity.version))
}

fn metadata(
    root: &Path,
    budget: &mut usize,
    deadline: Instant,
) -> (State, Option<String>, Option<String>, Option<String>) {
    if *budget == 0 || Instant::now() >= deadline {
        return (State::MetadataBudgetExceeded, None, None, None);
    }
    let Ok(directory) = Directory::open(root) else {
        return (State::MetadataUnavailable, None, None, None);
    };
    let leaf = Path::new("package.json");
    let Ok(stat) = directory.metadata(leaf) else {
        return (State::MetadataUnavailable, None, None, None);
    };
    if !stat.is_file() {
        return (State::MetadataUnavailable, None, None, None);
    }
    let limit = MAX_MANIFEST_BYTES.min(*budget);
    if stat.len() > limit as u64 {
        return (State::MetadataBudgetExceeded, None, None, None);
    }
    let Ok(read) = directory.read(leaf, limit) else {
        return (State::MetadataUnavailable, None, None, None);
    };
    *budget = budget.saturating_sub(read.bytes.len());
    let identity = serde_json::from_slice::<Value>(&read.bytes)
        .ok()
        .and_then(|value| declared_identity(&value));
    match identity {
        Some((name, version)) => (State::Declared, Some(name), Some(version), None),
        None => (
            State::MetadataInvalid,
            None,
            None,
            Some(hash(b"guard-invalid-package-metadata-v1\0", &read.bytes)),
        ),
    }
}

pub(super) fn observe(
    subject: &NativeBashSubjectV1,
    source_bytes: usize,
    deadline: Instant,
) -> Vec<NativeScriptPackageBindingV1> {
    let mut roots: BTreeMap<PathBuf, Vec<u16>> = BTreeMap::new();
    for (index, input) in subject.code_inputs.iter().enumerate() {
        if input.kind == NativeScriptInputKindV1::Interpreter {
            continue;
        }
        if let Some(root) = package_root(Path::new(&input.resolved_path)) {
            if let Ok(index) = u16::try_from(index) {
                roots.entry(root).or_default().push(index);
            }
        }
    }
    let mut budget = MAX_METADATA_BYTES.min(1_048_576usize.saturating_sub(source_bytes));
    let mut remaining_inputs = 64usize.saturating_sub(subject.code_inputs.len());
    let mut bindings = Vec::with_capacity(roots.len());
    for (root, indices) in roots {
        let (state, name, version, invalid_hash) = if remaining_inputs == 0 {
            (State::MetadataBudgetExceeded, None, None, None)
        } else {
            remaining_inputs -= 1;
            metadata(&root, &mut budget, deadline)
        };
        let attribution =
            json!({"state":state,"name":name,"version":version,"invalid_hash":invalid_hash});
        let encoded = guard_policy_snapshot::canonical_json_bytes(&attribution)
            .expect("bounded package attribution is JSON");
        bindings.push(NativeScriptPackageBindingV1 {
            root_scope_sha256: hash(
                b"guard-script-package-root-v1\0",
                root.as_os_str().as_encoded_bytes(),
            ),
            ecosystem: "npm".into(),
            name,
            version,
            state,
            metadata_sha256: hash(b"guard-script-package-metadata-v1\0", &encoded),
            code_input_indices: indices,
        });
    }
    bindings.sort_by(|a, b| a.root_scope_sha256.cmp(&b.root_scope_sha256));
    bindings
}

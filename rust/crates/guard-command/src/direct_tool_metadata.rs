//! Native direct-tool validation helpers.
use super::*;

/// `_bun_runtime_config_exists` (:191-205).
pub(super) fn bun_runtime_config_exists(
    workspace: &Path,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    if authority
        .environment()
        .get("BUN_OPTIONS")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    let xdg_config_home = authority
        .environment()
        .get("XDG_CONFIG_HOME")
        .map(|v| v.trim().to_owned())
        .unwrap_or_default();
    for directory in workspace.ancestors() {
        let candidate = directory.join("bunfig.toml");
        if candidate.exists() && !bunfig_is_install_only(&candidate) {
            return true;
        }
    }
    let mut candidates = vec![home_dir.join(".bunfig.toml")];
    if !xdg_config_home.is_empty() {
        candidates.push(Path::new(&xdg_config_home).join(".bunfig.toml"));
    }
    candidates.iter().any(|candidate| candidate.exists())
}

/// `_bunfig_is_install_only` (:206-237).
pub(super) fn bunfig_is_install_only(path: &Path) -> bool {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if path.is_symlink() || !metadata.is_file() || metadata.len() > MAX_METADATA_BYTES {
        return false;
    }
    let text = match read_bounded_text(path, MAX_METADATA_BYTES) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let payload: toml::Value = match toml::from_str(&text) {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    let table = match payload.as_table() {
        Some(table) => table,
        None => return false,
    };
    if table.len() != 1 || !table.contains_key("install") {
        return false;
    }
    let install = match table.get("install").and_then(|v| v.as_table()) {
        Some(install) => install,
        None => return false,
    };
    if !install
        .keys()
        .all(|key| matches!(key.as_str(), "linker" | "lockfile" | "smol"))
    {
        return false;
    }
    let linker = install.get("linker");
    let smol = install.get("smol");
    let lockfile = install.get("lockfile");
    if let Some(linker) = linker {
        if linker.as_str() != Some("hoisted") && linker.as_str() != Some("isolated") {
            return false;
        }
    }
    if let Some(smol) = smol {
        if !smol.is_bool() {
            return false;
        }
    }
    if lockfile.is_none() {
        return true;
    }
    let lockfile = match lockfile.and_then(|v| v.as_table()) {
        Some(lockfile) => lockfile,
        None => return false,
    };
    lockfile.len() <= 1
        && lockfile.get("save").map(|v| v.is_bool()).unwrap_or(false)
        && lockfile.keys().all(|key| key == "save")
}

/// `_workspace_typescript_is_bound` (:239-269).
pub(super) fn workspace_typescript_is_bound(
    workspace: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    let package_dir = workspace.join("node_modules").join("typescript");
    let compiler = package_dir.join("bin").join("tsc");
    let package = read_package_json(&package_dir.join("package.json"));
    let package = match package {
        Some(package) => package,
        None => return false,
    };
    if package.get("name").and_then(Value::as_str) != Some("typescript") {
        return false;
    }
    let installed_version = package.get("version");
    let package_bin = package.get("bin");
    let bin_ok = installed_version.map(Value::is_string).unwrap_or(false)
        && package_bin
            .and_then(Value::as_object)
            .and_then(|bin| bin.get("tsc"))
            .and_then(Value::as_str)
            .map(|tsc| tsc == "bin/tsc" || tsc == "./bin/tsc")
            .unwrap_or(false);
    if !bin_ok {
        return false;
    }
    let resolved_compiler = match compiler.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    let resolved_workspace = match workspace.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    if resolved_compiler.strip_prefix(&resolved_workspace).is_err() {
        return false;
    }
    if compiler.is_symlink()
        || resolved_compiler != path_absolute(&compiler)
        || !resolved_compiler.is_file()
    {
        return false;
    }
    let declared_version = declared_dependency_version(workspace, "typescript");
    let lockfile = workspace.join("bun.lock");
    if declared_version.is_none()
        || !lockfile.is_file()
        || workspace.join("package-lock.json").exists()
    {
        return false;
    }
    let locked_identity = locked_bun_package_identity(&lockfile, "typescript");
    let installed_version = installed_version
        .and_then(Value::as_str)
        .unwrap_or_default();
    match locked_identity {
        Some((locked_version, integrity)) => {
            locked_version == installed_version
                && semver_spec_matches(&declared_version.unwrap_or_default(), installed_version)
                && typescript_package_has_trusted_identity(
                    &package_dir,
                    &locked_version,
                    &integrity,
                    authority,
                )
        }
        None => false,
    }
}

/// `_locked_bun_package_identity` (:271-293).
pub(super) fn locked_bun_package_identity(
    path: &Path,
    package_name: &str,
) -> Option<(String, String)> {
    if path.is_symlink() || !path.is_file() || path.metadata().ok()?.len() > MAX_METADATA_BYTES {
        return None;
    }
    let lock_text = read_bounded_text(path, MAX_METADATA_BYTES).ok()?;
    let lock = loads_jsonc(&lock_text).ok()?;
    let packages = lock.as_object()?.get("packages")?.as_object()?;
    let entry = packages.get(package_name)?.as_array()?;
    let first = entry.first()?.as_str()?;
    let prefix = format!("{package_name}@");
    if entry.len() <= 3 {
        return None;
    }
    let integrity = entry[3].as_str()?;
    if !first.starts_with(&prefix) || !integrity.starts_with("sha512-") {
        return None;
    }
    let decoded = strict_base64_decode(&integrity[7..])?;
    if decoded.len() != 64 {
        return None;
    }
    Some((first[prefix.len()..].to_owned(), integrity.to_owned()))
}

/// `_typescript_package_has_trusted_identity` (:295-306).
pub(super) fn typescript_package_has_trusted_identity(
    package_dir: &Path,
    version: &str,
    integrity: &str,
    authority: &dyn DirectToolAuthority,
) -> bool {
    let trusted_digest = match authority.typescript_package_digest(version, integrity) {
        Some(digest) => digest,
        None => return false,
    };
    match package_tree_digest(package_dir, authority) {
        Some(digest) => digest == trusted_digest,
        None => false,
    }
}

/// `_package_tree_digest` (:308-340). Returns `Err`-as-`None` since every
/// caller maps any failure to rejection.
pub(super) fn package_tree_digest(
    root: &Path,
    authority: &dyn DirectToolAuthority,
) -> Option<String> {
    let canonical_root = root.canonicalize().ok()?;
    if root.is_symlink() || !canonical_root.is_dir() {
        return None;
    }
    let mut records: Vec<(String, String)> = Vec::new();
    let mut total_bytes: u64 = 0;
    // `os.walk(followlinks=False)`, `directory_names.sort()`, `filenames.sort()`
    // — recursive pre-order walk over sorted children.
    let mut pending = vec![canonical_root.clone()];
    while let Some(directory_path) = pending.pop() {
        if !authority.within_budget() {
            return None;
        }
        // Depth-first pre-order; pending is a stack, so push sorted dirs in
        // reverse to visit them in sorted order.
        let mut directory_names: Vec<PathBuf> = Vec::new();
        let mut filenames: Vec<String> = Vec::new();
        for entry in fs::read_dir(&directory_path).ok()? {
            if !authority.within_budget() {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                return None;
            }
            if file_type.is_dir() {
                directory_names.push(entry.path());
            } else {
                filenames.push(name);
            }
        }
        directory_names.sort();
        filenames.sort();
        for filename in &filenames {
            if !authority.within_budget() {
                return None;
            }
            let path = directory_path.join(filename);
            let metadata = path.metadata().ok()?;
            if !path.is_file() {
                return None;
            }
            total_bytes = total_bytes.checked_add(metadata.len())?;
            if records.len() >= MAX_PACKAGE_TREE_FILES || total_bytes > MAX_PACKAGE_TREE_BYTES {
                return None;
            }
            let content = read_bounded_bytes(
                &path,
                MAX_PACKAGE_TREE_BYTES.saturating_sub(total_bytes - metadata.len()),
            )
            .ok()?;
            total_bytes = total_bytes
                .checked_sub(metadata.len())?
                .checked_add(content.len() as u64)?;
            if total_bytes > MAX_PACKAGE_TREE_BYTES {
                return None;
            }
            let relative = path
                .strip_prefix(&canonical_root)
                .ok()?
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            records.push((relative, hex::encode(Sha256::digest(&content))));
        }
        for dir in directory_names.iter().rev() {
            pending.push(dir.clone());
        }
    }
    let encoded = py_json_tuple_list(&records);
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard:package-tree:v1\0");
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    Some(hex::encode(hasher.finalize()))
}

/// `_declared_dependency_version` (:341-354).
pub(super) fn declared_dependency_version(workspace: &Path, package_name: &str) -> Option<String> {
    let package = read_package_json(&workspace.join("package.json"))?;
    for section in DEPENDENCY_SECTIONS {
        let dependencies = match package.get(*section).and_then(Value::as_object) {
            Some(dependencies) => dependencies,
            None => continue,
        };
        if let Some(declared) = dependencies.get(package_name).and_then(Value::as_str) {
            return Some(declared.to_owned());
        }
    }
    None
}

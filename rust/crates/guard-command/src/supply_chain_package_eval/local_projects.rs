use super::*;

/// `_own_package_name` (:3094-3110).
// supply_chain_package_eval.py:3094-3110
#[allow(dead_code)]
pub(super) fn own_package_name(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Option<String> {
    if optional_string(target.get("ecosystem")).as_deref() != Some("pypi") {
        return None;
    }
    if optional_string(target.get("source_url")).is_some() {
        return None;
    }
    if optional_string(target.get("source_kind")).is_some() {
        return None;
    }
    let raw_spec = optional_string(target.get("raw_spec")).unwrap_or_default();
    if raw_spec.contains("://")
        || raw_spec.starts_with("git+")
        || raw_spec.starts_with("file:")
        || raw_spec.starts_with("./")
        || raw_spec.starts_with("../")
        || raw_spec.starts_with('/')
    {
        return None;
    }
    let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_else(|| {
        normalize_package_name(
            deps,
            "pypi",
            &optional_string(target.get("name")).unwrap_or_default(),
        )
    });
    if !FIRST_PARTY_PYPI_PACKAGES.contains(normalized_name.as_str()) {
        return None;
    }
    Some(optional_string(target.get("name")).unwrap_or(normalized_name))
}

/// `_manifest_package_name` (:3469-3475).
// supply_chain_package_eval.py:3469-3475
#[allow(dead_code)]
pub(super) fn manifest_package_name(manifest_text: &str) -> Option<String> {
    let payload: Value = serde_json::from_str(if manifest_text.is_empty() {
        "{}"
    } else {
        manifest_text
    })
    .ok()?;
    payload
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `_python_setup_script_looks_suspicious` (:3464-3468).
// supply_chain_package_eval.py:3464-3468
#[allow(dead_code)]
pub(super) fn python_setup_script_looks_suspicious(content: &str) -> bool {
    static SUSPICIOUS_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\b(?:os\.system|subprocess\.(?:run|Popen|call|check_output)|requests\.(?:get|post)|urllib\.request\.)",
        )
        .expect("SUSPICIOUS_RE")
    });
    static CURL_WGET_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:curl|wget)\b").expect("CURL_WGET_RE"));
    SUSPICIOUS_RE.is_match(content) || CURL_WGET_RE.is_match(content)
}

/// `_local_python_path_text` (:3460-3461).
// supply_chain_package_eval.py:3460-3461
#[allow(dead_code)]
pub(super) fn local_python_path_text(raw_spec: &str) -> String {
    let trimmed = raw_spec.trim();
    // Strip a `file:` prefix if present.
    if let Some(rest) = trimmed.strip_prefix("file:") {
        return rest.trim().to_string();
    }
    trimmed.to_string()
}

/// `_looks_like_explicit_local_python_path` (:3424-3434).
// supply_chain_package_eval.py:3424-3434
#[allow(dead_code)]
pub(super) fn looks_like_explicit_local_python_path(raw_spec: &str) -> bool {
    static DRIVE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z]:[\\\\/]").expect("DRIVE_RE"));
    let text = local_python_path_text(raw_spec);
    let (normalized, _extras) = split_python_extras(&text);
    normalized == "."
        || normalized == "~"
        || normalized.starts_with("./")
        || normalized.starts_with("../")
        || normalized.starts_with('/')
        || normalized.starts_with("~/")
        || normalized.starts_with(".\\")
        || normalized.starts_with("..\\")
        || normalized.starts_with("~\\")
        || normalized.starts_with("\\\\")
        || normalized.starts_with("//")
        || normalized.contains('/')
        || normalized.contains('\\')
        || DRIVE_RE.is_match(&normalized)
}

/// `_local_python_project_path` (:3438-3462).
// supply_chain_package_eval.py:3438-3462
#[allow(dead_code)]
pub(super) fn local_python_project_path(
    target: &Map<String, Value>,
    workspace_dir: &Path,
) -> Option<PathBuf> {
    let mut raw_spec = optional_string(target.get("raw_spec"));
    let source_url = optional_string(target.get("source_url"));
    let editable = target
        .get("editable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if let Some(url) = &source_url {
        if url.starts_with("file:") {
            raw_spec = Some(py_partition(url, "file:").2.to_string());
        } else {
            return None;
        }
    }
    if raw_spec.is_none() {
        return if editable {
            Some(workspace_dir.to_path_buf())
        } else {
            None
        };
    }
    let raw_spec = raw_spec.unwrap();
    if raw_spec.starts_with("http://")
        || raw_spec.starts_with("https://")
        || raw_spec.starts_with("git+")
        || raw_spec.starts_with("github:")
        || raw_spec.starts_with("gitlab:")
        || raw_spec.starts_with("bitbucket:")
    {
        return None;
    }
    if !looks_like_explicit_local_python_path(&raw_spec) {
        let has_py = workspace_dir.join("pyproject.toml").exists()
            || workspace_dir.join("setup.py").exists();
        return if editable && has_py {
            Some(workspace_dir.to_path_buf())
        } else {
            None
        };
    }
    let path_text = local_python_path_text(&raw_spec);
    let candidate_path = expand_user_path(&path_text);
    let disk_path = if candidate_path.is_absolute() {
        candidate_path
    } else {
        workspace_dir.join(candidate_path)
    };
    if disk_path.is_dir() {
        if disk_path.join("pyproject.toml").exists() || disk_path.join("setup.py").exists() {
            return Some(disk_path);
        }
        return None;
    }
    let parent = disk_path.parent().map(Path::to_path_buf);
    if matches!(
        disk_path.file_name().and_then(|n| n.to_str()),
        Some("pyproject.toml") | Some("setup.py")
    ) && disk_path.exists()
    {
        return parent;
    }
    let has_py =
        workspace_dir.join("pyproject.toml").exists() || workspace_dir.join("setup.py").exists();
    if editable && has_py {
        Some(workspace_dir.to_path_buf())
    } else {
        None
    }
}

/// Expand a leading `~` like Python's `Path.expanduser` (RuntimeError -> literal).
#[allow(dead_code)]
pub(super) fn expand_user_path(text: &str) -> PathBuf {
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    } else if text == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(text)
}

/// `str.partition(sep)` — (before, sep, after); after is empty when sep absent.
#[allow(dead_code)]
pub(super) fn py_partition<'a>(value: &'a str, sep: &str) -> (&'a str, &'a str, &'a str) {
    match value.find(sep) {
        Some(index) => (
            &value[..index],
            &value[index..index + sep.len()],
            &value[index + sep.len()..],
        ),
        None => (value, "", ""),
    }
}

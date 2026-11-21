use std::path::{Path, PathBuf};

use super::Result;

pub(super) fn canonical(value: &str) -> Result<PathBuf> {
    if guard_command::bash_approval::is_descriptor_reference(value) {
        return Err("bash_process_descriptor_unproven");
    }
    if value.len() > 4096 || !Path::new(value).is_absolute() {
        return Err("bash_context_path_invalid");
    }
    std::fs::canonicalize(value).map_err(|_| "bash_context_path_unavailable")
}

pub(super) fn text(path: &Path) -> Result<String> {
    path.to_str().map(str::to_owned).ok_or("bash_path_encoding")
}

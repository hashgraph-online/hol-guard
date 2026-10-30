//! What a read-only pytest run adds to the read-only sink.
//!
//! Guard's own sink links the account's own Python packages into the run's
//! private home, so a package installed with `pip install --user` still
//! imports, and keeps bytecode and pytest's cache out of the workspace the
//! profile leaves read-only. This does the same.

use std::os::unix::fs::DirBuilderExt;

use super::*;

/// Link the account's own Python packages into the private home under
/// `private`: the root the run may then read, or `None` when the native
/// side links none.
pub(super) fn link_user_site(private: &Path) -> Outcome<Option<String>> {
    let source: BTreeMap<String, String> = environment().into_iter().collect();
    let target = match native("user_site_link_target", json!({ "source": source }))? {
        Value::Null => return Ok(None),
        Value::String(target) => target,
        _ => return Err(unavailable("invalid_reply")),
    };
    let library = private.join("home/Library");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&library)
        .and_then(|()| std::os::unix::fs::symlink(&target, library.join("Python")))
        .map_err(|_| unavailable("user_site"))?;
    Ok(Some(target))
}

/// Keep bytecode and pytest's cache under `private`, out of the read-only
/// workspace.
pub(super) fn settle(environment: &mut BTreeMap<String, String>, private: &Path) -> Outcome<()> {
    let cache = path_text(&private.join("tmp/pytest-cache"))?;
    environment.insert("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned());
    environment.insert(
        "PYTEST_ADDOPTS".to_owned(),
        format!("-o cache_dir={}", crate::mcp_proxy_shlex::quote(&cache)),
    );
    Ok(())
}

#[cfg(test)]
#[path = "contained_pytest_readonly_sink_tests.rs"]
mod tests;

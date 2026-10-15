//! Preserve lexical runtime aliases while avoiding redundant readonly mounts.
use super::plan::Result;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[allow(clippy::too_many_arguments)]
pub(super) fn compose(
    backend: &Path,
    workspace: &Path,
    cwd: &Path,
    helper: &Path,
    mounts: Vec<PathBuf>,
    writes: Vec<PathBuf>,
    images: BTreeSet<PathBuf>,
    snapshot: &Path,
    digest: &str,
    directory: &str,
) -> Result<Value> {
    let mut argv = vec![
        backend.to_string_lossy().into_owned(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-all".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "CAP_SYS_ADMIN".into(),
        "--cap-add".into(),
        "CAP_SETPCAP".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--perms".into(),
        "0700".into(),
        "--tmpfs".into(),
        "/guard-approved-mappings".into(),
    ];
    let mut mounts: Vec<_> = mounts
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    mounts.sort_by_key(|path| (path.components().count(), path.clone()));
    let mut mounted: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut bind = |flag: &str, source: &Path, destination: &Path| {
        argv.extend([
            flag.into(),
            source.to_string_lossy().into_owned(),
            destination.to_string_lossy().into_owned(),
        ]);
    };
    for path in mounts {
        let source = path
            .canonicalize()
            .map_err(|_| "Linux runtime mount could not be resolved.")?;
        if mounted.iter().any(|(parent, original)| {
            path.strip_prefix(parent)
                .is_ok_and(|relative| source == original.join(relative))
        }) {
            continue;
        }
        bind("--ro-bind", &source, &path);
        mounted.push((path, source));
    }
    bind("--ro-bind", workspace, workspace);
    for path in writes {
        bind("--bind", &path, &path);
    }
    let mut images: Vec<_> = images.into_iter().collect();
    images.sort_by_key(|path| (path.components().count(), path.clone()));
    for path in images {
        let source = path
            .canonicalize()
            .map_err(|_| "Linux approved image could not be resolved.")?;
        bind("--ro-bind", &source, &path);
    }
    argv.extend([
        "--perms".into(),
        "0700".into(),
        "--dir".into(),
        directory.into(),
        "--ro-bind".into(),
        snapshot.to_string_lossy().into_owned(),
        Path::new(directory)
            .join(super::plan::FILENAME)
            .to_string_lossy()
            .into_owned(),
        "--chdir".into(),
        cwd.to_string_lossy().into_owned(),
        "--".into(),
        helper.to_string_lossy().into_owned(),
        "restricted-linux-launch".into(),
        digest.into(),
    ]);
    Ok(json!(argv))
}

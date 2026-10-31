//! What a contained build adds to the read-only sink.
//!
//! A build Guard sends to its output profile may write the one directory
//! native authority read for it, and nothing else in the project. Guard's
//! own sink creates Vite's config bundle directory first when that is the
//! grant, starts the run with a private copy of the project's esbuild when
//! it can prepare one, and asks native authority again just before launch
//! whether each granted directory may still be written, so a plan cannot be
//! granted one directory and started against another. This does the same.

use std::os::unix::fs::DirBuilderExt;

use super::readonly::{self, ReadonlyPlan};
use super::vitest::{transform_image, Images};
use super::*;

const INVALID_OUTPUT: &str = "node_build_invalid_output";

/// Run `plan`, the build Guard's own sink planned for `payload`.
pub(super) fn run(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    mut plan: ReadonlyPlan,
    timeout: u64,
    signals: &process::Signals,
) -> Outcome<i32> {
    for root in &plan.output_roots {
        let root = Path::new(root);
        // Vite creates this directory itself; a sandbox grant needs it first.
        if root.file_name() == Some(".vite-temp".as_ref()) {
            create_bundle_directory(root, Path::new(&plan.workspace))?;
        }
    }
    let private = readonly::private_root()?;
    signals.clean_up(private.path.clone());
    let images = Images::create()?;
    signals.clean_up(images.path.clone());
    // The approved workspace stays in scope, so a build planned in another
    // directory cannot shed the original project's denies.
    let mut contexts = vec![path_text(workspace)?];
    if !contexts.contains(&plan.cwd) {
        contexts.push(plan.cwd.clone());
    }
    let image = transform_image(payload, authority, &mut plan, &contexts, &images, false)?;
    let mut environment = readonly::environment(&plan, &private)?;
    if let Some(image) = &image {
        environment.insert("ESBUILD_BINARY_PATH".into(), path_text(&image.image)?);
    }
    // Node preloads and search paths from the host are not project input.
    environment.remove("NODE_OPTIONS");
    environment.remove("NODE_PATH");
    for root in &plan.output_roots {
        let asked = json!({
            "path": root,
            "workspace": plan.workspace,
            "cwd": plan.cwd,
            "arguments": plan.command,
        });
        if native("node_build_output_admissible", asked)? != Value::Bool(true) {
            return Err(unavailable("invalid_reply"));
        }
    }
    readonly::launch(
        &plan,
        &private,
        &environment,
        signals,
        timeout,
        process::Notes::Silent,
    )
}

/// Create Vite's bundle directory only as a real directory under the
/// workspace, reached without a link.
fn create_bundle_directory(root: &Path, workspace: &Path) -> Outcome<()> {
    let refused = || {
        Failure::new(
            INVALID_OUTPUT,
            "Vite's config bundle directory is not a real directory inside the project.",
        )
    };
    let parent = root.parent().ok_or_else(refused)?;
    if is_link(root) || !reached_without_links(parent, workspace) {
        return Err(refused());
    }
    match std::fs::DirBuilder::new().mode(0o755).create(root) {
        Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => Err(refused()),
        _ if real_directory(root) => Ok(()),
        _ => Err(refused()),
    }
}

fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|info| info.file_type().is_symlink())
}

fn real_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|info| info.is_dir())
}

/// Whether `path` is a real directory and no component up to `workspace`
/// is a link.
fn reached_without_links(path: &Path, workspace: &Path) -> bool {
    let Ok(boundary) = workspace.canonicalize() else {
        return false;
    };
    let mut current = path;
    loop {
        if !real_directory(current) {
            return false;
        }
        let Ok(here) = current.canonicalize() else {
            return false;
        };
        if here == boundary {
            return true;
        }
        let Some(parent) = current.parent().filter(|_| here.starts_with(&boundary)) else {
            return false;
        };
        current = parent;
    }
}

#[cfg(test)]
#[path = "contained_node_build_sink_tests.rs"]
mod tests;

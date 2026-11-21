//! `guard_home_redirected`: whether a link redirects the Guard home.
//!
//! The command layer creates the Guard store before a delegated install writes
//! its provider rows, and must not create it beneath a link the install would
//! refuse. The user's own home may be a link, so only what lies below it
//! counts; a Guard home outside the user's home is redirected when its
//! resolved path differs from the path it was given.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use crate::harness_adapter::{Ctx, Step};

fn linked(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// Whether a link redirects `ctx.guard_home`.
fn redirected(ctx: &Ctx) -> bool {
    let guard_home = ctx.absolute(&ctx.guard_home);
    let home = ctx.absolute(&ctx.home);
    let Ok(below) = guard_home.strip_prefix(&home) else {
        return ctx.resolved(&guard_home) != guard_home;
    };
    let mut current = home;
    below.components().any(|part| {
        current.push(part);
        linked(&current)
    })
}

pub(super) fn run(ctx: &Ctx) -> Step<Value> {
    Ok(json!({ "redirected": redirected(ctx) }))
}

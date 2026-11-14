//! Removing Guard's Cursor hooks: restore the backed-up config, or strip
//! Guard's entries and keep the third-party hooks.

use std::path::Path;

use super::copilot_install::rendered;
use super::cursor::{self, Ask};
use super::cursor_files::{read_text, restore, unlink, unlink_file, write_authorized};
use super::cursor_hooks::without_managed;
use super::files::{self, within_root, Doc};
use super::{path_text, Step};
use crate::pyjson::{self, PyVal};

/// `uninstall_cursor_hooks`.
pub(super) fn uninstall(ask: &Ask) -> Step<Doc> {
    let ctx = ask.ctx;
    let (hooks, script) = (cursor::hooks_path(ctx), cursor::script_path(ctx));
    within_root(ctx, &ctx.home, &hooks, "Cursor hooks")?;
    within_root(ctx, &ctx.home, &script, "Cursor hook script")?;
    let backup = cursor::digest_path(ctx, &hooks, "hooks-", "backup");
    let state = cursor::digest_path(ctx, &hooks, "hooks-", "state");
    within_root(ctx, &ctx.guard_home, &backup, "Cursor hook backup")?;
    within_root(ctx, &ctx.guard_home, &state, "Cursor hook state")?;
    let mut restored = restore(ctx, &backup, &hooks, "The Cursor hooks backup")?;
    if restored {
        unlink_file(ctx, &backup)?;
        unlink_file(ctx, &state)?;
    }
    if !restored && ctx.absolute(&hooks).is_file() && remove_managed(ask, &hooks, &script)? {
        restored = true;
        unlink_file(ctx, &state)?;
    }
    if ctx.absolute(&script).is_file() {
        let source = read_text(ctx, &script, "The Cursor hook script")?.unwrap_or_default();
        if crate::cursor_hook_config::is_managed_script(&source) {
            unlink(ctx, &script)?;
        }
    }
    let managed = cursor::managed_script_path(ctx);
    within_root(ctx, &ctx.guard_home, &managed, "Cursor managed hook script")?;
    unlink_file(ctx, &managed)?;
    let mut result = Doc::default();
    result
        .set("managed_hooks_path", files::path_value(&hooks))
        .set("restored", PyVal::Bool(restored))
        .set(
            "removed_hook_script",
            PyVal::Bool(!ctx.absolute(&script).is_file()),
        );
    Ok(result)
}

/// `_remove_managed_hook_entries`: whether Guard's entries were removed.
fn remove_managed(ask: &Ask, hooks: &Path, script: &Path) -> Step<bool> {
    let ctx = ask.ctx;
    let Ok(text) = std::fs::read_to_string(ctx.absolute(hooks)) else {
        return Ok(false);
    };
    let Ok(payload) = pyjson::parse(&text) else {
        return Ok(false);
    };
    let (cleaned, removed) = without_managed(ask, &payload, &path_text(&ctx.resolved(script)))?;
    if !removed {
        return Ok(false);
    }
    match cleaned {
        None => unlink(ctx, hooks)?,
        Some(cleaned) => write_authorized(ctx, hooks, &rendered(&cleaned)?)?,
    }
    Ok(true)
}

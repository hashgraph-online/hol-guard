//! The Guard process that asked: its interpreter, frozen state, package root
//! and version, sent once in every request's context as `caller`.
//!
//! Each launcher, hook argv and package path an adapter writes is derived
//! here from those facts, instead of every Python adapter gathering them.

use serde_json::Value;

use super::{Ctx, Failure, Step};

/// The variables a managed launcher pins from the installer's environment
/// (`_LAUNCHER_BINDING_ENV_VARS`).
const LAUNCHER_BINDING_ENV: [&str; 4] = [
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
    "HOL_GUARD_NATIVE_DIAGNOSTIC",
    "HOL_GUARD_TEST_MODE",
];

fn text<'a>(ctx: &'a Ctx, key: &str) -> Step<&'a str> {
    ctx.caller
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)
}

/// Whether the caller is a frozen Guard binary.
pub(super) fn frozen(ctx: &Ctx) -> Step<bool> {
    ctx.caller
        .get("frozen")
        .and_then(Value::as_bool)
        .ok_or(Failure::Invalid)
}

/// The directory the caller imports `codex_plugin_scanner` from.
pub(super) fn package_root(ctx: &Ctx) -> Step<&str> {
    text(ctx, "package_root")
}

/// The caller's interpreter as its absolute path, unresolved.
pub(super) fn executable(ctx: &Ctx) -> Step<&str> {
    text(ctx, "executable")
}

/// `guard_cli_launcher()`: the argv0 Guard writes into harness hooks, MCP
/// proxies and launchers, the caller's interpreter unless it is frozen.
pub(super) fn launcher(ctx: &Ctx) -> Step<&str> {
    text(ctx, "launcher")
}

/// `resolve_frozen_guard_cli()` of a frozen caller: the prune-safe launcher a
/// daemon recovery runs through.
pub(super) fn frozen_launcher(ctx: &Ctx) -> Step<&str> {
    text(ctx, "frozen_launcher")
}

/// The interpreter a Codex hook relaunches: a frozen binary by its resolved
/// bytes, since the hook manifest authenticates exactly those, else the
/// caller's interpreter.
pub(super) fn hook_python(ctx: &Ctx) -> Step<&str> {
    if frozen(ctx)? {
        text(ctx, "executable_resolved")
    } else {
        executable(ctx)
    }
}

/// `merge_guard_launcher_env(pin_package=True)`: the package a launcher
/// imports, unless the caller is frozen, then each native binding variable
/// the caller set.
pub(super) fn launcher_env(ctx: &Ctx) -> Step<Vec<(String, String)>> {
    let mut env = Vec::new();
    if !frozen(ctx)? {
        env.push(("PYTHONPATH".to_owned(), package_root(ctx)?.to_owned()));
    }
    for name in LAUNCHER_BINDING_ENV {
        if let Some(value) = ctx.env(name).filter(|value| !value.is_empty()) {
            env.push((name.to_owned(), value.to_owned()));
        }
    }
    Ok(env)
}

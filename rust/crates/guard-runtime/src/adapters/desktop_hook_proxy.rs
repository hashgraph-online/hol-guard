//! `runner_authority` kind `desktop_hook_proxy`: the signed macOS Desktop
//! proxy launch for frozen bounded hooks, which
//! `guard/adapters/desktop_hook_proxy.py` built before it moved here.
//!
//! - `command` answers the `/bin/sh` launch that checks the proxy's signature
//!   again before every hook, or `null` to keep the Core bridge. The proxy and
//!   Core must be private executables side by side in one app bundle, and the
//!   proxy, Core and the bundle must verify with one Apple Team ID.
//! - `verify` checks that a stored launch is that script over such paths and
//!   answers its config and Core path for the caller's own checks, or `null`.
//! - `script` answers the script and its `$0`, for callers that recognise it.
//!
//! The caller sends whether the Desktop app launched it and the proxy path it
//! was given; the resident's own environment is never read.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};
use crate::macos_code_signing::signing_team;
use crate::native_install_verdict::{Runner, SystemRunner};

const SHELL: &str = "/bin/sh";
const NAME: &str = "hol-guard-desktop-proxy";
const TEAM_TIMEOUT: Duration = Duration::from_secs(5);
const SCRIPT: &str = r#"set -u
proxy=$1
expected_team=$2
bundle=$3
config=$4
fallback=$5
proxy_required=$6
fallback_bridge() {
  [ "$proxy_required" = "1" ] && exit 125
  exec "$fallback" __guard-bounded-hook "$config"
}
verify_team() {
  candidate=$1
  /usr/bin/codesign --verify --strict --verbose=2 "$candidate" >/dev/null 2>&1 || return 1
  actual_team=$(
    /usr/bin/codesign --display --verbose=4 "$candidate" 2>&1 \
      | /usr/bin/sed -n 's/^TeamIdentifier=//p' \
      | /usr/bin/head -n 1
  ) || return 1
  [ -n "$actual_team" ] || return 1
  [ "$actual_team" != "not set" ] || return 1
  [ "$actual_team" = "$expected_team" ]
}
[ -x "$proxy" ] && [ ! -L "$proxy" ] || fallback_bridge
[ -x "$fallback" ] && [ ! -L "$fallback" ] || fallback_bridge
[ -d "$bundle" ] && [ ! -L "$bundle" ] || fallback_bridge
proxy_before=$(/usr/bin/stat -f '%d:%i:%u:%p' "$proxy" 2>/dev/null) || fallback_bridge
fallback_before=$(/usr/bin/stat -f '%d:%i:%u:%p' "$fallback" 2>/dev/null) || fallback_bridge
verify_team "$bundle" || fallback_bridge
verify_team "$proxy" || fallback_bridge
verify_team "$fallback" || fallback_bridge
proxy_after=$(/usr/bin/stat -f '%d:%i:%u:%p' "$proxy" 2>/dev/null) || fallback_bridge
fallback_after=$(/usr/bin/stat -f '%d:%i:%u:%p' "$fallback" 2>/dev/null) || fallback_bridge
[ "$proxy_before" = "$proxy_after" ] || fallback_bridge
[ "$fallback_before" = "$fallback_after" ] || fallback_bridge
"$proxy" __guard-hook-proxy "$config"
status=$?
if [ "$status" -eq 125 ] || [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then
  fallback_bridge
fi
exit "$status""#;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let map = args_object(args)?;
    let macos = cfg!(target_os = "macos");
    match map.get("op").and_then(Value::as_str) {
        Some("command") => command(map, macos, &mut SystemRunner),
        Some("verify") => verify(map, macos, &mut SystemRunner),
        Some("script") if map.len() == 1 => Ok(json!({ "script": SCRIPT, "name": NAME })),
        _ => Err(ERR_INVALID),
    }
}

/// The proxy, Core and bundle of a verified launch and their one team.
#[derive(Debug, PartialEq)]
struct Launch {
    proxy: PathBuf,
    core: PathBuf,
    bundle: PathBuf,
    team: String,
}

fn command(map: &Map<String, Value>, macos: bool, runner: &mut impl Runner) -> KindResult {
    let keys = ["op", "core", "config", "require_proxy", "desktop", "proxy"];
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let text = |key: &str| map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let optional = |key: &str| match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        _ => Err(ERR_INVALID),
    };
    let (core, config) = (text("core")?, text("config")?);
    let require = map
        .get("require_proxy")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let (desktop, proxy) = (optional("desktop")?, optional("proxy")?);
    let launch = match proxy.filter(|proxy| macos && desktop == Some("1") && !proxy.is_empty()) {
        Some(proxy) => verified(Path::new(proxy), Path::new(core), runner),
        None => None,
    };
    Ok(json!({ "argv": launch.map(|launch| argv(&launch, config, require)) }))
}

fn argv(launch: &Launch, config: &str, require: bool) -> Vec<String> {
    let path = |path: &Path| path.to_string_lossy().into_owned();
    vec![
        SHELL.to_owned(),
        "-c".to_owned(),
        SCRIPT.to_owned(),
        NAME.to_owned(),
        path(&launch.proxy),
        launch.team.clone(),
        path(&launch.bundle),
        config.to_owned(),
        path(&launch.core),
        if require { "1" } else { "0" }.to_owned(),
    ]
}

/// A stored launch is trusted only as `/bin/sh -c SCRIPT NAME proxy team
/// bundle config core`, over the exact verified paths and team.
fn verify(map: &Map<String, Value>, macos: bool, runner: &mut impl Runner) -> KindResult {
    if map.len() != 2 {
        return Err(ERR_INVALID);
    }
    let args = map
        .get("args")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|arg| arg.as_str().ok_or(ERR_INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let unverified = json!({ "config": null, "core": null });
    let [shell, flag, script, name, proxy, team, bundle, config, core] = args.as_slice() else {
        return Ok(unverified);
    };
    if !macos || [*shell, *flag, *script, *name] != [SHELL, "-c", SCRIPT, NAME] {
        return Ok(unverified);
    }
    let expected = Launch {
        proxy: PathBuf::from(proxy),
        core: PathBuf::from(core),
        bundle: PathBuf::from(bundle),
        team: (*team).to_owned(),
    };
    if !expected.bundle.is_absolute()
        || verified(&expected.proxy, &expected.core, runner) != Some(expected)
    {
        return Ok(unverified);
    }
    Ok(json!({ "config": config, "core": core }))
}

/// The launch when `proxy` and `core` are trusted executables beside each
/// other in one bundle and all three verify with one team.
fn verified(proxy: &Path, core: &Path, runner: &mut impl Runner) -> Option<Launch> {
    if !proxy.is_absolute() || !core.is_absolute() || !trusted_path(proxy) || !trusted_path(core) {
        return None;
    }
    let proxy = fs::canonicalize(proxy).ok()?;
    let core = fs::canonicalize(core).ok()?;
    let bundle = bundle_of(&proxy)?;
    if bundle_of(&core).as_ref() != Some(&bundle) || proxy.parent() != core.parent() {
        return None;
    }
    let team = team_of(runner, &proxy)?;
    if team_of(runner, &core)? != team || team_of(runner, &bundle)? != team {
        return None;
    }
    Some(Launch {
        proxy,
        core,
        bundle,
        team,
    })
}

fn team_of(runner: &mut impl Runner, path: &Path) -> Option<String> {
    signing_team(runner, path.to_str()?, false, TEAM_TIMEOUT)
}

/// The nearest enclosing `.app` directory.
fn bundle_of(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .find(|ancestor| {
            ancestor
                .extension()
                .is_some_and(|extension| extension == "app")
        })
        .map(Path::to_path_buf)
}

/// A regular executable that only this user or root owns and nobody else can
/// rewrite, under a bundle whose `Contents/MacOS` chain is the same.
#[cfg(unix)]
fn trusted_path(path: &Path) -> bool {
    use nix::unistd::{access, AccessFlags};
    let Ok(raw) = fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(resolved) = fs::canonicalize(path) else {
        return false;
    };
    let Ok(info) = fs::metadata(&resolved) else {
        return false;
    };
    if raw.file_type().is_symlink()
        || !info.is_file()
        || access(&resolved, AccessFlags::X_OK).is_err()
        || !private(&info)
    {
        return false;
    }
    let Some(bundle) = bundle_of(&resolved) else {
        return false;
    };
    let contents = bundle.join("Contents");
    [bundle.clone(), contents.clone(), contents.join("MacOS")]
        .iter()
        .all(|directory| {
            let raw = fs::symlink_metadata(directory);
            let info = fs::metadata(directory);
            matches!((raw, info), (Ok(raw), Ok(info))
                if !raw.file_type().is_symlink() && info.is_dir() && private(&info))
        })
}

#[cfg(not(unix))]
fn trusted_path(_path: &Path) -> bool {
    false
}

#[cfg(unix)]
fn private(info: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    [0, nix::unistd::getuid().as_raw()].contains(&info.uid()) && info.mode() & 0o022 == 0
}

#[cfg(all(test, unix))]
#[path = "desktop_hook_proxy_tests.rs"]
mod tests;

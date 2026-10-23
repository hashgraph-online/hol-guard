//! Read-only Rust status command over the existing public snapshot directory.

use gauntlet_dashboard::snapshot::PublicRoot;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(OsStr::new("--state")) {
        return Err("usage: gauntlet-status --state ABSOLUTE_STATE_DIRECTORY".into());
    }
    let state = args
        .next()
        .map(PathBuf::from)
        .ok_or("--state needs an absolute directory")?;
    if args.next().is_some() || !state.is_absolute() {
        return Err("usage: gauntlet-status --state ABSOLUTE_STATE_DIRECTORY".into());
    }
    let public = PublicRoot::open(&state.join("public"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    println!("{}", serde_json::to_string_pretty(&public.snapshot(now))?);
    Ok(())
}

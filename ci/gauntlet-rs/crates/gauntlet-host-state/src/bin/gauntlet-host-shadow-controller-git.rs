//! Uninstalled read-only diagnostic for exact Git controller source objects.

use gauntlet_host_state::verify_git_controller_source;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

fn embedded_source_map() -> Result<BTreeMap<String, String>, String> {
    let baseline: Value = serde_json::from_str(include_str!("../../../../parity-manifest.v1.json"))
        .map_err(|_| "invalid embedded baseline manifest")?;
    let delta: Value =
        serde_json::from_str(include_str!("../../../../integration-source-delta.v1.json"))
            .map_err(|_| "invalid embedded integration delta")?;
    if delta["base_source_commit"] != baseline["source_commit"] {
        return Err("integration delta has a different baseline".to_owned());
    }
    let mut map = BTreeMap::new();
    for row in baseline["files"]
        .as_array()
        .ok_or("invalid embedded baseline files")?
    {
        let path = row["path"]
            .as_str()
            .ok_or("invalid embedded baseline path")?;
        let hash = row["sha256"]
            .as_str()
            .ok_or("invalid embedded baseline hash")?;
        if map.insert(path.to_owned(), hash.to_owned()).is_some() {
            return Err("duplicate embedded baseline path".to_owned());
        }
    }
    for row in delta["changed"]
        .as_array()
        .ok_or("invalid embedded changed files")?
    {
        let path = row["path"]
            .as_str()
            .ok_or("invalid embedded changed path")?;
        let old = row["base_sha256"]
            .as_str()
            .ok_or("invalid embedded original hash")?;
        let new = row["sha256"]
            .as_str()
            .ok_or("invalid embedded changed hash")?;
        if map.get(path).map(String::as_str) != Some(old) {
            return Err("embedded source delta does not match baseline".to_owned());
        }
        map.insert(path.to_owned(), new.to_owned());
    }
    for row in delta["added"]
        .as_array()
        .ok_or("invalid embedded added files")?
    {
        let path = row["path"].as_str().ok_or("invalid embedded added path")?;
        let hash = row["sha256"]
            .as_str()
            .ok_or("invalid embedded added hash")?;
        if map.insert(path.to_owned(), hash.to_owned()).is_some() {
            return Err("embedded added path already exists".to_owned());
        }
    }
    if map.len() != 426 {
        return Err("embedded integration map has an unexpected file count".to_owned());
    }
    Ok(map)
}

fn run() -> Result<String, String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: gauntlet-host-shadow-controller-git ABSOLUTE_REPOSITORY EXACT_COMMIT_SHA"
                .to_owned(),
        );
    }
    let map = embedded_source_map()?;
    verify_git_controller_source(Path::new(&args[1]), &args[2], &map)
        .map(|proof| proof.to_json().to_string())
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("Git controller source shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}

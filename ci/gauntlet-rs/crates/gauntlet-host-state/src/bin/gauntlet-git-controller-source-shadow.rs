//! Read-only exact Git source-map proof before an isolated controller install.

use gauntlet_host_state::verify_git_controller_source;
use std::collections::BTreeMap;
use std::path::Path;

fn run() -> Result<serde_json::Value, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: gauntlet-git-controller-source-shadow ABSOLUTE_REPOSITORY EXACT_COMMIT_SHA ABSOLUTE_SOURCE_MAP_JSON"
                .to_owned(),
        );
    }
    let path = Path::new(&args[3]);
    if !path.is_absolute() || path.canonicalize().map_err(|error| error.to_string())? != path {
        return Err("canonical absolute source map required".to_owned());
    }
    let raw = std::fs::read(path).map_err(|error| error.to_string())?;
    if raw.is_empty() || raw.len() > 1024 * 1024 {
        return Err("bounded source map required".to_owned());
    }
    let canonical = gauntlet_contracts::canonicalize(&raw).map_err(|error| error.to_string())?;
    let hashes: BTreeMap<String, String> =
        serde_json::from_slice(&canonical).map_err(|error| error.to_string())?;
    verify_git_controller_source(Path::new(&args[1]), &args[2], &hashes)
        .map(|proof| proof.to_json())
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(proof) => println!("{proof}"),
        Err(error) => {
            eprintln!("Git controller source unavailable: {error}");
            std::process::exit(2);
        }
    }
}

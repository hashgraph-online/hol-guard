//! Uninstalled Linux ARM64 Root diagnostic for one new inert controller tree.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn source_map(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    use rustix::fs::{fstat, open, FileType, Mode, OFlags};
    use std::io::Read;

    if !path.is_absolute() || path.canonicalize().map_err(|_| "source map unavailable")? != path {
        return Err("canonical absolute source map path required".to_owned());
    }
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "source map unavailable")?;
    let stat = fstat(&descriptor).map_err(|_| "source map unavailable")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size > 1024 * 1024
    {
        return Err("source map must be one bounded regular file".to_owned());
    }
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    std::fs::File::from(descriptor)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "source map read failed")?;
    if bytes.len() as i64 != stat.st_size {
        return Err("source map changed during read".to_owned());
    }
    let canonical =
        gauntlet_contracts::canonicalize(&bytes).map_err(|_| "invalid bounded source map JSON")?;
    serde_json::from_slice(&canonical)
        .map_err(|_| "source map must contain path-to-hash entries".to_owned())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: gauntlet-controller-install-shadow ABSOLUTE_SOURCE_ROOT EXACT_COMMIT_SHA ABSOLUTE_SOURCE_MAP_JSON EXPECTED_TREE_SHA256".to_owned());
    }
    let map = source_map(std::path::Path::new(&args[3]))?;
    gauntlet_worker_state::install_fixed_controller(
        std::path::Path::new(&args[1]),
        &args[2],
        &map,
        &args[4],
    )
    .map(|proof| proof.to_json().to_string())
    .map_err(|error| error.to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("controller install shadow unavailable: {error}");
            std::process::exit(2);
        }
    }
}

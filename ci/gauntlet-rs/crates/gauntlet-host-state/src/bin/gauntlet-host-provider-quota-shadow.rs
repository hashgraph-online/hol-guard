//! Read the retained Python v1 model-provider lifetime journal on the Mac.
//! This has no provider process, reservation or admission side effect.

use gauntlet_evidence::read_provider_quota_snapshot;
use std::path::Path;

fn lower_sha(raw: &str) -> bool {
    raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn run() -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS provider-quota shadow required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || !lower_sha(&args[2]) || !lower_sha(&args[3]) {
        return Err(
            "usage: gauntlet-host-provider-quota-shadow PRIVATE_QUOTA_ROOT CONFIG_SHA256 ALLOWANCE_SHA256"
                .to_owned(),
        );
    }
    let snapshot = read_provider_quota_snapshot(Path::new(&args[1]), &args[2], Some(&args[3]))
        .map_err(|error| format!("retained quota unavailable: {error}"))?;
    if snapshot["qualification_eligible"] != false {
        return Err("quota diagnostic unexpectedly claimed eligibility".to_owned());
    }
    println!("{snapshot}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("host provider quota shadow unavailable: {error}");
        std::process::exit(2);
    }
}

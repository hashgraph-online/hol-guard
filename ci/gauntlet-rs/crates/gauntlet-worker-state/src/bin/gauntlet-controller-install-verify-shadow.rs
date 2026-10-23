//! Independent read-only check of a fixed newly installed controller path.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<String, String> {
    use gauntlet_contracts::is_git_sha;
    use gauntlet_evidence::verify_controller_tree;
    use serde_json::json;
    use std::path::Path;

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: gauntlet-controller-install-verify-shadow EXACT_COMMIT_SHA EXPECTED_TREE_SHA256"
                .to_owned(),
        );
    }
    let source = &args[1];
    let tree_pin = &args[2];
    if !is_git_sha(source)
        || tree_pin.len() != 64
        || !tree_pin
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("exact source and tree pins required".to_owned());
    }
    let path = format!("/opt/hol-gauntlet/controller-{}", &source[..16]);
    let observed =
        verify_controller_tree(Path::new(&path), tree_pin).map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":"hol-gauntlet-controller-install-verification.v1",
        "source_sha":source,
        "controller_path":path,
        "controller_tree_digest":observed.digest(),
        "controller_tree_entries":observed.entries(),
        "controller_tree_bytes":observed.bytes(),
        "outside_pin_provenance_verified":false,
        "controller_executed":false,
        "execution_eligible":false,
    })
    .to_string())
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<String, String> {
    Err("Linux ARM64 diagnostic artifact required".to_owned())
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("controller install verification unavailable: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    use gauntlet_evidence::{
        observe_local_conformance_package_from_paths_ineligible,
        observe_local_conformance_package_with_key_pins_ineligible,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 6 && args.len() != 11 {
        eprintln!("usage: gauntlet-local-conformance-shadow ABSOLUTE_CONFIG_JSON EXTERNAL_CONFIG_SHA256 ABSOLUTE_ASSET_ROOT ABSOLUTE_CONTROLLER_ROOT EXTERNAL_CONTROLLER_TREE_SHA256 [OUTSIDE_BOUNDARY_KEY OUTSIDE_CANCEL_KEY OUTSIDE_INPUT_BINDING_KEY OUTSIDE_SUCCESS_KEY OUTSIDE_TIMEOUT_KEY]");
        std::process::exit(2);
    }
    let (Some(config_digest), Some(controller_digest)) = (args[2].to_str(), args[5].to_str())
    else {
        eprintln!("outside SHA-256 pins must be lowercase ASCII");
        std::process::exit(2);
    };
    let result = if args.len() == 11 {
        let roles = ["boundary", "cancel", "input-binding", "success", "timeout"];
        let keys: Option<BTreeMap<String, String>> = roles
            .into_iter()
            .zip(&args[6..11])
            .map(|(role, key)| Some((role.to_owned(), key.to_str()?.to_owned())))
            .collect();
        match keys {
            Some(keys) => observe_local_conformance_package_with_key_pins_ineligible(
                Path::new(&args[1]),
                config_digest,
                Path::new(&args[3]),
                Path::new(&args[4]),
                controller_digest,
                &keys,
            ),
            None => {
                eprintln!("outside control keys must be lowercase ASCII hex");
                std::process::exit(2);
            }
        }
    } else {
        observe_local_conformance_package_from_paths_ineligible(
            Path::new(&args[1]),
            config_digest,
            Path::new(&args[3]),
            Path::new(&args[4]),
            controller_digest,
        )
    };
    match result {
        Ok(shadow) => println!("{}", shadow.to_json()),
        Err(error) => {
            eprintln!("local conformance shadow refused: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux Root required for local conformance shadow");
    std::process::exit(2);
}

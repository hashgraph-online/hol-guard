use gauntlet_evidence::{
    load_runner_config_from_paths, verify_runner_assets_inert, verify_runner_file_assets,
};
use serde_json::json;
use std::path::Path;

fn main() {
    let arguments: Vec<_> = std::env::args_os().collect();
    let full_inventory =
        arguments.len() == 5 && arguments[4].to_str() == Some("--full-inert-assets");
    if arguments.len() != 4 && !full_inventory {
        eprintln!(
            "usage: gauntlet-inputs-verify ABSOLUTE_CONFIG_JSON EXTERNAL_CONFIG_SHA256 ABSOLUTE_ASSET_ROOT [--full-inert-assets]"
        );
        std::process::exit(2);
    }
    let config = Path::new(&arguments[1]);
    let Some(pin) = arguments[2].to_str() else {
        eprintln!("external config SHA-256 must be lowercase ASCII");
        std::process::exit(2);
    };
    let asset_root = Path::new(&arguments[3]);
    if !config.is_absolute() || !asset_root.is_absolute() {
        eprintln!("config and asset root must be absolute paths");
        std::process::exit(2);
    }
    let result = load_runner_config_from_paths(config, pin, asset_root).and_then(|loaded| {
        let files = verify_runner_file_assets(&loaded.verified, asset_root)?;
        let complete = if full_inventory {
            Some(verify_runner_assets_inert(&loaded, asset_root)?)
        } else {
            None
        };
        Ok(json!({
            "profile": "gauntlet-runner-inputs.v1",
            "schema": loaded.verified.config.value()["schema"],
            "config_digest": pin,
            "selected_episodes": loaded.verified.config.value()["selection"].as_array().map(Vec::len),
            "shards": loaded.verified.shards,
            "selection_reservations": loaded.verified.selection_reservations.to_json(),
            "file_assets_verified": files,
            "full_inert_asset_inventory": complete.as_ref().map(|inventory| &inventory.observed),
            "full_inert_asset_inventory_completed": complete.is_some(),
            "installed_package_version_metadata": loaded.installed_package_version,
            "tree_and_installed_assets_verified": false,
            "execution_eligible": false,
        }))
    });
    match result {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("gauntlet runner inputs invalid: {error}");
            std::process::exit(1);
        }
    }
}

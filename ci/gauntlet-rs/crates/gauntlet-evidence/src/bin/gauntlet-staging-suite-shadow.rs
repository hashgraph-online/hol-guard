//! Read-only host-manifest and six-role guest staging reconciliation.

#[cfg(target_os = "linux")]
fn run() -> Result<serde_json::Value, String> {
    use gauntlet_evidence::{
        observe_staging_suite_native_mcp_root_owned_ineligible,
        observe_staging_suite_root_owned_ineligible,
        observe_staging_suite_sdk_docs_oracle_root_owned_ineligible,
        observe_staging_suite_sdk_docs_oracle_root_relay_ineligible,
        observe_staging_suite_sdk_tap_root_owned_ineligible,
    };
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3
        && (args.len() != 4 || args[3] != "--require-native-mcp")
        && (args.len() != 10 || args[3] != "--require-sdk-tap")
        && (args.len() != 12 || args[3] != "--require-sdk-docs-oracle")
        && (args.len() != 12 || args[3] != "--require-sdk-docs-oracle-root-relay")
    {
        return Err(
            "usage: gauntlet-staging-suite-shadow BUILD_JOB HOST_MANIFEST_SHA256 [--require-native-mcp|--require-sdk-tap SUCCESS_SHA INPUT_SHA INJECTION_SHA BOUNDARY_SHA TIMEOUT_SHA CANCEL_SHA|--require-sdk-docs-oracle|--require-sdk-docs-oracle-root-relay CONTROLLER_SOURCE_SHA CONTROLLER_TREE_SHA256 SUCCESS_SHA INPUT_SHA INJECTION_SHA BOUNDARY_SHA TIMEOUT_SHA CANCEL_SHA]".to_owned(),
        );
    }
    if args.len() == 12 {
        let pins: [String; 6] = args[6..12]
            .to_vec()
            .try_into()
            .map_err(|_| "six outside SDK tap journal digests required".to_owned())?;
        let observe = if args[3] == "--require-sdk-docs-oracle-root-relay" {
            observe_staging_suite_sdk_docs_oracle_root_relay_ineligible
        } else {
            observe_staging_suite_sdk_docs_oracle_root_owned_ineligible
        };
        return observe(&args[1], &args[2], &args[4], &args[5], &pins)
            .map(|proof| proof.to_json())
            .map_err(|error| error.to_string());
    }
    if args.len() == 10 {
        let pins: [String; 6] = args[4..10]
            .to_vec()
            .try_into()
            .map_err(|_| "six outside SDK tap journal digests required".to_owned())?;
        return observe_staging_suite_sdk_tap_root_owned_ineligible(&args[1], &args[2], &pins)
            .map(|proof| proof.to_json())
            .map_err(|error| error.to_string());
    }
    let observe = if args.len() == 4 {
        observe_staging_suite_native_mcp_root_owned_ineligible
    } else {
        observe_staging_suite_root_owned_ineligible
    };
    observe(&args[1], &args[2])
        .map(|proof| proof.to_json())
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux Root staging suite audit required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("staging suite audit unavailable: {error}");
            std::process::exit(2);
        }
    }
}

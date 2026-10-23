//! Read-only joint restart verification of one Root tap and effect journal.

use gauntlet_host_state::HostControllerKeyPinJournal;
use serde_json::{json, Value};
use std::path::Path;

fn run() -> Result<Vec<u8>, String> {
    if !cfg!(target_os = "macos") {
        return Err("macOS Lima host artifact required".to_owned());
    }
    let args: Vec<String> = std::env::args().collect();
    let signed_product = args.len() == 9 && args[7] == "--signed-control-effect-reader";
    let product = args.len() == 9 && (args[7] == "--kernel-effect-reader" || signed_product);
    if args.len() != 7 && !product {
        return Err("usage: gauntlet-host-staging-effect-restart-readback PRIVATE_HOST_PIN_DIR RUN_ID SOURCE_SHA CONFIG_SHA WORKER_GENERATION_SHA READBACK_BINARY_SHA [{--kernel-effect-reader | --signed-control-effect-reader} READER_SHA]".to_owned());
    }
    let journal = HostControllerKeyPinJournal::open(Path::new(&args[1]))
        .map_err(|error| format!("private host pins unavailable: {error}"))?;
    let key = journal
        .read(&args[2])
        .map_err(|error| format!("prelaunch host key pin unavailable: {error}"))?;
    let tap = journal
        .read_sdk_tap_journal_pin(&args[2])
        .map_err(|error| format!("post-run host tap pin unavailable: {error}"))?;
    let effect = journal
        .read_effect_events_pin(&args[2])
        .map_err(|error| format!("post-run host effect pin unavailable: {error}"))?;
    key.match_effect_events_tap_ineligible(&tap, &effect)
        .map_err(|error| error.to_string())?;
    if key.pins.source_sha != args[3]
        || key.pins.deployment_digest != args[4]
        || key.pins.worker_generation != args[5]
    {
        return Err("host pins differ from outside source/config/worker generation".to_owned());
    }
    let defaults: Value = serde_json::from_str(include_str!("../../operations-defaults-v1.json"))
        .map_err(|_| "compiled Lima defaults are invalid".to_owned())?;
    let limactl = defaults["limactl"]
        .as_str()
        .ok_or("compiled Lima executable unavailable")?;
    let vm = defaults["vm"]
        .as_str()
        .ok_or("compiled Lima VM unavailable")?;
    let tap_restart = key
        .observe_fixed_vm_staging_restart_readback(limactl, vm, &args[6], &tap)
        .map_err(|error| format!("keyed tap restart readback uncertain: {error}"))?;
    let effect_restart = journal
        .verify_effect_events_from_lima_ineligible(&args[2])
        .map_err(|error| format!("keyed effect restart readback uncertain: {error}"))?;
    let mut product_effects = Vec::new();
    if product {
        for surface in ["provider-remote", "provider-home"] {
            let result = if signed_product {
                key.observe_fixed_vm_signed_kernel_provider_effect(
                    &args[8],
                    &effect,
                    &tap_restart.role,
                    surface,
                )
            } else {
                key.observe_fixed_vm_kernel_provider_effect(
                    &args[8],
                    &effect,
                    &tap_restart.role,
                    surface,
                )
            };
            product_effects.push(
                result.map_err(|e| format!("kernel-bound {surface} readback uncertain: {e}"))?,
            );
        }
        if signed_product
            && product_effects[0]["signed_control_relation"]
                != product_effects[1]["signed_control_relation"]
        {
            return Err("provider effects do not share one signed product relation".to_owned());
        }
    }
    if effect_restart != effect
        || tap_restart.terminal_sha256 != effect.terminal_sha256
        || tap_restart.report_sha256 != effect.report_sha256
        || journal.read(&args[2]).map_err(|error| error.to_string())? != key
        || journal
            .read_sdk_tap_journal_pin(&args[2])
            .map_err(|error| error.to_string())?
            != tap
        || journal
            .read_effect_events_pin(&args[2])
            .map_err(|error| error.to_string())?
            != effect
    {
        return Err("joint host tap/effect pins changed during restart readback".to_owned());
    }
    let mut value = json!({
        "schema":"hol-gauntlet-host-staging-effect-restart-readback.v1",
        "run_id":args[2],
        "role":tap_restart.role,
        "host_key_record_sha256":key.raw_sha256,
        "host_tap_pin_sha256":tap.raw_sha256,
        "host_effect_pin_sha256":effect.raw_sha256,
        "terminal_sha256":effect.terminal_sha256,
        "report_sha256":effect.report_sha256,
        "tap_journal_sha256":tap.journal_sha256,
        "effect_journal_sha256":effect.journal_sha256,
        "effect_events":effect.events,
        "unknown_writers":effect.unknown_writers,
        "restart_state":"verified-ineligible-terminal",
        "guard_causality_verified":false,
        "execution_eligible":false,
    });
    if product {
        value["schema"] = json!("hol-gauntlet-host-staging-kernel-effect-restart-readback.v1");
        value["kernel_bound_provider_effects"] = json!(product_effects);
        if signed_product {
            value["schema"] =
                json!("hol-gauntlet-host-staging-signed-kernel-effect-restart-readback.v1");
        }
    }
    gauntlet_contracts::canonicalize(value.to_string().as_bytes())
        .map_err(|error| error.to_string())
}

fn main() {
    match run() {
        Ok(raw) => println!("{}", String::from_utf8_lossy(&raw)),
        Err(error) => {
            eprintln!("joint staging restart readback unavailable: {error}");
            std::process::exit(2);
        }
    }
}

//! Read-only ARM diagnostic for sibling systemd product-cell units.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn run() -> Result<serde_json::Value, String> {
    if std::env::args_os().len() != 1 {
        return Err("this diagnostic accepts no selectors".to_owned());
    }
    let units =
        gauntlet_worker_state::observe_product_cell_units().map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "schema":"hol-gauntlet-product-cell-siblings-shadow.v1",
        "system_slice":"/sys/fs/cgroup/system.slice",
        "unit_count":units.len(),
        "units":units,
        "point_in_time_only":true,
        "whole_job_cleanup_proven":false,
        "execution_eligible":false,
    }))
}

#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
fn run() -> Result<serde_json::Value, String> {
    Err("Linux ARM64 diagnostic required".to_owned())
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("product-cell inventory unavailable: {error}");
            std::process::exit(2);
        }
    }
}

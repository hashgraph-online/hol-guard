//! Package one plugin folder the way `hol-guard plugin package` does, without
//! building the full Guard runtime. The loader smoke workflow uses it to feed
//! each runtime's own validator.
//!
//! Usage: `cargo run -p guard-plugin-kit --example package -- <plugin> <out>`

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [root, out] = args.as_slice() else {
        eprintln!("usage: package <plugin> <out>");
        return ExitCode::from(2);
    };
    let root = std::fs::canonicalize(root).expect("plugin folder");
    let out = std::path::absolute(Path::new(out)).expect("output folder");
    let request = serde_json::json!({
        "command": "package",
        "root": root.to_string_lossy(),
        "out_dir": out.to_string_lossy(),
        "strict": false,
    });
    let response = guard_plugin_kit::run_request(request.to_string().as_bytes());
    println!(
        "{}",
        serde_json::to_string_pretty(&response).expect("render")
    );
    if response["ok"] == serde_json::json!(true)
        && response["result"]["packaged"] == serde_json::json!(true)
    {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

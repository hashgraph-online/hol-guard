//! Freeze pure classifier inputs for the Python floor recorder, without a resident.

use std::io::{self, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let arguments: Vec<Vec<String>> = serde_json::from_str(&input)?;
    let facts: Vec<_> = arguments
        .into_iter()
        .map(|args| {
            let value = guard_command::github_command_capabilities::classify_github_cli(&args);
            serde_json::json!({
                "args": args,
                "capability": value.capability.as_str(),
                "capabilities": value.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "reason_code": value.reason_code,
                "detail": value.detail,
            })
        })
        .collect();
    serde_json::to_writer(io::stdout(), &facts)?;
    Ok(())
}

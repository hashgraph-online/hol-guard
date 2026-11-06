//! Local JSON-lines interface for producer qualification and integration.
use std::io::{self, BufRead, Write};
fn main() {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        let read =
            std::io::Read::take(&mut input, 4 * 1024 * 1024 + 1).read_until(b'\n', &mut bytes);
        if !matches!(read,Ok(n) if n>0) {
            break;
        }
        if bytes.len() > 4 * 1024 * 1024 {
            std::process::exit(2);
        }
        let response = match serde_json::from_slice(&bytes) {
            Ok(request) => guard_command::cloud_catalog::evaluate(&request),
            Err(_) => serde_json::json!({"error":"catalog_invalid"}),
        };
        if serde_json::to_writer(&mut output, &response).is_err()
            || writeln!(output).is_err()
            || output.flush().is_err()
        {
            break;
        }
    }
}

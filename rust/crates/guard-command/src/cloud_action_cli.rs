//! Local JSON-lines interface for a hosting service's cloud action decisions.
use std::io::{self, BufRead, Read, Write};
use std::process::ExitCode;

use guard_command::cloud_action::{error_result, CloudActionEvaluator};
use guard_command::cloud_action_activation::parse_public_key;
use guard_command::cloud_action_binding::load_binding_set;

const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_BINDING_SET_BYTES: u64 = 16 * 1024 * 1024;
const BINDING_SET_ENV: &str = "GUARD_CLOUD_ACTION_BINDING_SET";
const ACTIVATION_KEY_ENV: &str = "GUARD_CLOUD_ACTION_ACTIVATION_PUBLIC_KEY";

enum Line {
    End,
    Request,
    Oversize,
}

fn main() -> ExitCode {
    let evaluator = match startup() {
        Ok(evaluator) => evaluator,
        Err(code) => {
            eprintln!("guard-cloud-action: {code}");
            return ExitCode::from(2);
        }
    };
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        let response = match read_line(&mut input, &mut bytes) {
            Ok(Line::End) | Err(_) => break,
            Ok(Line::Request) => evaluator.evaluate(&bytes),
            Ok(Line::Oversize) => error_result(None, "limit"),
        };
        if serde_json::to_writer(&mut output, &response).is_err()
            || writeln!(output).is_err()
            || output.flush().is_err()
        {
            break;
        }
    }
    ExitCode::SUCCESS
}

/// `--binding-set <path>` and `--activation-public-key <hex>`, each falling
/// back to its environment variable. Any bad input stops the process before it
/// answers a request.
fn startup() -> Result<CloudActionEvaluator, &'static str> {
    let mut binding_set = std::env::var(BINDING_SET_ENV).ok();
    let mut activation_key = std::env::var(ACTIVATION_KEY_ENV).ok();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("usage")?;
        match flag.as_str() {
            "--binding-set" => binding_set = Some(value),
            "--activation-public-key" => activation_key = Some(value),
            _ => return Err("usage"),
        }
    }
    let path = binding_set.ok_or("usage")?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_BINDING_SET_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| "binding_set_unreadable")?;
    if bytes.len() as u64 > MAX_BINDING_SET_BYTES {
        return Err("binding_set_limit");
    }
    let bindings = load_binding_set(&bytes)?;
    let key = activation_key
        .as_deref()
        .map(parse_public_key)
        .transpose()?;
    Ok(CloudActionEvaluator::new(bindings, key))
}

/// One request line, capped at [`MAX_LINE_BYTES`]. The rest of an oversize
/// line is discarded unread so the next request starts on a line boundary.
fn read_line(input: &mut impl BufRead, bytes: &mut Vec<u8>) -> io::Result<Line> {
    let read = Read::take(&mut *input, MAX_LINE_BYTES as u64 + 1).read_until(b'\n', bytes)?;
    if read == 0 {
        return Ok(Line::End);
    }
    if bytes.len() <= MAX_LINE_BYTES || bytes.last() == Some(&b'\n') {
        return Ok(Line::Request);
    }
    loop {
        let buffered = input.fill_buf()?;
        let Some(end) = buffered.iter().position(|byte| *byte == b'\n') else {
            let all = buffered.len();
            input.consume(all);
            if all == 0 {
                return Ok(Line::Oversize);
            }
            continue;
        };
        input.consume(end + 1);
        return Ok(Line::Oversize);
    }
}

//! Local JSON-lines interface for a hosting service's cloud action decisions.
//!
//! Both `guard-cloud-action` and `hol-guard-runtime cloud-action` serve it, so
//! a host that installs the Guard wheel already has an evaluator.
use std::io::{self, BufRead, Read, Write};

use serde_json::Value;

use crate::cloud_action::{error_result, CloudActionEvaluator};
use crate::cloud_action_activation::parse_public_key;
use crate::cloud_action_binding::load_binding_set;
use crate::cloud_action_inspect::{inspect, inspect_error};

const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_BINDING_SET_BYTES: u64 = 16 * 1024 * 1024;
const BINDING_SET_ENV: &str = "GUARD_CLOUD_ACTION_BINDING_SET";
const ACTIVATION_KEY_ENV: &str = "GUARD_CLOUD_ACTION_ACTIVATION_PUBLIC_KEY";

enum Line {
    End,
    Request,
    Oversize,
}

/// Answers one result line per request line until stdin ends. Returns the
/// process exit code: 0 after a clean run, 2 when startup input is bad, in
/// which case nothing is read or answered. `program` prefixes the startup
/// error on stderr.
///
/// `inspect` as the first argument serves content inspection instead: it is
/// stateless, so it takes no binding set and no flags.
pub fn serve(program: &str, args: &[String]) -> i32 {
    if let [command, rest @ ..] = args {
        if command == "inspect" {
            if !rest.is_empty() {
                eprintln!("{program}: usage");
                return 2;
            }
            answer_lines(inspect, |code| inspect_error(None, code));
            return 0;
        }
    }
    let evaluator = match startup(args) {
        Ok(evaluator) => evaluator,
        Err(code) => {
            eprintln!("{program}: {code}");
            return 2;
        }
    };
    answer_lines(
        |bytes| evaluator.evaluate(bytes),
        |code| error_result(None, code),
    );
    0
}

fn answer_lines(answer: impl Fn(&[u8]) -> Value, refuse: impl Fn(&str) -> Value) {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        let response = match read_line(&mut input, &mut bytes) {
            Ok(Line::End) | Err(_) => break,
            Ok(Line::Request) => answer(&bytes),
            Ok(Line::Oversize) => refuse("limit"),
        };
        if serde_json::to_writer(&mut output, &response).is_err()
            || writeln!(output).is_err()
            || output.flush().is_err()
        {
            break;
        }
    }
}

/// `--binding-set <path>` and `--activation-public-key <hex>`, each falling
/// back to its environment variable. Any bad input stops the process before it
/// answers a request.
fn startup(args: &[String]) -> Result<CloudActionEvaluator, &'static str> {
    let mut binding_set = std::env::var(BINDING_SET_ENV).ok();
    let mut activation_key = std::env::var(ACTIVATION_KEY_ENV).ok();
    let mut args = args.iter().cloned();
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

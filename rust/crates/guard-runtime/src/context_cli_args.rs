//! The arguments of `hol-guard context`: `--guard-home` and `--json` anywhere,
//! one subcommand and that subcommand's own arguments.

use serde_json::{Map, Value};

/// What a parsed command line asks for.
pub(super) enum Parsed {
    Help(String),
    Run(Command),
}

pub(super) struct Command {
    pub(super) guard_home: Option<String>,
    pub(super) json: bool,
    pub(super) action: Action,
}

pub(super) enum Action {
    /// A control request: `status`, `installations`, `recheck`, `activate` or `stop`.
    Control(&'static str),
    /// A version request's input.
    Versions(Map<String, Value>),
    Usage,
    Lean {
        action: &'static str,
        limit: Option<i64>,
    },
}

const SUBCOMMANDS: [(&str, &str); 13] = [
    ("status", "Show requested and verified runtime availability without probing CIGAR"),
    ("runtimes", "Show the built-in engine without launching CIGAR"),
    ("check", "Schedule verification of the saved runtime in the background"),
    ("start", "Start the saved, explicitly enabled runtime after native verification"),
    ("off", "Cancel context work and persist opt-out; retain Guard approvals"),
    ("usage", "Show model usage per AI tool, read from each tool's own records on this computer"),
    ("lean", "Pick when Codex sums up older turns in a long session (on --limit N, off or status)"),
    ("jobs", "List built-in engine setup progress without starting CIGAR"),
    ("job", "Inspect one setup job"),
    ("switch", "Prepare a replacement while preserving the current running or off state; commit separately"),
    ("commit", "Commit a Ready selection; keep CIGAR off or acknowledge a running runtime interruption"),
    ("cancel", "Cancel a setup job and retain cleanup ownership"),
    ("recover", "Reconcile a job explicitly; never restore grants from progress records"),
];

pub(super) fn usage_line() -> String {
    let names: Vec<&str> = SUBCOMMANDS.iter().map(|(name, _)| *name).collect();
    format!(
        "usage: hol-guard context [-h] [--guard-home GUARD_HOME] [--json] {{{}}} ...",
        names.join(",")
    )
}

fn help() -> String {
    let mut text = format!(
        "{}\n\nInspect and control optional local CIGAR context assistance.\n\nsubcommands:\n",
        usage_line()
    );
    for (name, description) in SUBCOMMANDS {
        text.push_str(&format!("  {name:<10} {description}\n"));
    }
    text.push_str(
        "\noptions:\n  -h, --help            show this help message and exit\n  \
         --guard-home GUARD_HOME\n  --json\n",
    );
    text
}

fn lean_help() -> String {
    "usage: hol-guard context lean [-h] [--limit LIMIT] [{on,off,status}]\n\n\
     Sets Codex's model_auto_compact_token_limit to the size you pick. A smaller chat is not a \
     cheaper one: after each summary Codex reads again, at full price, the files it had already \
     read, so this can raise the bill. Guard sets no size of its own.\n\n\
     options:\n  --limit LIMIT  with on: sum up once a session passes this many tokens \
     (10,000 to 10,000,000)\n"
        .to_owned()
}

/// Read `argv`, the arguments after `context`.
pub(super) fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut guard_home = None;
    let mut json = false;
    let mut positional: Vec<String> = Vec::new();
    let mut options: Vec<(String, Option<String>)> = Vec::new();
    let mut help_asked = false;
    let mut items = argv.iter();
    while let Some(item) = items.next() {
        let (name, inline) = match item.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_owned())),
            _ => (item.as_str(), None),
        };
        match name {
            "-h" | "--help" => help_asked = true,
            "--json" if inline.is_none() => json = true,
            "--guard-home" | "--job-id" | "--generation" | "--limit" => {
                let value = match inline {
                    Some(value) => value,
                    None => items
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("argument {name}: expected one argument"))?,
                };
                if name == "--guard-home" {
                    guard_home = Some(value);
                } else {
                    options.push((name.to_owned(), Some(value)));
                }
            }
            "--acknowledge-reconnect" if inline.is_none() => {
                options.push((name.to_owned(), None));
            }
            _ if name.starts_with('-') && name.len() > 1 => {
                return Err(format!("unrecognized arguments: {item}"));
            }
            _ => positional.push(item.clone()),
        }
    }
    let Some((subcommand, rest)) = positional.split_first() else {
        if help_asked {
            return Ok(Parsed::Help(help()));
        }
        return Err("the following arguments are required: context_command".to_owned());
    };
    if help_asked {
        return Ok(Parsed::Help(if subcommand == "lean" {
            lean_help()
        } else {
            help()
        }));
    }
    let action = action(subcommand, rest, &options)?;
    Ok(Parsed::Run(Command {
        guard_home,
        json,
        action,
    }))
}

fn action(
    subcommand: &str,
    rest: &[String],
    options: &[(String, Option<String>)],
) -> Result<Action, String> {
    let option = |name: &str| {
        options
            .iter()
            .rev()
            .find(|(option, _)| option == name)
            .and_then(|(_, value)| value.clone())
    };
    let flag = |name: &str| options.iter().any(|(option, _)| option == name);
    let allow = |names: &[&str]| match options
        .iter()
        .find(|(option, _)| !names.contains(&option.as_str()))
    {
        Some((option, _)) => Err(format!("unrecognized arguments: {option}")),
        None => Ok(()),
    };
    let positionals = |count: usize, names: &str| {
        if rest.len() < count {
            Err(format!("the following arguments are required: {names}"))
        } else if rest.len() > count {
            Err(format!(
                "unrecognized arguments: {}",
                rest[count..].join(" ")
            ))
        } else {
            Ok(())
        }
    };
    let control = |kind: &'static str| {
        allow(&[])?;
        positionals(0, "")?;
        Ok(Action::Control(kind))
    };
    match subcommand {
        "status" => control("status"),
        "runtimes" => control("installations"),
        "check" => control("recheck"),
        "start" => control("activate"),
        "off" => control("stop"),
        "usage" => {
            allow(&[])?;
            positionals(0, "")?;
            Ok(Action::Usage)
        }
        "lean" => {
            allow(&["--limit"])?;
            if rest.len() > 1 {
                return Err(format!("unrecognized arguments: {}", rest[1..].join(" ")));
            }
            let action = match rest.first().map(String::as_str) {
                None | Some("status") => "status",
                Some("on") => "enable",
                Some("off") => "disable",
                Some(other) => {
                    return Err(format!(
                        "argument lean_action: invalid choice: '{other}' (choose from 'on', 'off', 'status')"
                    ))
                }
            };
            let limit = option("--limit")
                .map(|value| {
                    value
                        .parse::<i64>()
                        .map_err(|_| format!("argument --limit: invalid int value: '{value}'"))
                })
                .transpose()?;
            Ok(Action::Lean { action, limit })
        }
        "jobs" => {
            allow(&[])?;
            positionals(0, "")?;
            Ok(versions("jobs"))
        }
        "job" | "cancel" => {
            allow(&[])?;
            positionals(1, "job_id")?;
            let mut input = versions_input(subcommand);
            input.insert("job_id".into(), Value::from(rest[0].as_str()));
            Ok(Action::Versions(input))
        }
        "switch" => {
            allow(&["--job-id", "--generation"])?;
            let job_id = option("--job-id");
            let generation = option("--generation");
            let missing: Vec<&str> = [
                job_id.is_none().then_some("--job-id"),
                rest.is_empty().then_some("target_runtime_id"),
                generation.is_none().then_some("--generation"),
            ]
            .into_iter()
            .flatten()
            .collect();
            if !missing.is_empty() {
                return Err(format!(
                    "the following arguments are required: {}",
                    missing.join(", ")
                ));
            }
            positionals(1, "target_runtime_id")?;
            let mut input = versions_input("prepare_switch");
            input.insert("job_id".into(), Value::from(job_id));
            input.insert("target_runtime_id".into(), Value::from(rest[0].as_str()));
            input.insert("expected_generation".into(), Value::from(generation));
            Ok(Action::Versions(input))
        }
        "commit" => {
            allow(&["--generation", "--acknowledge-reconnect"])?;
            let generation = option("--generation");
            if rest.is_empty() || generation.is_none() {
                let missing: Vec<&str> = [
                    rest.is_empty().then_some("job_id"),
                    generation.is_none().then_some("--generation"),
                ]
                .into_iter()
                .flatten()
                .collect();
                return Err(format!(
                    "the following arguments are required: {}",
                    missing.join(", ")
                ));
            }
            positionals(1, "job_id")?;
            let mut input = versions_input("commit");
            input.insert("job_id".into(), Value::from(rest[0].as_str()));
            input.insert("expected_generation".into(), Value::from(generation));
            input.insert(
                "reconnect".into(),
                Value::Bool(flag("--acknowledge-reconnect")),
            );
            Ok(Action::Versions(input))
        }
        "recover" => {
            allow(&["--generation"])?;
            positionals(1, "job_id")?;
            let mut input = versions_input("recover");
            input.insert("job_id".into(), Value::from(rest[0].as_str()));
            if let Some(generation) = option("--generation") {
                input.insert("expected_generation".into(), Value::from(generation));
            }
            Ok(Action::Versions(input))
        }
        other => Err(format!(
            "argument context_command: invalid choice: '{other}'"
        )),
    }
}

fn versions(action: &str) -> Action {
    Action::Versions(versions_input(action))
}

fn versions_input(action: &str) -> Map<String, Value> {
    let mut input = Map::new();
    input.insert("action".into(), Value::from(action));
    input
}

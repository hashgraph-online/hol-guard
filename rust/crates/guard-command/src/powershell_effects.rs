//! Maps bounded PowerShell calls onto the POSIX executables Guard already
//! models, so existing read/write/delete/network floors apply unchanged.

use crate::powershell_parser::{PsArg, PsCall};

type Reason = &'static str;

const PARAMETER: Reason = "powershell_cmdlet_parameter_unsupported";
const ARGUMENTS: Reason = "powershell_static_method_arguments_unsupported";

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Read,
    Write,
    Append,
    OutFile,
    Remove,
    Copy,
    Move,
    Web,
    Launch,
}

fn cmdlet_kind(name: &str) -> Option<Kind> {
    Some(match name {
        "get-content" | "gc" | "cat" | "type" => Kind::Read,
        "set-content" | "sc" => Kind::Write,
        "add-content" | "ac" => Kind::Append,
        "out-file" => Kind::OutFile,
        "remove-item" | "ri" | "rm" | "del" | "erase" | "rd" | "rmdir" => Kind::Remove,
        "copy-item" | "cpi" | "cp" | "copy" => Kind::Copy,
        "move-item" | "mi" | "mv" | "move" => Kind::Move,
        "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm" => Kind::Web,
        "start-process" | "saps" | "start" => Kind::Launch,
        _ => return None,
    })
}

/// True for names that only PowerShell resolves to a modeled effect, so a
/// POSIX-exact parse of them should be redone with PowerShell semantics.
pub(crate) fn is_powershell_specific(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    cmdlet_kind(&lowered).is_some()
        && (lowered.contains('-')
            || matches!(
                lowered.as_str(),
                "iwr" | "irm" | "ri" | "cpi" | "mi" | "saps" | "sc" | "ac"
            ))
}

struct Bound {
    positionals: Vec<String>,
    named: Vec<(String, Option<String>)>,
}

impl Bound {
    fn has(&self, name: &str) -> bool {
        self.named.iter().any(|(key, _)| key == name)
    }
    fn value(&self, name: &str) -> Option<&str> {
        self.named
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| value.as_deref())
    }
}

fn bind(args: &[PsArg], values: &[&str], switches: &[&str]) -> Result<Bound, Reason> {
    let mut bound = Bound {
        positionals: Vec::new(),
        named: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        index += 1;
        if !arg.param {
            bound.positionals.push(arg.value.clone());
            continue;
        }
        let name = arg.value.trim_start_matches('-').to_ascii_lowercase();
        if values.contains(&name.as_str()) {
            let value = args.get(index).ok_or(PARAMETER)?;
            index += 1;
            bound.named.push((name, Some(value.value.clone())));
        } else if switches.contains(&name.as_str()) {
            if args.get(index).is_some_and(|next| next.attached) {
                return Err(PARAMETER);
            }
            bound.named.push((name, None));
        } else {
            return Err(PARAMETER);
        }
    }
    Ok(bound)
}

/// Positional slots bound in order, skipping slots already named.
fn fill(bound: &Bound, slots: &[&[&str]]) -> Result<Vec<Option<String>>, Reason> {
    let mut positional = bound.positionals.iter();
    let mut out = Vec::new();
    for names in slots {
        let named = names.iter().find_map(|name| bound.value(name));
        out.push(match named {
            Some(value) => Some(value.to_owned()),
            None => positional.next().cloned(),
        });
    }
    if positional.next().is_some() {
        return Err(PARAMETER);
    }
    Ok(out)
}

fn path_slot(slot: Option<String>) -> Result<String, Reason> {
    slot.filter(|path| !path.is_empty()).ok_or(PARAMETER)
}

pub(crate) fn canonicalize(call: &PsCall) -> Result<Vec<String>, Reason> {
    match call {
        PsCall::Command { name, args } => canonicalize_command(name, args),
        PsCall::Static {
            type_name,
            method,
            args,
        } => canonicalize_static(type_name, method, args),
    }
}

fn recursive_force(recurse: bool, force: bool) -> Option<String> {
    match (recurse, force) {
        (true, true) => Some("-rf".to_owned()),
        (true, false) => Some("-r".to_owned()),
        (false, true) => Some("-f".to_owned()),
        _ => None,
    }
}

fn canonicalize_command(name: &str, args: &[PsArg]) -> Result<Vec<String>, Reason> {
    let kind = cmdlet_kind(&name.to_ascii_lowercase());
    let path_names: &[&str] = &["path", "literalpath"];
    let mut tokens = Vec::new();
    match kind {
        Some(Kind::Read) => {
            let bound = bind(
                args,
                &[
                    "path",
                    "literalpath",
                    "encoding",
                    "totalcount",
                    "head",
                    "tail",
                    "readcount",
                ],
                &["raw"],
            )?;
            let mut paths: Vec<String> = bound
                .named
                .iter()
                .filter(|(key, _)| path_names.contains(&key.as_str()))
                .filter_map(|(_, value)| value.clone())
                .collect();
            paths.extend(bound.positionals.iter().cloned());
            if paths.is_empty() || paths.iter().any(String::is_empty) {
                return Err(PARAMETER);
            }
            tokens.push("cat".to_owned());
            tokens.extend(paths);
        }
        Some(Kind::Write | Kind::Append | Kind::OutFile) => {
            let out_file = kind == Some(Kind::OutFile);
            let bound = if out_file {
                bind(
                    args,
                    &["filepath", "path", "literalpath", "encoding", "width"],
                    &["append", "force", "noclobber", "nonewline"],
                )?
            } else {
                bind(
                    args,
                    &["path", "literalpath", "value", "encoding"],
                    &["force", "nonewline"],
                )?
            };
            let slots: &[&[&str]] = if out_file {
                &[&["filepath", "path", "literalpath"]]
            } else {
                &[&["path", "literalpath"], &["value"]]
            };
            let path = path_slot(fill(&bound, slots)?.remove(0))?;
            tokens.push("tee".to_owned());
            if kind == Some(Kind::Append) || bound.has("append") {
                tokens.push("-a".to_owned());
            }
            tokens.push(path);
        }
        Some(Kind::Remove) => {
            let bound = bind(args, &["path", "literalpath"], &["recurse", "force"])?;
            let mut paths: Vec<String> = bound
                .named
                .iter()
                .filter(|(key, _)| path_names.contains(&key.as_str()))
                .filter_map(|(_, value)| value.clone())
                .collect();
            paths.extend(bound.positionals.iter().cloned());
            if paths.is_empty() || paths.iter().any(String::is_empty) {
                return Err(PARAMETER);
            }
            tokens.push("rm".to_owned());
            tokens.extend(recursive_force(bound.has("recurse"), bound.has("force")));
            tokens.extend(paths);
        }
        Some(Kind::Copy | Kind::Move) => {
            let bound = bind(
                args,
                &["path", "literalpath", "destination"],
                &["recurse", "force"],
            )?;
            let mut slots = fill(&bound, &[&["path", "literalpath"], &["destination"]])?;
            let destination = path_slot(slots.remove(1))?;
            let source = path_slot(slots.remove(0))?;
            let copy = kind == Some(Kind::Copy);
            tokens.push(if copy { "cp" } else { "mv" }.to_owned());
            let recurse = copy && bound.has("recurse");
            tokens.extend(recursive_force(recurse, bound.has("force")));
            tokens.extend([source, destination]);
        }
        Some(Kind::Web) => {
            let bound = bind(
                args,
                &[
                    "uri",
                    "method",
                    "body",
                    "infile",
                    "outfile",
                    "contenttype",
                    "timeoutsec",
                    "useragent",
                    "maximumredirection",
                ],
                &["usebasicparsing"],
            )?;
            let url = path_slot(fill(&bound, &[&["uri"]])?.remove(0))?;
            tokens.push("curl".to_owned());
            if let Some(method) = bound.value("method") {
                tokens.extend(["-X".to_owned(), method.to_ascii_uppercase()]);
            }
            tokens.push(url);
            if let Some(body) = bound.value("body") {
                tokens.extend(["--data".to_owned(), body.to_owned()]);
            }
            if let Some(file) = bound.value("infile") {
                tokens.extend(["--data-binary".to_owned(), format!("@{file}")]);
            }
            if let Some(file) = bound.value("outfile") {
                tokens.extend(["-o".to_owned(), file.to_owned()]);
            }
        }
        Some(Kind::Launch) => return Err("powershell_process_launch_not_supported"),
        None => {
            tokens.push(name.to_owned());
            tokens.extend(args.iter().map(|arg| arg.value.clone()));
        }
    }
    Ok(tokens)
}

fn canonicalize_static(
    type_name: &str,
    method: &str,
    args: &[String],
) -> Result<Vec<String>, Reason> {
    let lowered = type_name.to_ascii_lowercase();
    let short = lowered.strip_prefix("system.").unwrap_or(&lowered);
    let method = method.to_ascii_lowercase();
    if matches!(short, "diagnostics.process") && method == "start" {
        return Err("powershell_process_launch_not_supported");
    }
    if short != "io.file" {
        return Err("powershell_static_method_unclassified");
    }
    let (executable, flag, arity): (&str, Option<&str>, usize) = match method.as_str() {
        "readalltext" | "readalllines" | "readallbytes" => ("cat", None, 1),
        "writealltext" | "writealllines" | "writeallbytes" => ("tee", None, 2),
        "appendalltext" => ("tee", Some("-a"), 2),
        "delete" => ("rm", None, 1),
        "copy" => ("cp", None, 2),
        "move" => ("mv", None, 2),
        _ => return Err("powershell_static_method_unclassified"),
    };
    if args.len() != arity {
        return Err(ARGUMENTS);
    }
    let mut paths = if matches!(executable, "tee") {
        vec![args[0].clone()]
    } else {
        args.to_vec()
    };
    if paths.iter().any(String::is_empty) {
        return Err(ARGUMENTS);
    }
    let mut tokens = vec![executable.to_owned()];
    tokens.extend(flag.map(str::to_owned));
    tokens.append(&mut paths);
    Ok(tokens)
}

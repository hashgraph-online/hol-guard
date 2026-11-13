//! Programs that are not package managers but install code from a registry
//! through one of their verbs: `dotnet add package` and `dotnet tool install`
//! fetch NuGet packages, `code --install-extension` fetches an editor
//! extension from a marketplace, and `python -m pip install` is pip under
//! another name. Each reaches the same package review as `npm install`.

use crate::CommandSegmentV1;

/// Editors that install marketplace extensions with `--install-extension`.
const EXTENSION_EDITORS: &[&str] = &[
    "code",
    "code-insiders",
    "codium",
    "cursor",
    "windsurf",
    "positron",
];

/// True when `segment` installs a package or extension from a registry
/// although its program is not one [`super::executable_is_package_tool`]
/// names.
pub(in crate::pretool) fn installs_from_registry(segment: &CommandSegmentV1) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let name = program_name(executable);
    let arguments: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    if name == "dotnet" {
        return dotnet_installs(&arguments);
    }
    if EXTENSION_EDITORS.contains(&name.as_str()) {
        return arguments.iter().any(|argument| {
            *argument == "--install-extension" || argument.starts_with("--install-extension=")
        });
    }
    python_module_installs(&name, &arguments)
}

/// The program's basename, lowercased, without a Windows launcher suffix.
fn program_name(executable: &str) -> String {
    let name = executable
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(executable)
        .to_ascii_lowercase();
    match name.rsplit_once('.') {
        Some((stem, "exe" | "cmd" | "bat")) => stem.to_owned(),
        _ => name,
    }
}

/// `dotnet add [<project>] package <id>`, `dotnet package add <id>`,
/// `dotnet tool install|update <id>` and `dotnet new install <template>`
/// each download from NuGet.
fn dotnet_installs(arguments: &[&str]) -> bool {
    match arguments.first().copied() {
        Some("add") => arguments
            .iter()
            .skip(1)
            .take(2)
            .any(|word| *word == "package"),
        Some("tool") => matches!(arguments.get(1).copied(), Some("install" | "update")),
        Some("new") => matches!(arguments.get(1).copied(), Some("install")),
        // The .NET 10 SDK's noun-first spelling of `add package`.
        Some("package") => matches!(arguments.get(1).copied(), Some("add" | "update")),
        _ => false,
    }
}

/// Python long options that take their value as the next argument.
const PYTHON_VALUE_OPTIONS: &[&str] = &["--check-hash-based-pycs"];

/// pip's general options that take their value as the next argument, and so
/// may sit between `pip` and its verb.
const PIP_VALUE_OPTIONS: &[&str] = &[
    "--python",
    "--log",
    "--log-file",
    "--keyring-provider",
    "--proxy",
    "--retries",
    "--timeout",
    "--exists-action",
    "--trusted-host",
    "--cert",
    "--client-cert",
    "--cache-dir",
    "--use-feature",
    "--use-deprecated",
    "--resume-retries",
];

/// `python -m pip install …` (any `python`, `python3`, `python3.12`, `py`)
/// runs pip's install verb. Options before `-m` are skipped with their values
/// (`-W ignore`, `-X utf8`), and `-mpip` reads as `-m pip`; `-m pip` with
/// another verb (`list`, `show`, `freeze`) installs nothing.
fn python_module_installs(name: &str, arguments: &[&str]) -> bool {
    let interpreter = name == "py"
        || name
            .strip_prefix("python")
            .is_some_and(|version| version.chars().all(|c| c.is_ascii_digit() || c == '.'));
    if !interpreter {
        return false;
    }
    let mut index = 0;
    let (module, rest) = loop {
        let Some(argument) = arguments.get(index).copied() else {
            return false;
        };
        if !argument.starts_with('-') {
            return false;
        }
        if argument.starts_with("--") {
            index += if PYTHON_VALUE_OPTIONS.contains(&argument) {
                2
            } else {
                1
            };
            continue;
        }
        // A short-option cluster such as `-Im` or `-Impip`: the first
        // option that takes a value consumes the rest of the cluster, or
        // the next argument when the cluster ends with it.
        match short_cluster_value(&argument[1..]) {
            ClusterValue::Flags => index += 1,
            ClusterValue::Command => return false,
            ClusterValue::Value { module, tail } => {
                let (value, next) = if tail.is_empty() {
                    let Some(value) = arguments.get(index + 1).copied() else {
                        return false;
                    };
                    (value, index + 2)
                } else {
                    (tail, index + 1)
                };
                if module {
                    break (value, next);
                }
                index = next;
            }
        }
    };
    if !matches!(module, "pip" | "pip3") {
        return false;
    }
    let mut words = arguments.iter().skip(rest);
    while let Some(word) = words.next() {
        if PIP_VALUE_OPTIONS.contains(word) {
            words.next();
        } else if !word.starts_with('-') {
            return matches!(*word, "install" | "download" | "wheel");
        }
    }
    false
}

/// What a Python short-option cluster (without its `-`) does with a value.
enum ClusterValue<'a> {
    /// Only flags that take no value.
    Flags,
    /// `-c`: the program is the next argument, not a module.
    Command,
    /// `-m`, `-W` or `-X`, with whatever of the cluster follows it.
    Value { module: bool, tail: &'a str },
}

fn short_cluster_value(cluster: &str) -> ClusterValue<'_> {
    for (at, letter) in cluster.char_indices() {
        let tail = &cluster[at + letter.len_utf8()..];
        match letter {
            'c' => return ClusterValue::Command,
            'm' => return ClusterValue::Value { module: true, tail },
            'W' | 'X' => {
                return ClusterValue::Value {
                    module: false,
                    tail,
                }
            }
            _ => {}
        }
    }
    ClusterValue::Flags
}

#[cfg(test)]
#[path = "registry_installers_tests.rs"]
mod tests;

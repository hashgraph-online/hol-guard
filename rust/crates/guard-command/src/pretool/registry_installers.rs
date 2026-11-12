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

/// `dotnet add [<project>] package <id>`, `dotnet tool install|update <id>`
/// and `dotnet new install <template>` each download from NuGet.
fn dotnet_installs(arguments: &[&str]) -> bool {
    match arguments.first().copied() {
        Some("add") => arguments
            .iter()
            .skip(1)
            .take(2)
            .any(|word| *word == "package"),
        Some("tool") => matches!(arguments.get(1).copied(), Some("install" | "update")),
        Some("new") => matches!(arguments.get(1).copied(), Some("install")),
        _ => false,
    }
}

/// `python -m pip install …` (any `python`, `python3`, `python3.12`, `py`)
/// runs pip's install verb. Options before `-m` are skipped; `-m pip` with
/// another verb (`list`, `show`, `freeze`) installs nothing.
fn python_module_installs(name: &str, arguments: &[&str]) -> bool {
    let interpreter = name == "py"
        || name
            .strip_prefix("python")
            .is_some_and(|version| version.chars().all(|c| c.is_ascii_digit() || c == '.'));
    if !interpreter {
        return false;
    }
    let Some(module_at) = arguments.iter().position(|argument| *argument == "-m") else {
        return false;
    };
    if arguments[..module_at]
        .iter()
        .any(|argument| !argument.starts_with('-'))
    {
        return false;
    }
    let module = arguments.get(module_at + 1).copied().unwrap_or_default();
    if !matches!(module, "pip" | "pip3") {
        return false;
    }
    arguments
        .iter()
        .skip(module_at + 2)
        .find(|argument| !argument.starts_with('-'))
        .is_some_and(|verb| matches!(*verb, "install" | "download" | "wheel"))
}

#[cfg(test)]
#[path = "registry_installers_tests.rs"]
mod tests;

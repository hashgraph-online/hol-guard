//! Package specs npm's configuration adds to an `npx` launch.
//!
//! A spec that was read is the package the review names. A spec that could
//! not be read leaves the package unnamed, which is a block rather than a
//! review of the runner on the command line. Spec values are not logged.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use crate::env_wrapper::parse_env_wrapper;
use crate::package_intent_common::PackageIntentTarget;

use super::*;

pub(crate) fn unidentified_npm_package_target() -> PackageIntentTarget {
    PackageIntentTarget {
        ecosystem: "npm".to_owned(),
        package_name: None,
        raw_spec: String::new(),
        requested_specifier: None,
        source_url: None,
        source_kind: None,
        source_repository: None,
        source_revision_kind: None,
        source_identity: None,
        source_invalid_reason: Some(NPM_CONFIG_PACKAGE_UNIDENTIFIED.to_owned()),
        alias: None,
        dependency_group: None,
        extras: Vec::new(),
        editable: false,
    }
}

/// Packages this segment's `npx` installs from npm configuration.
///
/// A segment that is not `npx` adds nothing. Assignments on `raw` are the
/// environment npm reads; `env -` and an unreadable config file leave the
/// package unnamed.
pub(crate) fn configured_packages_for_segment(
    raw: &[String],
    normalized: &[String],
    environment: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    home: Option<&Path>,
) -> NpmConfiguredPackages {
    let Some(command) = normalized.first() else {
        return NpmConfiguredPackages::Absent;
    };
    if launch_name(command) != "npx" {
        return NpmConfiguredPackages::Absent;
    }
    let Some(effective) = environment_after_wrappers(raw, environment) else {
        return NpmConfiguredPackages::Unnamed;
    };
    let Some(cwd) = cwd.filter(|cwd| cwd.is_absolute()) else {
        // The shell could not place this launch, so there is no project
        // `.npmrc` to read. An environment `package` value still names the
        // install. A `userconfig` or `globalconfig` redirect might too, and
        // without a directory its path cannot be resolved, so that package
        // stays unnamed. Nothing else is a package setting.
        return packages_from_environment(&effective).unwrap_or_else(|| {
            let settings = environment_settings(&effective);
            if settings.contains_key("userconfig") || settings.contains_key("globalconfig") {
                NpmConfiguredPackages::Unnamed
            } else {
                NpmConfiguredPackages::Absent
            }
        });
    };
    npm_configured_exec_packages(&effective, cwd, home)
}

/// Specs `npm exec` installs from `environment` and the config files `cwd`
/// loads. An environment `package` value wins over every file.
pub(crate) fn npm_configured_exec_packages(
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    home: Option<&Path>,
) -> NpmConfiguredPackages {
    if !cwd.is_absolute() {
        return NpmConfiguredPackages::Unnamed;
    }
    let settings = environment_settings(environment);
    if let Some(value) = settings.get("package") {
        return match package_spec(value, environment) {
            Ok(Some(spec)) => NpmConfiguredPackages::Named(vec![spec]),
            Ok(None) => NpmConfiguredPackages::Absent,
            Err(()) => NpmConfiguredPackages::Unnamed,
        };
    }
    let mut files: Vec<PathBuf> = cwd
        .ancestors()
        .map(|folder| folder.join(".npmrc"))
        .collect();
    match settings.get("userconfig") {
        Some(value) => match resolved_config_path(cwd, home, value, environment) {
            Some(path) => files.push(path),
            None => return NpmConfiguredPackages::Unnamed,
        },
        None => {
            if let Some(home) = home.filter(|home| home.is_absolute()) {
                files.push(home.join(".npmrc"));
            } else if let Some(home) = environment
                .get("HOME")
                .map(PathBuf::from)
                .filter(|home| home.is_absolute())
            {
                files.push(home.join(".npmrc"));
            } else {
                return NpmConfiguredPackages::Unnamed;
            }
        }
    }
    if let Some(value) = settings.get("globalconfig") {
        match resolved_config_path(cwd, home, value, environment) {
            Some(path) => files.push(path),
            None => return NpmConfiguredPackages::Unnamed,
        }
    }
    collect_file_specs(&files, environment, cwd, home, &settings)
}

fn packages_from_environment(
    environment: &BTreeMap<String, String>,
) -> Option<NpmConfiguredPackages> {
    let settings = environment_settings(environment);
    let value = settings.get("package")?;
    Some(match package_spec(value, environment) {
        Ok(Some(spec)) => NpmConfiguredPackages::Named(vec![spec]),
        Ok(None) => NpmConfiguredPackages::Absent,
        Err(()) => NpmConfiguredPackages::Unnamed,
    })
}

fn collect_file_specs(
    files: &[PathBuf],
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    home: Option<&Path>,
    settings: &BTreeMap<String, String>,
) -> NpmConfiguredPackages {
    let mut specs = Vec::new();
    let mut pending = files.to_vec();
    let mut seen = BTreeMap::<String, ()>::new();
    let mut redirects_followed = 0usize;
    while let Some(path) = pending.pop() {
        let key = path.to_string_lossy().into_owned();
        if seen.insert(key, ()).is_some() {
            continue;
        }
        let scan = match scan_npmrc(&path, environment) {
            Some(scan) => scan,
            None => return NpmConfiguredPackages::Unnamed,
        };
        specs.extend(scan.0);
        for (name, value) in scan.1 {
            if settings.contains_key(&name) {
                continue;
            }
            redirects_followed += 1;
            if redirects_followed > 32 {
                return NpmConfiguredPackages::Unnamed;
            }
            match resolved_config_path(cwd, home, &value, environment) {
                Some(redirect) => pending.push(redirect),
                None => return NpmConfiguredPackages::Unnamed,
            }
        }
    }
    if specs.is_empty() {
        NpmConfiguredPackages::Absent
    } else {
        NpmConfiguredPackages::Named(dedup_specs(specs))
    }
}

type NpmrcScan = (Vec<String>, Vec<(String, String)>);

fn scan_npmrc(path: &Path, environment: &BTreeMap<String, String>) -> Option<NpmrcScan> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return Some((Vec::new(), Vec::new()));
        }
        Err(_) => return None,
    };
    // A FIFO or directory is not opened: a blocking open would wait for a
    // writer, and the byte cap would never run.
    if !metadata.is_file() || metadata.len() > NPMRC_READ_LIMIT {
        return None;
    }
    let mut bytes = Vec::new();
    let read = fs::File::open(path)
        .and_then(|file| file.take(NPMRC_READ_LIMIT + 1).read_to_end(&mut bytes));
    if read.is_err() || !u64::try_from(bytes.len()).is_ok_and(|length| length <= NPMRC_READ_LIMIT) {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut specs = Vec::new();
    let mut redirects = Vec::new();
    for line in text.split(['\n', '\r']) {
        let Some((name, value)) = npmrc_assignment(line) else {
            continue;
        };
        let name = if name.contains("${") {
            expand_npm_value(&name, environment)?.to_lowercase()
        } else {
            name
        };
        if !PACKAGE_SETTINGS.contains(&name.as_str()) {
            continue;
        }
        let value = value?;
        if name == "package" {
            match package_spec(&value, environment) {
                Ok(Some(spec)) => specs.push(spec),
                Ok(None) => {}
                Err(()) => return None,
            }
            continue;
        }
        redirects.push((name, value));
    }
    Some((specs, redirects))
}

fn npmrc_assignment(line: &str) -> Option<(String, Option<String>)> {
    let text = line.trim();
    if text.is_empty()
        || text.starts_with(['#', ';'])
        || (text.starts_with('[') && text.ends_with(']'))
    {
        return None;
    }
    let (raw_name, raw_value) = match text.split_once('=') {
        Some((name, value)) => (name.trim(), Some(value.trim().to_owned())),
        None => (text, None),
    };
    let trimmed = raw_name.trim_matches(['"', '\'']).trim();
    let name = trimmed.strip_suffix("[]").unwrap_or(trimmed).to_lowercase();
    if name.is_empty() {
        return None;
    }
    Some((name, raw_value))
}

fn package_spec(value: &str, environment: &BTreeMap<String, String>) -> Result<Option<String>, ()> {
    let expanded = expand_npm_value(value, environment).ok_or(())?;
    let spec = unquote(expanded.trim());
    if spec.is_empty() {
        return Ok(None);
    }
    if spec.starts_with('-')
        || spec
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || spec.contains('#')
        || spec.contains(';')
    {
        return Err(());
    }
    Ok(Some(spec.to_owned()))
}

fn unquote(token: &str) -> &str {
    let bytes = token.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[0] == *bytes.last().unwrap_or(&0)
    {
        return token[1..token.len() - 1].trim();
    }
    token
}

fn expand_npm_value(value: &str, environment: &BTreeMap<String, String>) -> Option<String> {
    if !value.contains("${") {
        return Some(value.to_owned());
    }
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '$' && chars.get(index + 1) == Some(&'{') {
            let start = index + 2;
            let mut end = start;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            if end == start || chars.get(end) != Some(&'}') {
                return None;
            }
            let name: String = chars[start..end].iter().collect();
            if !name
                .starts_with(|character: char| character.is_ascii_alphabetic() || character == '_')
            {
                return None;
            }
            out.push_str(environment.get(&name)?);
            index = end + 1;
            continue;
        }
        out.push(chars[index]);
        index += 1;
    }
    if out.contains("${") {
        None
    } else {
        Some(out)
    }
}

fn resolved_config_path(
    cwd: &Path,
    home: Option<&Path>,
    value: &str,
    environment: &BTreeMap<String, String>,
) -> Option<PathBuf> {
    let expanded = expand_npm_value(value, environment)?;
    config_path(cwd, home, &expanded)
}

fn environment_settings(environment: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut settings = BTreeMap::new();
    for (name, value) in environment {
        if value.is_empty() {
            continue;
        }
        if let Some(setting) = npm_setting_name(name) {
            settings.insert(setting, value.clone());
        }
    }
    settings
}

fn environment_after_wrappers(
    raw: &[String],
    environment: &BTreeMap<String, String>,
) -> Option<BTreeMap<String, String>> {
    if raw.iter().any(|token| token.contains('\0')) {
        return None;
    }
    let mut env = environment.clone();
    let mut index = 0;
    while index < raw.len() && env_assignment_token(&raw[index]) {
        if !apply_assignment(&mut env, &raw[index]) {
            return None;
        }
        index += 1;
    }
    while index < raw.len() && matches!(launch_name(&raw[index]), "sudo" | "command" | "time") {
        if launch_name(&raw[index]) == "sudo" {
            index = skip_sudo(raw, index + 1)?;
        } else {
            index += 1;
            while index < raw.len() && raw[index].starts_with('-') {
                index += 1;
            }
        }
        while index < raw.len() && env_assignment_token(&raw[index]) {
            if !apply_assignment(&mut env, &raw[index]) {
                return None;
            }
            index += 1;
        }
    }
    // Each `env` runs the next command, and that command may be `env` again.
    // `env FOO=1 env npm_config_package=left-pad npx tsx` installs left-pad.
    let mut ignored_environment = false;
    let mut rest = raw[index..].to_vec();
    while rest
        .first()
        .is_some_and(|token| launch_name(token) == "env")
    {
        let parsed = parse_env_wrapper(&rest[1..], Some(&env), None);
        if !parsed.complete || parsed.error.is_some() {
            return None;
        }
        if let Some(pairs) = parsed.effective_environment {
            env = pairs.into_iter().collect();
        }
        ignored_environment |= parsed.option_effects.ignore_environment;
        // `executable_argv` is a suffix of `rest` with this `env` removed.
        if parsed.executable_argv.len() >= rest.len() {
            return None;
        }
        rest = parsed.executable_argv;
    }
    if ignored_environment && !environment_settings(&env).contains_key("package") {
        // npm's home, and so its user config, is no longer the launch home.
        return None;
    }
    Some(env)
}

fn apply_assignment(environment: &mut BTreeMap<String, String>, token: &str) -> bool {
    if token.contains('`') || token.contains("$(") {
        return false;
    }
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    environment.insert(name.to_owned(), value.to_owned());
    true
}

fn env_assignment_token(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn skip_sudo(tokens: &[String], mut index: usize) -> Option<usize> {
    const VALUE_OPTIONS: [&str; 7] = ["-u", "-g", "-h", "-p", "-r", "-t", "-C"];
    while index < tokens.len() && tokens[index].starts_with('-') {
        let token = &tokens[index];
        if VALUE_OPTIONS.contains(&token.as_str()) {
            if index + 1 >= tokens.len() {
                return None;
            }
            index += 2;
            continue;
        }
        if token.starts_with("--")
            && !token.contains('=')
            && !matches!(token.as_str(), "--" | "--preserve-env" | "--login")
        {
            return None;
        }
        index += 1;
    }
    Some(index)
}

fn launch_name(token: &str) -> &str {
    Path::new(token)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(token)
}

fn dedup_specs(specs: Vec<String>) -> Vec<String> {
    let mut unique = Vec::new();
    for spec in specs {
        if !unique.contains(&spec) {
            unique.push(spec);
        }
    }
    unique
}

//! Whether npm's own configuration adds a package to an `npx` launch.
//!
//! `npm exec`, and so `npx`, takes the packages it installs from its
//! `package` setting (`const packages = this.npm.config.get('package')` in
//! `lib/commands/exec.js`), not only from `--package` on the command line.
//! npm reads that setting from the environment and from every `.npmrc` it
//! loads. When the setting names a package, libnpmexec skips the walk through
//! the project's `node_modules/.bin` (`needPackageCommandSwap` is false),
//! installs what the setting names, and runs the command with that package's
//! bins first on `PATH`.
//!
//! The routine-runner verdict reads the command alone, so the parser asks this
//! module before it lets that verdict stand for `npx`. Only setting names are
//! read: a value is never returned or logged, and is looked at only when it
//! names another configuration file to follow.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use super::*;

/// The largest `.npmrc` read; a larger one keeps the package review. The
/// same bound `verified_npm` puts on the config files it reads, kept here
/// because the parser is also compiled into `guard-command-build`, which does
/// not carry that module.
pub(super) const NPMRC_READ_LIMIT: u64 = 64 * 1024;

/// Settings that add a package, or that move npm to a configuration file this
/// check would otherwise not read. An `.npmrc` line or a command assignment
/// naming any of them keeps the package review. In the launch environment
/// only `package` does: the other two are followed to the file they name.
const PACKAGE_SETTINGS: [&str; 3] = ["package", "userconfig", "globalconfig"];

/// npm's name for the setting an `npm_config_*` environment name sets,
/// mirroring `loadEnv` in `@npmcli/config`: the prefix matches in any case,
/// every underscore after the first character becomes a hyphen, and the rest
/// is lowercased. Registry-scoped (`//host/:key`) names are never a package
/// setting, so they answer `None` like any other name.
pub(super) fn npm_setting_name(name: &str) -> Option<String> {
    let prefix = name.get(.."npm_config_".len())?;
    if !prefix.eq_ignore_ascii_case("npm_config_") {
        return None;
    }
    let rest = &name["npm_config_".len()..];
    let mut characters = rest.chars();
    let first = characters.next()?;
    if rest.starts_with("//") {
        return None;
    }
    Some(format!("{first}{}", characters.as_str().replace('_', "-")).to_lowercase())
}

/// Whether a command segment assigns one of [`PACKAGE_SETTINGS`] itself, as
/// in `npm_config_package=… npx tsx` or `env npm_config_package=… npx tsx`.
/// The parser strips those assignments before it reads the runner, so they
/// are read here from the segment as written. Any token in the segment
/// counts, which can only add a review.
pub(super) fn assigns_npm_package_setting(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        token
            .split_once('=')
            .and_then(|(name, _)| npm_setting_name(name))
            .is_some_and(|setting| PACKAGE_SETTINGS.contains(&setting.as_str()))
    })
}

/// The setting a `.npmrc` line assigns, or `None` for a blank line, a
/// comment or a section header.
fn npmrc_setting_name(line: &str) -> Option<String> {
    let text = line.trim();
    if text.is_empty()
        || text.starts_with(['#', ';'])
        || (text.starts_with('[') && text.ends_with(']'))
    {
        return None;
    }
    let name = text
        .split_once('=')
        .map_or(text, |(head, _)| head)
        .trim()
        .trim_matches(['"', '\''])
        .trim();
    // npm's ini parser reads `package[]=` as an entry of the `package` array.
    Some(name.strip_suffix("[]").unwrap_or(name).to_lowercase())
}

/// Whether the `.npmrc` at `path` could add a package to `npx`.
///
/// A missing file adds nothing. Anything else that is not a regular file
/// keeps the review without being opened, so a FIFO cannot stall the parser.
/// So does a file that cannot be read or is larger than `NPMRC_READ_LIMIT`.
/// npm expands `${VAR}` inside setting names, so a name built that way keeps
/// the review too: it could expand to `package`.
pub(super) fn npmrc_sets_package(path: &Path) -> bool {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return false;
        }
        Err(_) => return true,
    };
    if !metadata.is_file() || metadata.len() > NPMRC_READ_LIMIT {
        return true;
    }
    let mut bytes = Vec::new();
    let read = fs::File::open(path)
        .and_then(|file| file.take(NPMRC_READ_LIMIT + 1).read_to_end(&mut bytes));
    if read.is_err() || !u64::try_from(bytes.len()).is_ok_and(|length| length <= NPMRC_READ_LIMIT) {
        return true;
    }
    let text = String::from_utf8_lossy(&bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    // npm's ini parser, like Python's `splitlines`, also ends a line at a bare `\r`.
    text.split(['\n', '\r'])
        .filter_map(npmrc_setting_name)
        .any(|name| name.contains("${") || PACKAGE_SETTINGS.contains(&name.as_str()))
}

/// The file a path setting names, resolved the way npm resolves it against
/// the launch directory, or `None` when npm would expand a variable in it
/// first.
fn config_path(cwd: &Path, home: Option<&Path>, value: &str) -> Option<PathBuf> {
    if value.contains("${") {
        return None;
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return home.map(|home| home.join(rest));
    }
    if value.starts_with('~') {
        return None;
    }
    Some(cwd.join(value))
}

/// Whether npm's configuration, as `npx` loads it from `cwd` with
/// `environment`, names a package for `npm exec` to install.
///
/// npm reads the project `.npmrc` from the nearest folder above `cwd` that
/// holds a `package.json` or a `node_modules`, or from the workspace root
/// above that. Every `.npmrc` from `cwd` up is a superset of both. The user
/// config is `npm_config_userconfig` when set and `~/.npmrc` otherwise; a
/// global config named by `npm_config_globalconfig` is read too.
///
/// Out of scope: the global `npmrc` under npm's install prefix when nothing
/// names it, and npm's builtin `npmrc`. Both sit beside the npm install
/// itself, and finding them means resolving which node and npm would run.
pub(super) fn npm_config_adds_package(
    environment: &BTreeMap<String, String>,
    cwd: &Path,
    home: Option<&Path>,
) -> bool {
    if !cwd.is_absolute() {
        return true;
    }
    let mut settings: BTreeMap<String, &str> = BTreeMap::new();
    for (name, value) in environment {
        // npm skips an empty value.
        if value.is_empty() {
            continue;
        }
        if let Some(setting) = npm_setting_name(name) {
            settings.insert(setting, value.as_str());
        }
    }
    if settings.contains_key("package") {
        return true;
    }
    let mut files: Vec<PathBuf> = cwd
        .ancestors()
        .map(|folder| folder.join(".npmrc"))
        .collect();
    let user_config = match settings.get("userconfig") {
        Some(value) => config_path(cwd, home, value),
        None => home.map(|home| home.join(".npmrc")),
    };
    let Some(user_config) = user_config else {
        return true;
    };
    files.push(user_config);
    if let Some(value) = settings.get("globalconfig") {
        let Some(global_config) = config_path(cwd, home, value) else {
            return true;
        };
        files.push(global_config);
    }
    files.iter().any(|path| npmrc_sets_package(path))
}

/// Whether npm's configuration makes this `npx` launch install a package the
/// command never names. `segments_assign_setting` reports an assignment
/// inside the command itself. `environment` is the launch environment, or the
/// process's own when absent, the same fallback the segment model uses;
/// `home_dir` stands in for its `HOME` when that is missing.
pub(super) fn npx_config_adds_package(
    intent: &PackageIntent,
    segments_assign_setting: bool,
    environment: Option<&BTreeMap<String, String>>,
    home_dir: Option<&Path>,
) -> bool {
    if intent.package_manager != "npx" {
        return false;
    }
    if segments_assign_setting {
        return true;
    }
    let inherited;
    let environment = match environment {
        Some(environment) => environment,
        None => {
            inherited = std::env::vars().collect::<BTreeMap<_, _>>();
            &inherited
        }
    };
    let home = environment
        .get("HOME")
        .map(Path::new)
        .filter(|home| home.is_absolute())
        .or(home_dir);
    intent.local_executions.iter().any(|execution| {
        npm_config_adds_package(environment, Path::new(&execution.effective_cwd), home)
    })
}

use super::*;
use std::collections::BTreeMap;

const DENIED_ENV_KEYS: &[&str] = &[
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "BASH_ENV",
    "DATABASE_URL",
    "DOCKER_CONFIG",
    "DOCKER_HOST",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "ENV",
    "GIT_ASKPASS",
    "GNUPGHOME",
    "KRB5CCNAME",
    "KUBECONFIG",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "MONGODB_URI",
    "MYSQL_PWD",
    "NODE_AUTH_TOKEN",
    "NPM_CONFIG_USERCONFIG",
    "PGPASSWORD",
    "PIP_CONFIG_FILE",
    "PYTHONBREAKPOINT",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONWARNINGS",
    "REDIS_URL",
    "SSH_ASKPASS",
    "SSH_AUTH_SOCK",
    "ZDOTDIR",
];
const PROXY_ENV_KEYS: &[&str] = &[
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];
const SAFE_ENV_KEYS: &[&str] = &[
    "CI",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLORTERM",
    "COLUMNS",
    "FORCE_COLOR",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "LANG",
    "LANGUAGE",
    "LINES",
    "LOGNAME",
    "NO_COLOR",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONHASHSEED",
    "PYTHONIOENCODING",
    "PYTHONUNBUFFERED",
    "PYTHONUTF8",
    "SOURCE_DATE_EPOCH",
    "TERM",
    "TERM_PROGRAM",
    "TERM_PROGRAM_VERSION",
    "TF_BUILD",
    "TZ",
    "USER",
    "VIRTUAL_ENV_PROMPT",
];

static SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|_)(?:API_?KEY|AUTH(?:ORIZATION)?|BEARER|COOKIE|CREDENTIALS?|DSN|KEY(?:_?ID)?|PASSWORD|PRIVATE_?KEY|SECRET|SESSION|TOKEN)(?:_|$)").unwrap()
});

/// The version a manager's shims dispatch to, named by its own setting.
/// `~/.pyenv/shims/python` and its kind pick an interpreter from the version
/// named here before any file; dropping the setting runs a different version
/// inside the sandbox than the caller asked for outside it. Only the managers
/// whose installs a run may be granted, and only the name of a version: the
/// settings that move a manager's root instead name a directory and stay out.
const VERSION_SELECTORS: &[&str] = &[
    "GOENV_VERSION",
    "JENV_VERSION",
    "NODENV_VERSION",
    "PYENV_VERSION",
    "RBENV_VERSION",
    "TFENV_VERSION",
];

/// Whether `key` names a version for a manager's shims to resolve.
fn version_selector(key: &str) -> bool {
    VERSION_SELECTORS.contains(&key)
        || (key.starts_with("ASDF_") && key.ends_with("_VERSION") && key.len() > 13)
}

/// Whether `value` is a version a manager can name, and nothing else: one or
/// more plain names, never a path, a flag or anything a shell would act on.
fn version_names(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.split([' ', ':']).all(|name| {
            !name.is_empty()
                && !name.starts_with('-')
                && name
                    .chars()
                    .all(|letter| letter.is_ascii_alphanumeric() || "._-+".contains(letter))
        })
}

/// Whether [`filter`] can pass the caller's setting `key` to the run; it
/// drops every other name.
pub(crate) fn forwarded_setting(key: &str) -> bool {
    matches!(key, "PYTHONPATH" | "VIRTUAL_ENV")
        || SAFE_ENV_KEYS.contains(&key)
        || version_selector(key)
        || key.starts_with("LC_")
}

pub(super) fn filter(
    source: &BTreeMap<String, String>,
    workspace: &Path,
    cwd: &Path,
    private_home: &Path,
    private_tmp: &Path,
    allowed: &[PathBuf],
    user_site: bool,
) -> Result<BTreeMap<String, String>, RestrictedPytestError> {
    let mut result = BTreeMap::new();
    for (key, value) in source {
        if DENIED_ENV_KEYS.contains(&key.as_str())
            || PROXY_ENV_KEYS.contains(&key.as_str())
            || SECRET.is_match(key)
            || key.contains('\0')
            || value.contains('\0')
            || ["HOME", "PATH", "TEMP", "TMP", "TMPDIR"].contains(&key.as_str())
        {
            continue;
        }
        if key == "PYTHONPATH" {
            result.insert(key.clone(), restricted_pythonpath(value, workspace, cwd)?);
        } else if key == "VIRTUAL_ENV" {
            if let Ok(resolved) = expand_user(Path::new(value)).canonicalize() {
                if path_is_within(&resolved, workspace) {
                    result.insert(key.clone(), resolved.to_string_lossy().into_owned());
                }
            }
        } else if version_selector(key) {
            if version_names(value) {
                result.insert(key.clone(), value.clone());
            }
        } else if SAFE_ENV_KEYS.contains(&key.as_str()) || key.starts_with("LC_") {
            result.insert(key.clone(), value.clone());
        }
    }
    let mut dirs = Vec::new();
    for executable in allowed {
        let directory = executable.parent().unwrap_or(Path::new("/"));
        let value = directory.to_string_lossy().into_owned();
        if !dirs.contains(&value) {
            dirs.push(value);
        }
    }
    for (key, value) in [
        ("HOME", private_home.to_string_lossy().into_owned()),
        ("PATH", dirs.join(":")),
        ("PWD", cwd.to_string_lossy().into_owned()),
        ("TEMP", private_tmp.to_string_lossy().into_owned()),
        ("TMP", private_tmp.to_string_lossy().into_owned()),
        ("TMPDIR", private_tmp.to_string_lossy().into_owned()),
    ] {
        result.insert(key.to_owned(), value);
    }
    // A workspace run (no allowed executables) reaches `pnpm` and `yarn`
    // through Corepack, which reads the package manager it runs from a cache
    // below the real HOME. The plan grants that cache read-only; Corepack must
    // neither fetch (there is no network) nor pin a version in the workspace.
    if allowed.is_empty() {
        if let Some(cache) = super::toolchains::host_corepack_home() {
            let cache = cache.to_string_lossy().into_owned();
            for (key, value) in [
                ("COREPACK_HOME", cache.as_str()),
                ("COREPACK_ENABLE_AUTO_PIN", "0"),
                ("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0"),
                ("COREPACK_ENABLE_NETWORK", "0"),
                ("COREPACK_DEFAULT_TO_LATEST", "0"),
            ] {
                result.insert(key.to_owned(), value.to_owned());
            }
        }
    }
    // A Go build reads its dependencies from the module cache below the real
    // HOME, which the plan grants read-only, and writes its build cache into
    // the private directory. There is no network, so a toolchain switch or a
    // module download would only fail late; refusing both reports it at once.
    if allowed.is_empty() {
        if let Some(cache) = super::toolchains::host_go_module_cache() {
            result.insert(
                "GOMODCACHE".to_owned(),
                cache.to_string_lossy().into_owned(),
            );
        }
        for (key, value) in [
            ("GOCACHE", private_tmp.join("go-build")),
            ("GOPATH", private_tmp.join("go")),
        ] {
            result.insert(key.to_owned(), value.to_string_lossy().into_owned());
        }
        for (key, value) in [("GOPROXY", "off"), ("GOTOOLCHAIN", "local")] {
            result.insert(key.to_owned(), value.to_owned());
        }
    }
    // A Cargo build compiles the crate sources in the host registry, which the
    // plan grants read-only and links into a private `CARGO_HOME` cargo can
    // take its locks in. The toolchain resolves through the real rustup
    // installation, and the offline flag turns a missing crate into an
    // immediate error rather than a blocked fetch. A host that has fetched no
    // crate yet still gets all three: the private directory is empty rather
    // than absent, and a run whose toolchain lives in rustup needs
    // `RUSTUP_HOME` to find it at all.
    if allowed.is_empty() {
        result.insert(
            "CARGO_HOME".to_owned(),
            cargo_home(private_tmp).to_string_lossy().into_owned(),
        );
        result.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
        if let Some(rustup) = super::toolchains::host_rustup_home() {
            result.insert(
                "RUSTUP_HOME".to_owned(),
                rustup.to_string_lossy().into_owned(),
            );
        }
    }
    // A linked user site is read through the private HOME; otherwise it stays off.
    if !user_site {
        result.insert("PYTHONNOUSERSITE".to_owned(), "1".to_owned());
    }
    Ok(result)
}

/// The private `CARGO_HOME` a contained run uses. Cargo writes its locks and
/// its global cache at the top of this directory; the host's fetched crates
/// are linked in below it.
pub(super) fn cargo_home(private_tmp: &Path) -> PathBuf {
    private_tmp.join("cargo")
}

#[cfg(test)]
#[path = "environment_tests.rs"]
mod tests;

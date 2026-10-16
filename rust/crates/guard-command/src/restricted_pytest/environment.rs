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

/// Whether [`filter`] can pass the caller's setting `key` to the run; it
/// drops every other name.
pub(crate) fn forwarded_setting(key: &str) -> bool {
    matches!(key, "PYTHONPATH" | "VIRTUAL_ENV")
        || SAFE_ENV_KEYS.contains(&key)
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
    // A linked user site is read through the private HOME; otherwise it stays off.
    if !user_site {
        result.insert("PYTHONNOUSERSITE".to_owned(), "1".to_owned());
    }
    Ok(result)
}

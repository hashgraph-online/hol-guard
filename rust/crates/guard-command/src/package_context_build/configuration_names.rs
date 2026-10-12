//! Per-manager configuration file names, user-level configuration locations
//! and the text patterns that mark dynamic configuration.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::codex_output_py::PyPath;

use super::fs::Fs;
use super::Built;

pub(super) const JS_MANAGERS: &[&str] = &["bun", "bunx", "npm", "npx", "pnpm", "yarn"];
pub(super) const PYTHON_MANAGERS: &[&str] =
    &["pip", "pip3", "pipenv", "pipx", "poetry", "uv", "uvx"];
pub(super) const RUBY_MANAGERS: &[&str] = &["bundle", "bundler", "gem"];

pub(super) struct Names {
    pub(super) registry: &'static [&'static str],
    pub(super) workspace: &'static [&'static str],
    pub(super) hooks: &'static [&'static str],
}

/// Python `\s` also matches the ASCII separators U+001C..U+001F.
pub(super) fn dynamic_code_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?:require|import)[\s\x1c-\x1f]*\(").expect("dynamic code pattern")
    })
}

pub(super) fn env_reference_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("environment reference pattern")
    })
}

pub(super) fn npm_dynamic_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?im)^[\s\x1c-\x1f]*(?:globalconfig|userconfig)[\s\x1c-\x1f]*=")
            .expect("npm dynamic configuration pattern")
    })
}

pub(super) fn manager_names(manager: &str) -> Names {
    if JS_MANAGERS.contains(&manager) {
        return Names {
            registry: &[".npmrc"],
            workspace: &[
                ".yarnrc",
                ".yarnrc.yml",
                "pnpm-workspace.yaml",
                "pnpm-workspace.yml",
            ],
            hooks: &[".pnpmfile.cjs", "pnpmfile.cjs", ".pnp.cjs"],
        };
    }
    if PYTHON_MANAGERS.contains(&manager) {
        return Names {
            registry: &["pip.conf", "pip.ini"],
            workspace: &["Pipfile", "pyproject.toml", "uv.toml"],
            hooks: &[],
        };
    }
    if RUBY_MANAGERS.contains(&manager) {
        return Names {
            registry: &[".gemrc", ".bundle/config"],
            workspace: &["Gemfile"],
            hooks: &[],
        };
    }
    match manager {
        "cargo" => Names {
            registry: &[".cargo/config", ".cargo/config.toml"],
            workspace: &["Cargo.toml"],
            hooks: &["build.rs"],
        },
        "go" => Names {
            registry: &[],
            workspace: &["go.work", "go.mod"],
            hooks: &[],
        },
        "mvn" | "mvnw" => Names {
            registry: &["settings.xml"],
            workspace: &["pom.xml", ".mvn/maven.config"],
            hooks: &[],
        },
        "gradle" | "gradlew" => Names {
            registry: &["gradle.properties"],
            workspace: &["settings.gradle", "settings.gradle.kts"],
            hooks: &["init.gradle"],
        },
        "composer" => Names {
            registry: &["auth.json"],
            workspace: &["composer.json"],
            hooks: &["composer.patches.json"],
        },
        _ => Names {
            registry: &[],
            workspace: &[],
            hooks: &[],
        },
    }
}

/// `_user_configuration_paths`: path, label is always `user`, and whether the
/// file is an npmrc.
pub(super) fn user_configuration_paths(
    fs: &Fs,
    manager: &str,
    environment: &BTreeMap<String, String>,
) -> Built<Vec<(String, bool)>> {
    let home = match environment.get("HOME").filter(|value| !value.is_empty()) {
        Some(value) => fs.expanduser(value)?,
        None => fs.home_directory(),
    };
    let under_home = |parts: &[&str]| {
        parts
            .iter()
            .fold(PyPath::new(&home), |path, part| path.join(part))
            .to_string()
    };
    let mut paths: Vec<(String, bool)> = Vec::new();
    if JS_MANAGERS.contains(&manager) {
        let configured = environment
            .get("NPM_CONFIG_USERCONFIG")
            .filter(|value| !value.is_empty());
        paths.push((
            match configured {
                Some(value) => fs.expanduser(value)?,
                None => under_home(&[".npmrc"]),
            },
            true,
        ));
    } else if PYTHON_MANAGERS.contains(&manager) {
        match environment
            .get("PIP_CONFIG_FILE")
            .filter(|value| !value.is_empty())
        {
            Some(value) => paths.push((fs.expanduser(value)?, false)),
            None => {
                paths.push((under_home(&[".config", "pip", "pip.conf"]), false));
                paths.push((under_home(&[".config", "uv", "uv.toml"]), false));
            }
        }
    } else if manager == "cargo" {
        let base = match environment.get("CARGO_HOME") {
            Some(value) => fs.expanduser(value)?,
            None => under_home(&[".cargo"]),
        };
        paths.push((PyPath::new(&base).join("config").to_string(), false));
        paths.push((PyPath::new(&base).join("config.toml").to_string(), false));
    } else if manager == "composer" {
        let base = match environment.get("COMPOSER_HOME") {
            Some(value) => fs.expanduser(value)?,
            None => under_home(&[".composer"]),
        };
        paths.push((PyPath::new(&base).join("config.json").to_string(), false));
        paths.push((PyPath::new(&base).join("auth.json").to_string(), false));
    } else if RUBY_MANAGERS.contains(&manager) {
        paths.push((under_home(&[".gemrc"]), false));
        paths.push((under_home(&[".bundle", "config"]), false));
    }
    let mut unique: Vec<(String, bool)> = Vec::new();
    for item in paths {
        if !unique.contains(&item) {
            unique.push(item);
        }
    }
    Ok(unique)
}

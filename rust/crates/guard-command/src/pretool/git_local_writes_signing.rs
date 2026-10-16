//! `git commit -S`: Git signs the commit with the program `gpg.format`
//! picks, `gpg` for OpenPGP, `gpgsm` for X.509 or `ssh-keygen` for SSH,
//! unless `gpg.<format>.program` (or `gpg.program`) names another. Signing
//! is the user's own choice when that program is theirs: the repository sets
//! no `gpg.*` key, SSH signing names no `defaultKeyCommand` to run, and every
//! program the configuration could pick resolves to an installed executable
//! in a trusted location, outside home, the working directory and temp.

use super::super::git_remote_config::GitConfig;
use guard_contracts::GuardExecutionEnvironmentV1;
use std::path::Path;

/// Whether a signed commit starts only the user's installed signing program.
pub(super) fn trusted(
    effective: &GitConfig,
    repository: &GitConfig,
    home: &Path,
    cwd: &Path,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
) -> bool {
    if repository
        .keys()
        .any(|key| key.to_ascii_lowercase().starts_with("gpg."))
    {
        return false;
    }
    let setting = |key: &str| values(effective, key);
    // Every format any scope names could be the one Git reads last.
    let formats = setting("gpg.format");
    let formats: Vec<&str> = if formats.is_empty() {
        vec!["openpgp"]
    } else {
        formats.iter().map(|value| value.trim()).collect()
    };
    formats.iter().all(|format| {
        // Git matches the format name exactly.
        let (default, legacy) = match *format {
            "openpgp" => ("gpg", setting("gpg.program")),
            "x509" => ("gpgsm", &[][..]),
            // With no signing key, SSH signing runs this command to pick one.
            "ssh" if setting("gpg.ssh.defaultkeycommand").is_empty() => ("ssh-keygen", &[][..]),
            _ => return false,
        };
        let configured: Vec<&String> = setting(&format!("gpg.{format}.program"))
            .iter()
            .chain(legacy)
            .collect();
        let programs: Vec<&str> = if configured.is_empty() {
            vec![default]
        } else {
            configured.into_iter().map(String::as_str).collect()
        };
        programs.into_iter().all(|program| {
            // Git expands a leading `~` in this path; the proof does not.
            !program.is_empty()
                && !program.starts_with('~')
                && super::super::git_config::trusted_command(
                    program,
                    home,
                    cwd,
                    execution_environment,
                )
                .is_some()
        })
    })
}

fn values<'a>(config: &'a GitConfig, key: &str) -> &'a [String] {
    config.get(key).map(Vec::as_slice).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::trusted;
    use std::path::Path;

    fn config(pairs: &[(&str, &str)]) -> super::GitConfig {
        let mut config = super::GitConfig::new();
        for (key, value) in pairs {
            config
                .entry((*key).to_owned())
                .or_default()
                .push((*value).to_owned());
        }
        config
    }

    #[test]
    fn repository_signing_settings_and_key_commands_are_refused() {
        let (home, cwd) = (
            Path::new("/nonexistent/home"),
            Path::new("/nonexistent/cwd"),
        );
        for (effective, repository) in [
            (
                config(&[("gpg.program", "/usr/bin/true")]),
                config(&[("gpg.program", "/usr/bin/true")]),
            ),
            (
                config(&[("gpg.format", "ssh")]),
                config(&[("gpg.format", "ssh")]),
            ),
            (
                config(&[
                    ("gpg.format", "ssh"),
                    ("gpg.ssh.defaultkeycommand", "ssh-add -L"),
                ]),
                config(&[]),
            ),
            (config(&[("gpg.format", "pkcs7")]), config(&[])),
            (config(&[("gpg.program", "~/bin/gpg")]), config(&[])),
            (config(&[("gpg.openpgp.program", "")]), config(&[])),
        ] {
            assert!(
                !trusted(&effective, &repository, home, cwd, None),
                "{effective:?} {repository:?}"
            );
        }
    }
}

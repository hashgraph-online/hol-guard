//! Name and install-layout hints about a runtime executable.
//!
//! Everything here reads the path text only. A file name or a directory such
//! as `versions/node/v20.11.1/bin/node` is something anyone can create, so a
//! hint is at most a self-reported claim: this module cannot produce a trusted
//! identity and nothing in it opens or starts the file.

/// What the path says the executable is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Hint {
    pub(crate) family: Option<&'static str>,
    pub(crate) version: Option<String>,
    /// Who built it, when the layout names an installer of that vendor's
    /// releases. Still a path claim, so it can flag a build but never clear one.
    pub(crate) vendor: Option<&'static str>,
}

/// Node install layouts that carry upstream release builds (nvm, fnm, Volta,
/// asdf, Homebrew and the release tarball). A bare `/usr/bin/node` may be a
/// distribution build with backported fixes, so it names no vendor.
const NODE_UPSTREAM_VENDOR: &str = "nodejs.org";

pub(crate) fn hint_for(resolved: &str) -> Hint {
    let normalized = resolved.replace('\\', "/");
    let components: Vec<&str> = normalized.split('/').filter(|c| !c.is_empty()).collect();
    let Some((file, directories)) = components.split_last() else {
        return Hint::default();
    };
    let (family, name_version) = family_from_name(file);
    let Some(family) = family else {
        return Hint::default();
    };
    let layout_version = layout_version(family, directories);
    let laid_out = layout_version.is_some();
    let version = match (name_version, layout_version) {
        (Some(named), Some(laid_out)) => {
            // A name and a directory that disagree prove nothing either way.
            laid_out
                .starts_with(&format!("{named}."))
                .then_some(laid_out)
        }
        (Some(named), None) => Some(named),
        (None, laid_out) => laid_out,
    };
    let vendor =
        (family == "node" && laid_out && version.is_some()).then_some(NODE_UPSTREAM_VENDOR);
    Hint {
        family: Some(family),
        version,
        vendor,
    }
}

fn family_from_name(file: &str) -> (Option<&'static str>, Option<String>) {
    let lower = file.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    match stem {
        "node" | "nodejs" => return (Some("node"), None),
        "bun" => return (Some("bun"), None),
        "deno" => return (Some("deno"), None),
        "python" | "python3" | "pythonw" => return (Some("python"), None),
        _ => {}
    }
    if let Some(rest) = stem.strip_prefix("python") {
        let parts: Vec<&str> = rest.split('.').collect();
        let numeric = parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if numeric && (2..=3).contains(&parts.len()) {
            return (Some("python"), Some(parts.join(".")));
        }
    }
    (None, None)
}

fn layout_version(family: &str, directories: &[&str]) -> Option<String> {
    let mut found = None;
    for (index, component) in directories.iter().enumerate() {
        let candidate = prefixed_version(family, component).or_else(|| {
            let next = directories.get(index + 1)?;
            marks_version_directory(family, component, directories.get(index.wrapping_sub(1)))
                .then(|| strict_version(next))
                .flatten()
        });
        if let Some(version) = candidate {
            // The deepest match is closest to the executable.
            found = Some(version);
        }
    }
    found
}

/// `node-v20.11.1-linux-x64`, `cpython-3.12.4-macos-aarch64-none`, `bun-v1.1.0`.
fn prefixed_version(family: &str, component: &str) -> Option<String> {
    let lower = component.to_ascii_lowercase();
    let prefix = if family == "python" {
        "cpython-"
    } else {
        return lower
            .strip_prefix(family)
            .and_then(|rest| rest.strip_prefix('-'))
            .and_then(|rest| strict_version(rest.split('-').next()?));
    };
    let rest = lower.strip_prefix(prefix)?;
    strict_version(rest.split(['-', '+']).next()?)
}

/// A directory whose next component is a version: Homebrew's `Cellar/node/22.3.0`,
/// nvm's `versions/node/v20.11.1`, fnm's `node-versions/v20.11.1`, asdf's
/// `installs/nodejs/20.11.1`, Volta's `image/node/20.11.1` and pyenv's
/// `.pyenv/versions/3.12.4`.
fn marks_version_directory(family: &str, component: &str, previous: Option<&&str>) -> bool {
    let lower = component.to_ascii_lowercase();
    let formula = lower.split('@').next().unwrap_or("");
    match family {
        "node" => matches!(formula, "node" | "nodejs") || lower == "node-versions",
        "python" => {
            formula == "python" || (lower == "versions" && previous.is_some_and(|p| *p == ".pyenv"))
        }
        "bun" | "deno" => formula == family,
        _ => false,
    }
}

/// `v20.11.1`, `22.3.0` and Homebrew's `22.3.0_1` revision form, as `X.Y.Z`.
pub(crate) fn strict_version(text: &str) -> Option<String> {
    let text = text.strip_prefix('v').unwrap_or(text);
    let text = match text.split_once('_') {
        Some((version, revision))
            if !revision.is_empty() && revision.bytes().all(|b| b.is_ascii_digit()) =>
        {
            version
        }
        Some(_) => return None,
        None => text,
    };
    let parts: Vec<&str> = text.split('.').collect();
    let valid = parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 9
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        });
    valid.then(|| text.to_owned())
}

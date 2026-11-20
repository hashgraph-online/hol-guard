//! Where a project keeps its version and changelog, for a release or a
//! changelog entry: the version's file and value, the tool that bumps it,
//! and the changelog's newest entry heading, so a new entry can match it.
use super::{shown, Project};

const CHANGELOGS: [&str; 4] = ["CHANGELOG", "CHANGES", "HISTORY", "NEWS"];
const BUMP_FILES: [&str; 4] = [
    ".bumpversion.cfg",
    ".bumpversion.toml",
    ".bumpversion.cfg.toml",
    "tbump.toml",
];

pub(super) fn version(project: &Project) -> Vec<String> {
    let mut lines = Vec::new();
    let dynamic = project
        .py(&["project", "dynamic"])
        .and_then(|v| v.as_array())
        .is_some_and(|list| list.iter().any(|v| v.as_str() == Some("version")));
    if let Some(value) = project.py(&["project", "version"]).and_then(|v| v.as_str()) {
        lines.push(format!(
            "Version: `{}` in pyproject.toml [project]",
            shown(value)
        ));
    } else if dynamic {
        lines.extend(dynamic_version(project));
    }
    if let Some(value) = project.package.as_ref().and_then(|p| p.get("version")) {
        let value = value.as_str().unwrap_or_default();
        lines.push(format!("Version: `{}` in package.json", shown(value)));
    }
    if let Some(bump) = BUMP_FILES.iter().find(|file| project.has(file)) {
        lines.push(format!(
            "Version bumps: {bump} lists every file a bump edits"
        ));
    } else if project.py(&["tool", "bumpversion"]).is_some() {
        lines.push("Version bumps: [tool.bumpversion] in pyproject.toml".to_owned());
    }
    lines
}

/// Where a version pyproject.toml leaves to the build backend comes from.
fn dynamic_version(project: &Project) -> Vec<String> {
    if project.py(&["tool", "setuptools_scm"]).is_some() {
        return vec!["Version: from Git tags (setuptools_scm)".to_owned()];
    }
    if let Some(path) = project
        .py(&["tool", "hatch", "version", "path"])
        .and_then(|v| v.as_str())
    {
        return vec![format!("Version: in {} (hatch)", shown(path))];
    }
    let attr = project.py(&["tool", "setuptools", "dynamic", "version", "attr"]);
    if let Some(attr) = attr.and_then(|v| v.as_str()) {
        return vec![format!(
            "Version: the `{}` attribute (setuptools)",
            shown(attr)
        )];
    }
    // flit's module name is a dotted import path; a distribution name maps
    // its dashes and dots to underscores.
    let flit = project.py(&["tool", "flit", "module", "name"]);
    let module = (flit
        .and_then(|v| v.as_str())
        .map(|name| name.replace('.', "/")))
    .or_else(|| {
        let name = project.py(&["project", "name"])?.as_str()?;
        Some(name.replace(['-', '.'], "_"))
    });
    let plain = |m: &String| {
        m.split('/')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || c == '_'))
    };
    let Some(module) = module.filter(plain) else {
        return Vec::new();
    };
    let places = [
        format!("src/{module}/__init__.py"),
        format!("{module}/__init__.py"),
        format!("src/{module}.py"),
        format!("{module}.py"),
    ];
    for place in places {
        let Some(text) = project.read(&place) else {
            continue;
        };
        if let Some(line) = text.lines().find(|line| line.starts_with("__version__")) {
            return vec![format!("Version: `{}` in {place}", shown(line))];
        }
    }
    Vec::new()
}

pub(super) fn changelog(project: &Project) -> Vec<String> {
    let found = project.listed("", |name| {
        let stem = name.split('.').next().unwrap_or(name);
        CHANGELOGS.contains(&stem.to_uppercase().as_str())
            && matches!(
                name.rsplit_once('.').map(|(_, e)| e),
                None | Some("md" | "rst" | "txt")
            )
    });
    let Some(name) = found.first() else {
        return Vec::new();
    };
    let newest = project.read(name).and_then(|text| newest_entry(&text));
    vec![match newest {
        Some(heading) => format!(
            "Changelog: {name}; its newest entry is headed `{}`",
            shown(&heading)
        ),
        None => format!("Changelog: {name}"),
    }]
}

/// The heading of the newest entry: the first heading line holding a digit,
/// in Markdown (`## 2.1.0`) or reStructuredText (a line over `-----`).
fn newest_entry(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().take(80).collect();
    lines.iter().enumerate().find_map(|(at, line)| {
        let trimmed = line.trim();
        let underlined = lines.get(at + 1).is_some_and(|next| {
            let next = next.trim();
            next.len() >= 3
                && next
                    .chars()
                    .all(|c| matches!(c, '-' | '=' | '~' | '^' | '*'))
        });
        let heading = trimmed.starts_with('#') || underlined;
        // An "Unreleased" section above the last release is the newest entry.
        let named = trimmed.chars().any(|c| c.is_ascii_digit())
            || trimmed.to_ascii_lowercase().contains("unreleased");
        (heading && named && trimmed.len() <= 80).then(|| trimmed.to_owned())
    })
}

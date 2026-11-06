//! Project paths that steer or run an agent harness the next time it opens
//! the repository: plugins, hooks, settings, MCP servers, slash commands and
//! instruction files. Planting one is a persistence vector, because the
//! harness loads it without asking, so a write that creates or changes any of
//! them is reviewed even inside the workspace, in every write route (the
//! workspace sandbox profile, the Linux overlay, file-edit tools, host shell
//! writes, `apply_patch` and the semantic contained write). Plain-text
//! instruction files are the exception on the host routes. Reading is
//! unaffected.
//!
//! Names are matched case-insensitively at any depth. A directory name covers
//! everything below it; a file name covers only that basename.

/// Directories a harness, editor or git hook runner auto-loads from. The list
/// lives beside the credential screen that also reads it.
pub(crate) use guard_secure_fs::credential_store_names::HARNESS_DIRECTORIES;

/// Files that register a command a harness or tool launches (MCP servers,
/// lint and test commands). Writes to them are reviewed in every route.
pub(crate) const HARNESS_CONFIG_FILES: &[&str] = &[
    ".aider.conf.yml",
    ".mcp.json",
    "crush.json",
    "opencode.json",
    "opencode.jsonc",
];

/// Plain-text agent instruction files. They execute nothing and show in a
/// diff, so file-edit tools and host shell writes may change them silently.
/// The workspace sandbox still denies them, as it always has.
pub(crate) const HARNESS_INSTRUCTION_FILES: &[&str] = &[
    ".aider.model.settings.yml",
    ".clinerules",
    ".cursorrules",
    ".goosehints",
    ".roomodes",
    ".roorules",
    ".windsurfrules",
    "agents.md",
    "claude.md",
    "copilot-instructions.md",
    "gemini.md",
    "qwen.md",
];

/// Subdirectories of `.github` that GitHub Copilot loads as agent
/// instructions, prompts, agents or hooks. The rest of `.github` stays open.
pub(crate) const GITHUB_AGENT_DIRECTORIES: &[&str] =
    &["agents", "chatmodes", "hooks", "instructions", "prompts"];

/// True when `name` (any letter case) is a harness directory.
pub(crate) fn directory_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    HARNESS_DIRECTORIES.contains(&lowered.as_str())
}

/// True when `name` (any letter case) is a file that registers a launch command.
pub(crate) fn config_file_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    HARNESS_CONFIG_FILES.contains(&lowered.as_str())
}

/// True when any component of the workspace-relative `parts` names harness
/// configuration: a harness directory, a launch-command config file, or an agent directory
/// directly under `.github`.
pub(crate) fn path_parts_protected<'a>(parts: impl IntoIterator<Item = &'a str>) -> bool {
    let mut previous_github = false;
    for part in parts {
        let lowered = part.to_ascii_lowercase();
        if directory_name(&lowered)
            || config_file_name(&lowered)
            || (previous_github && GITHUB_AGENT_DIRECTORIES.contains(&lowered.as_str()))
        {
            return true;
        }
        previous_github = lowered == ".github";
    }
    false
}

/// True when a write to `canonical` (the resolved target) or to `supplied`
/// (the spelling the caller used) lands on harness configuration inside
/// `workspace`. Both count: a link such as `AGENTS.md -> docs/rules.md`
/// still names an instruction file, and a link into `.zcode` still lands there.
pub(crate) fn write_target_protected(
    supplied: &std::path::Path,
    canonical: &std::path::Path,
    workspace: &std::path::Path,
) -> bool {
    fn parts(path: &std::path::Path) -> Option<Vec<&str>> {
        path.components()
            .filter_map(|component| match component {
                std::path::Component::Normal(part) => Some(part.to_str()),
                _ => None,
            })
            .collect()
    }
    let resolved = canonical.strip_prefix(workspace).unwrap_or(canonical);
    let spelled = supplied.strip_prefix(workspace).unwrap_or(supplied);
    [resolved, spelled]
        .into_iter()
        .any(|path| parts(path).is_none_or(path_parts_protected))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protected(path: &str) -> bool {
        path_parts_protected(path.split('/'))
    }

    #[test]
    fn harness_configuration_is_protected_at_any_depth() {
        for path in [
            ".zcode/x",
            ".opencode/plugins/x.ts",
            "pkg/.Claude/settings.json",
            ".copilot/a",
            ".clinerules/rules.md",
            ".gemini/settings.json",
            ".kiro/steering/a.md",
            ".roo/rules/a.md",
            ".windsurf/rules/a.md",
            ".continue/config.yaml",
            ".pi/extensions/a.ts",
            ".husky/pre-commit",
            ".mcp.json",
            "sub/opencode.jsonc",
            ".github/instructions/a.md",
            ".github/hooks/a.json",
            "opencode.json",
        ] {
            assert!(protected(path), "{path}");
        }
    }

    #[test]
    fn write_targets_count_both_the_spelling_and_the_resolved_path() {
        use std::path::Path;
        let workspace = Path::new("/w/proj");
        let target = |supplied: &str, canonical: &str| {
            write_target_protected(Path::new(supplied), Path::new(canonical), workspace)
        };
        assert!(target("/w/proj/.mcp.json", "/w/proj/docs/rules.json"));
        assert!(target("opencode.json", "/w/proj/opencode.json"));
        assert!(!target("AGENTS.md", "/w/proj/AGENTS.md"));
        assert!(target("notes.md", "/w/proj/.zcode/notes.md"));
        assert!(!target("src/a.ts", "/w/proj/src/a.ts"));
        assert!(!target("/w/proj/src/a.ts", "/w/proj/src/a.ts"));
    }

    #[test]
    fn ordinary_project_paths_stay_open() {
        for path in [
            "src/main.rs",
            "tests/a.test.ts",
            "dist/index.js",
            "node_modules/.cache/x",
            ".github/dependabot.yml",
            "AGENTS.md",
            "docs/CLAUDE.md",
            "GEMINI.md",
            ".github/copilot-instructions.md",
            ".github/ISSUE_TEMPLATE/bug.md",
            ".vscode-test/x",
            ".pipeline/x",
            ".opencode-notes.txt",
            "docs/hooks/readme.md",
            "agents/readme.md",
            "README.md",
        ] {
            assert!(!protected(path), "{path}");
        }
    }
}

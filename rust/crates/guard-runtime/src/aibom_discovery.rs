//! Shared workspace AIBOM discovery: `AGENTS.md`, standards documents, cursor
//! rules, project skills and the Codex marketplace. Every rule is a port of
//! the legacy Python discovery; a gap that cannot be represented faithfully
//! is a typed refusal, never a silently shorter inventory.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::aibom_artifact::{instruction_artifact, Instruction};
use super::aibom_marketplace::marketplace_plugins;
use super::aibom_paths::{
    instruction_role_for_path, is_dir, is_file, is_symlink, py_join, recursive_markdown_files,
    resolve, resolves_within_root, safe_matching_files, DOC_DIRECTORY_ROLES, ERR_NON_UTF8,
};
use super::aibom_skills::{project_skill_artifacts, SkillSource};

pub(crate) const ERR_ROOT: &str = "native_runner_authority_aibom_workspace_invalid";

/// Harnesses that natively discover skills from the shared `.agents/skills`
/// workspace directory.
const WORKSPACE_SKILL_HARNESSES: [&str; 8] = [
    "codex",
    "openclaw",
    "opencode",
    "claude-code",
    "cursor",
    "gemini",
    "pi",
    "omp",
];
const STANDARDS_CONTEXT_ROOTS: [&str; 3] = [".", ".agents/context", "docs"];
const ROOT_INSTRUCTION_NAMES: [(&str, &str); 8] = [
    ("CLAUDE.md", "claude_md"),
    ("DESIGN.md", "design_md"),
    ("PRODUCT.md", "product_md"),
    ("ROADMAP.md", "roadmap_md"),
    ("SECURITY.md", "security_md"),
    ("POLICY.md", "policy_md"),
    ("POLICIES.md", "policy_md"),
    ("STANDARDS.md", "standards_md"),
];

fn posix_relative(path: &Path, base: &Path) -> Result<String, &'static str> {
    let relative = path.strip_prefix(base).map_err(|_| ERR_ROOT)?;
    let mut parts = Vec::new();
    for component in relative.components() {
        parts.push(component.as_os_str().to_str().ok_or(ERR_NON_UTF8)?);
    }
    Ok(if parts.is_empty() {
        ".".to_owned()
    } else {
        parts.join("/")
    })
}

fn path_text(path: &Path) -> Result<&str, &'static str> {
    path.to_str().ok_or(ERR_NON_UTF8)
}

fn agents_md(harness: &str, workspace: &Path) -> Vec<Value> {
    let path = py_join(workspace, "AGENTS.md");
    if !is_file(&path) || is_symlink(&path) || !resolves_within_root(workspace, &path, true) {
        return Vec::new();
    }
    vec![instruction_artifact(Instruction {
        harness,
        path: &path,
        role: "agents_md",
        display_name: None,
        artifact_name: None,
        artifact_id: None,
    })]
}

fn standards_context(harness: &str, workspace: &Path) -> Result<Vec<Value>, &'static str> {
    let mut artifacts = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for relative_root in STANDARDS_CONTEXT_ROOTS {
        let search_root = if relative_root == "." {
            workspace.to_path_buf()
        } else {
            py_join(workspace, relative_root)
        };
        if relative_root != "." && !is_dir(&search_root) {
            continue;
        }
        if !resolves_within_root(workspace, &search_root, true) {
            continue;
        }
        for (filename, role) in ROOT_INSTRUCTION_NAMES {
            let path = py_join(&search_root, filename);
            if is_symlink(&path) || !is_file(&path) || !resolves_within_root(workspace, &path, true)
            {
                continue;
            }
            let normalized = path_text(&resolve(&path).map_err(|()| ERR_ROOT)?)?.to_owned();
            if !seen.insert(normalized) {
                continue;
            }
            let relative_id = posix_relative(&path, workspace)?;
            let display_name = if relative_root == "." {
                filename.to_owned()
            } else {
                format!("{filename} ({relative_root})")
            };
            let legacy_id = (harness == "claude-code" && relative_id == "CLAUDE.md")
                .then(|| format!("{harness}:project:instruction:claude-md"));
            artifacts.push(instruction_artifact(Instruction {
                harness,
                path: &path,
                role,
                display_name: Some(display_name),
                artifact_name: Some(relative_id.replace('/', ":")),
                artifact_id: legacy_id,
            }));
        }
        let docs_root = py_join(&search_root, "docs");
        if !is_dir(&docs_root) || !resolves_within_root(workspace, &docs_root, true) {
            continue;
        }
        for (directory_name, _) in DOC_DIRECTORY_ROLES {
            let base_dir = py_join(&docs_root, directory_name);
            if !is_dir(&base_dir) || !resolves_within_root(workspace, &base_dir, true) {
                continue;
            }
            for doc_path in recursive_markdown_files(workspace, &base_dir)? {
                let normalized = path_text(&resolve(&doc_path).map_err(|()| ERR_ROOT)?)?.to_owned();
                if !seen.insert(normalized) {
                    continue;
                }
                let role = instruction_role_for_path(&doc_path).unwrap_or("unknown_instruction");
                let relative_id = posix_relative(&doc_path, workspace)?;
                artifacts.push(instruction_artifact(Instruction {
                    harness,
                    path: &doc_path,
                    role,
                    display_name: Some(relative_id.clone()),
                    artifact_name: Some(relative_id.replace('/', ":")),
                    artifact_id: None,
                }));
            }
        }
    }
    Ok(artifacts)
}

fn cursor_rules(harness: &str, workspace: &Path) -> Result<Vec<Value>, &'static str> {
    let rules_dir: PathBuf = py_join(workspace, ".cursor/rules");
    if !is_dir(&rules_dir) || !resolves_within_root(workspace, &rules_dir, true) {
        return Ok(Vec::new());
    }
    let mut artifacts = Vec::new();
    for suffix in [".mdc", ".md"] {
        for rule_path in safe_matching_files(workspace, &rules_dir, suffix)? {
            let name = super::aibom_paths::file_name_string(&rule_path);
            artifacts.push(instruction_artifact(Instruction {
                harness,
                path: &rule_path,
                role: "cursor_rules",
                display_name: Some(super::aibom_paths::stem(&name).to_owned()),
                artifact_name: None,
                artifact_id: None,
            }));
        }
    }
    Ok(artifacts)
}

/// `discover_shared_workspace_aibom_artifacts`. `workspace` must be absolute;
/// the caller supplies the portable skill artifacts when the native walk
/// cannot serve the request.
pub(crate) fn shared_workspace_artifacts(
    harness: &str,
    workspace: &Path,
    skills: &SkillSource,
) -> Result<Vec<Value>, &'static str> {
    if !is_dir(workspace) {
        return Ok(Vec::new());
    }
    let Ok(workspace) = resolve(workspace) else {
        return Ok(Vec::new());
    };
    let mut artifacts = agents_md(harness, &workspace);
    artifacts.extend(standards_context(harness, &workspace)?);
    artifacts.extend(cursor_rules(harness, &workspace)?);
    if WORKSPACE_SKILL_HARNESSES.contains(&harness) {
        artifacts.extend(project_skill_artifacts(harness, &workspace, skills)?);
    }
    artifacts.extend(marketplace_plugins(harness, &workspace)?);
    Ok(artifacts)
}

//! Direct-command MCP launch validation shared by source compilation and admission.

const RESERVED_DIRECT_MCP_COMMANDS: &[&str] = &[
    "bash",
    "busybox",
    "bun",
    "bunx",
    "cargo",
    "cmd",
    "csh",
    "dash",
    "deno",
    "docker",
    "dotnet",
    "env",
    "fish",
    "go",
    "java",
    "ksh",
    "lua",
    "node",
    "nodejs",
    "npm",
    "npx",
    "perl",
    "php",
    "pipx",
    "pnpm",
    "podman",
    "powershell",
    "pwsh",
    "py",
    "python",
    "python3",
    "pythonw",
    "ruby",
    "sh",
    "sudo",
    "tcsh",
    "ts-node",
    "tsx",
    "uv",
    "uvx",
    "wsl",
    "yarn",
    "zsh",
];

const VERSIONED_INTERPRETER_BASES: &[&str] = &[
    "java", "lua", "node", "nodejs", "perl", "php", "py", "python", "pythonw", "ruby",
];

fn numeric_version_suffix(value: &str, base: &str) -> bool {
    let Some(suffix) = value.strip_prefix(base) else {
        return false;
    };
    !suffix.is_empty()
        && suffix.as_bytes()[0].is_ascii_digit()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn reserved_direct_mcp_command(value: &str) -> bool {
    RESERVED_DIRECT_MCP_COMMANDS.contains(&value)
        || VERSIONED_INTERPRETER_BASES
            .iter()
            .any(|base| numeric_version_suffix(value, base))
}

/// Canonical, portable basename; catalog selection never authenticates a binary.
pub(super) fn valid_direct_mcp_command(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && ![".exe", ".cmd", ".bat"]
            .iter()
            .any(|suffix| value.ends_with(suffix))
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && !reserved_direct_mcp_command(value)
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-')
                })
        })
}

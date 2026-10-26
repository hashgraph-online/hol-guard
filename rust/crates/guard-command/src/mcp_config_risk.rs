//! Risky launch settings in a configured MCP server.
//!
//! A project's MCP configuration names the program an agent starts for each
//! server, or the URL it connects to. These rules read that configuration
//! only: they never start the server, resolve its program or fetch its URL.
//!
//! A server launched through a shell script runs the shared launch screen, so
//! a script that pipes a download into a shell or sends the environment over
//! the network is named the same way as in an agent's shell commands.

use std::net::IpAddr;

use crate::launch_screen::screen_argv;

#[cfg(test)]
#[path = "mcp_config_risk_tests.rs"]
mod tests;

/// One rule's fixed wording. Nothing in it quotes the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpConfigRule {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub title: &'static str,
    pub reason: &'static str,
    pub false_positive_hint: Option<&'static str>,
}

pub const REMOTE_CODE_LAUNCH: McpConfigRule = McpConfigRule {
    id: "mcp.config.remote-code",
    category: "execution",
    severity: "critical",
    confidence: "strong",
    title: "MCP server launch runs downloaded code",
    reason: "The server starts through a shell script that pipes a download into a shell or interpreter, so it runs remote code without review.",
    false_positive_hint: None,
};

pub const ENVIRONMENT_EXFILTRATION_LAUNCH: McpConfigRule = McpConfigRule {
    id: "mcp.config.environment-exfiltration",
    category: "exfiltration",
    severity: "critical",
    confidence: "strong",
    title: "MCP server launch sends environment variables",
    reason: "The server starts through a shell script that pipes the process environment, which often holds secrets, to a network sender.",
    false_positive_hint: None,
};

pub const PRIVILEGED_LAUNCH: McpConfigRule = McpConfigRule {
    id: "mcp.config.privileged-launch",
    category: "privilege",
    severity: "high",
    confidence: "strong",
    title: "MCP server launches with elevated privileges",
    reason: "The server starts through sudo or a similar wrapper, so every tool it exposes runs with administrator rights.",
    false_positive_hint: Some("Expected only for a server that manages the machine itself."),
};

pub const PLAIN_HTTP_REMOTE: McpConfigRule = McpConfigRule {
    id: "mcp.config.remote-plain-http",
    category: "transport",
    severity: "high",
    confidence: "strong",
    title: "Remote MCP server uses plain HTTP",
    reason: "The server URL uses http to a host that is not loopback, so tool calls and replies cross the network unencrypted and can be read or changed.",
    false_positive_hint: None,
};

/// The rules a server's launch `command` and `args`, or its `url`, match, in
/// rule order and each at most once.
pub fn detect_mcp_config_risk(
    command: Option<&str>,
    args: &[String],
    url: Option<&str>,
) -> Vec<McpConfigRule> {
    let mut found = Vec::new();
    if let Some(command) = command.filter(|command| !command.trim().is_empty()) {
        let argv: Vec<String> = std::iter::once(command.to_owned())
            .chain(args.iter().cloned())
            .collect();
        let risk = screen_argv(&argv);
        if risk.remote_code {
            found.push(REMOTE_CODE_LAUNCH);
        }
        if risk.environment_exfiltration {
            found.push(ENVIRONMENT_EXFILTRATION_LAUNCH);
        }
        if risk.privileged {
            found.push(PRIVILEGED_LAUNCH);
        }
    }
    if url.is_some_and(is_plain_http_remote) {
        found.push(PLAIN_HTTP_REMOTE);
    }
    found
}

/// An `http` URL whose host is not loopback.
fn is_plain_http_remote(url: &str) -> bool {
    let url = url.trim();
    let Some(rest) = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .and_then(|_| url.get(7..))
    else {
        return false;
    };
    // WHATWG URL parsing, which MCP clients follow, ends the authority at a backslash too.
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => host_port.split(':').next().unwrap_or_default(),
    };
    !host.is_empty() && !is_loopback_host(host)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        Err(_) => false,
    }
}

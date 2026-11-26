//! Resolve a tool call to a compiled browser driver profile.
//!
//! A call can name its driver four ways: the MCP server name, the package that launched the server,
//! a tool-name namespace such as `mcp__example-pilot__`, or a harness built-in tool name. Order:
//!
//! 1. An exact identity (server name, package, harness tool) beats a namespace prefix.
//! 2. Within one rank, a first-party profile beats a contributed one.
//! 3. Within one rank and trust class, the longer namespace wins, then the lower driver id, so the
//!    answer never depends on table order.
//!
//! Two contributed profiles cannot claim one identity: `compile_browser_driver_set` refuses that.
//! A matched driver with no entry for the tool leaves the tool unclassified. It is never inferred
//! routine; the call keeps Guard's normal MCP review.

use guard_contracts::BrowserDriverTrustClassV1;

use crate::browser_driver_compile::{CompiledBrowserDriverV1, CompiledBrowserToolV1};

/// The identities one tool call carries. Absent fields are unknown, not empty.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BrowserToolCallIdentity<'a> {
    /// The tool name as the harness reported it, for example `mcp__example-pilot__open_page` or a
    /// built-in such as `browser`.
    pub harness_tool_name: &'a str,
    /// The MCP server the call is routed to, when the harness names it.
    pub mcp_server_name: Option<&'a str>,
    /// The MCP tool name on that server, when the harness names it.
    pub mcp_tool_name: Option<&'a str>,
    /// The package that launched the MCP server, when Guard recorded the launch.
    pub package: Option<&'a str>,
}

/// Which identity selected the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserDriverMatchKind {
    McpServerName,
    Package,
    HarnessTool,
    ToolNamespace,
}

impl BrowserDriverMatchKind {
    fn is_exact(self) -> bool {
        !matches!(self, Self::ToolNamespace)
    }
}

/// A resolved call. `tool` is `None` when the driver does not list the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserDriverMatch<'d, 'c> {
    pub driver: &'d CompiledBrowserDriverV1,
    pub kind: BrowserDriverMatchKind,
    /// The tool name looked up in the profile.
    pub tool_name: &'c str,
    pub tool: Option<&'d CompiledBrowserToolV1>,
}

impl BrowserDriverMatch<'_, '_> {
    /// True when the driver matched but does not list the tool.
    pub fn is_unclassified(&self) -> bool {
        self.tool.is_none()
    }
}

struct Candidate<'d, 'c> {
    driver: &'d CompiledBrowserDriverV1,
    kind: BrowserDriverMatchKind,
    tool_name: &'c str,
    namespace_len: usize,
}

impl Candidate<'_, '_> {
    /// Larger is preferred. Exactness first, then trust class, then namespace length.
    fn rank(&self) -> (bool, bool, usize) {
        (
            self.kind.is_exact(),
            self.driver.trust_class == BrowserDriverTrustClassV1::FirstParty,
            self.namespace_len,
        )
    }
}

/// Resolve `call` against the enabled driver table. `None` means no profile claims the call.
pub fn match_browser_driver<'d, 'c>(
    drivers: &'d [CompiledBrowserDriverV1],
    call: &BrowserToolCallIdentity<'c>,
) -> Option<BrowserDriverMatch<'d, 'c>> {
    let mut best: Option<Candidate<'d, 'c>> = None;
    for driver in drivers {
        for candidate in candidates(driver, call) {
            let better = match &best {
                None => true,
                Some(current) => {
                    let (rank, current_rank) = (candidate.rank(), current.rank());
                    rank > current_rank
                        || (rank == current_rank && candidate.driver.id < current.driver.id)
                }
            };
            if better {
                best = Some(candidate);
            }
        }
    }
    best.map(|candidate| BrowserDriverMatch {
        driver: candidate.driver,
        kind: candidate.kind,
        tool_name: candidate.tool_name,
        tool: candidate.driver.tools.get(candidate.tool_name),
    })
}

fn candidates<'d, 'c>(
    driver: &'d CompiledBrowserDriverV1,
    call: &BrowserToolCallIdentity<'c>,
) -> Vec<Candidate<'d, 'c>> {
    let matches = &driver.matches;
    let mut found = Vec::new();
    let mcp_tool = call.mcp_tool_name.filter(|name| !name.is_empty());
    let exact = |kind, tool_name| Candidate {
        driver,
        kind,
        tool_name,
        namespace_len: 0,
    };
    if let (Some(server), Some(tool)) = (call.mcp_server_name, mcp_tool) {
        if matches.mcp_server_names.iter().any(|name| name == server) {
            found.push(exact(BrowserDriverMatchKind::McpServerName, tool));
        }
    }
    if let (Some(package), Some(tool)) = (call.package, mcp_tool) {
        if matches.packages.iter().any(|name| name == package) {
            found.push(exact(BrowserDriverMatchKind::Package, tool));
        }
    }
    if matches
        .harness_tools
        .iter()
        .any(|name| name == call.harness_tool_name)
    {
        found.push(exact(
            BrowserDriverMatchKind::HarnessTool,
            call.harness_tool_name,
        ));
    }
    for namespace in &matches.tool_namespaces {
        if let Some(tool) = call.harness_tool_name.strip_prefix(namespace.as_str()) {
            if !tool.is_empty() {
                found.push(Candidate {
                    driver,
                    kind: BrowserDriverMatchKind::ToolNamespace,
                    tool_name: tool,
                    namespace_len: namespace.len(),
                });
            }
        }
    }
    found
}

#[cfg(test)]
#[path = "browser_driver_match_tests.rs"]
mod tests;

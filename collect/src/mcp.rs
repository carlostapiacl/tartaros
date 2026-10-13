//! MCP collector (v1, heuristic) — notices when the process tree launches an MCP
//! server the role was not granted. MCP servers are ordinary child processes, so
//! this reads their command lines and flags a server token not in the allowed
//! set. It is a heuristic over cmdline, not a protocol parser; good enough to
//! surface "a role loaded an MCP it shouldn't" until a precise source exists.

use tartaros_core::{Axis, Collector, Direction, EffectEvent, EffectSink, Outcome};
use std::collections::HashSet;

use crate::proc;

pub struct McpCollector {
    role: String,
    root_pid: u32,
    allowed: Vec<String>,
    seen: HashSet<String>,
}

impl McpCollector {
    pub fn new(role: impl Into<String>, root_pid: u32, allowed: Vec<String>) -> Self {
        McpCollector { role: role.into(), root_pid, allowed, seen: HashSet::new() }
    }

    /// Pure: from a command line, if it looks like an MCP server, return the
    /// server token and whether it is allowed.
    fn classify(&self, cmdline: &str) -> Option<(String, bool)> {
        let low = cmdline.to_lowercase();
        if !low.contains("mcp") && !low.contains("modelcontextprotocol") {
            return None;
        }
        // token = the recognizable server name if any allowed name appears,
        // else a coarse label so the event still fires for an unknown server.
        let token = self
            .allowed
            .iter()
            .find(|a| low.contains(&a.to_lowercase()))
            .cloned()
            .unwrap_or_else(|| first_mcp_token(&low));
        let allowed = self.allowed.iter().any(|a| low.contains(&a.to_lowercase()));
        Some((token, allowed))
    }

    fn event(&self, token: &str, allowed: bool) -> EffectEvent {
        EffectEvent::now(
            self.role.clone(),
            Axis::Mcp,
            "load",
            token.to_string(),
            if allowed { Direction::WithinTerritory } else { Direction::OutsideTerritory },
            Outcome::Attempted,
            "mcp/cmdline",
        )
    }
}

/// Best-effort server label from a cmdline that mentions mcp.
fn first_mcp_token(low: &str) -> String {
    for tok in low.split_whitespace() {
        if tok.contains("mcp") || tok.contains("modelcontextprotocol") {
            return tok.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '/').to_string();
        }
    }
    "mcp-unknown".to_string()
}

impl Collector for McpCollector {
    fn name(&self) -> &str {
        "mcp/cmdline"
    }

    fn poll(&mut self, sink: &mut dyn EffectSink) {
        for pid in proc::process_tree(self.root_pid) {
            if let Some(cmd) = proc::cmdline(pid) {
                if let Some((token, allowed)) = self.classify(&cmd) {
                    if self.seen.insert(token.clone()) {
                        sink.emit(&self.event(&token, allowed));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_ungranted_mcp_server() {
        let c = McpCollector::new("qa", 0, vec!["playwright".into()]);
        // not mcp at all
        assert!(c.classify("node build.js").is_none());
        // granted server
        let (tok, ok) = c.classify("npx @playwright/mcp-server --port 1").unwrap();
        assert!(ok);
        assert_eq!(tok, "playwright");
        // ungranted server
        let (_tok, ok) = c.classify("node server-filesystem-mcp.js").unwrap();
        assert!(!ok);
    }

    #[test]
    fn event_direction_reflects_grant() {
        let c = McpCollector::new("qa", 0, vec!["playwright".into()]);
        assert_eq!(c.event("playwright", true).direction, Direction::WithinTerritory);
        assert_eq!(c.event("other", false).direction, Direction::OutsideTerritory);
    }
}

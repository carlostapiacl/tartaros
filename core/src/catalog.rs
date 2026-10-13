//! Catalog — the map of what is "important" to notice when it is touched toward
//! the outside. Neutral classification used by collectors and by policy. New
//! entries go here, in one place, so every collector classifies the same way.

use crate::effect::Direction;

/// On-disk locations that hold secrets. A read reaching any of these is worth
/// recording even when allowed. Matched as a path component or suffix, so both
/// `~/.ssh` and `/home/x/.ssh/id_ed25519` hit `.ssh`.
pub const SECRET_MARKERS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".kube",
    ".docker/config.json",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".password-store",
    ".config/gh/hosts.yml",
    "Library/Keychains",
];

/// Filenames that are secrets wherever they appear.
pub const SECRET_FILE_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    "credentials",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".dockercfg",
];

/// Does this path reach a known secret location?
pub fn looks_like_secret(path: &str) -> bool {
    let p = path.replace('\\', "/");
    if SECRET_MARKERS.iter().any(|m| p.contains(m)) {
        return true;
    }
    let name = p.rsplit('/').next().unwrap_or(&p);
    SECRET_FILE_NAMES.iter().any(|f| *f == name)
}

/// Classify a remote endpoint relative to the agent's territory. Loopback on a
/// port the role was granted is within; loopback on any other port is a reach
/// toward a neighbour service (e.g. a port scan); anything non-loopback that is
/// not an allowed host is outside.
pub fn endpoint_direction(ip: &str, port: u16, within_ports: &[u16], allowed_hosts: &[String]) -> Direction {
    let is_loopback = ip == "127.0.0.1" || ip == "::1" || ip.starts_with("127.");
    if is_loopback {
        if within_ports.contains(&port) {
            Direction::WithinTerritory
        } else {
            Direction::OutsideTerritory
        }
    } else if allowed_hosts.iter().any(|h| h == ip) {
        Direction::WithinTerritory
    } else {
        Direction::OutsideTerritory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_paths_are_flagged() {
        assert!(looks_like_secret("/Users/x/.ssh/id_ed25519"));
        assert!(looks_like_secret("~/.aws/credentials"));
        assert!(looks_like_secret("/repo/.env"));
        assert!(looks_like_secret("/home/x/project/id_rsa"));
        assert!(!looks_like_secret("/repo/src/main.rs"));
        assert!(!looks_like_secret("/repo/README.md"));
    }

    #[test]
    fn endpoint_classification() {
        let within = [8001u16, 8081];
        // app ports on loopback: within
        assert_eq!(endpoint_direction("127.0.0.1", 8001, &within, &[]), Direction::WithinTerritory);
        // the team API on 8787 the role was NOT granted: a reach (scan-like)
        assert_eq!(endpoint_direction("127.0.0.1", 8787, &within, &[]), Direction::OutsideTerritory);
        // external host, not allowed: outside
        assert_eq!(endpoint_direction("8.8.8.8", 53, &within, &[]), Direction::OutsideTerritory);
        // external host explicitly allowed: within
        assert_eq!(endpoint_direction("140.82.112.3", 443, &within, &["140.82.112.3".into()]), Direction::WithinTerritory);
    }
}

//! Native-observed transport effects. Current command and extension policies
//! still judge every request; this module cannot grant consent or risk allow.
use std::collections::BTreeSet;
use std::net::SocketAddrV4;
use std::path::Path;

pub(super) fn destinations(
    argv: &[String],
    names: &[String],
    cwd: &Path,
    home: &Path,
) -> Result<BTreeSet<SocketAddrV4>, &'static str> {
    // These values are not in the selected Bash environment. Refuse instead
    // of silently stripping transport, trust or credential configuration.
    if names.iter().any(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy"
        ) || name.starts_with("CURL_")
            || name.starts_with("OPENSSL_")
            || matches!(
                name.as_str(),
                "SSL_CERT_FILE"
                    | "SSL_CERT_DIR"
                    | "SSLKEYLOGFILE"
                    | "QLOGDIR"
                    | "KRB5_CONFIG"
                    | "KRB5CCNAME"
            )
    }) {
        return Err("bash_network_environment_unproven");
    }
    let peers = guard_command::pretool::bound_curl_read_destinations(
        argv,
        guard_command::pretool::PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..Default::default()
        },
    )
    .ok_or("bash_network_read_delivery_unproven")?;
    // Seatbelt's address grammar accepts only localhost or wildcard hosts.
    // Public peers need brokered delivery; never advertise a working once
    // route whose generated profile the kernel cannot enforce.
    if peers
        .iter()
        .any(|peer| *peer.ip() != std::net::Ipv4Addr::LOCALHOST)
    {
        return Err("bash_network_remote_binding_unavailable");
    }
    Ok(peers)
}

pub(super) fn rules(peers: &BTreeSet<SocketAddrV4>) -> String {
    peers
        .iter()
        .map(|peer| {
            format!(
                "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                peer.port()
            )
        })
        .collect()
}

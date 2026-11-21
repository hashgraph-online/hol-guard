//! `local_identity` runner-authority kind: the host name and private address a
//! runtime session reports to Guard Cloud. Ported from `_safe_hostname`,
//! `_safe_private_ip`, `_safe_private_ipv6`, `_cloud_local_identity_payload`
//! and `_cloud_local_identity_source_payload` in `runtime/runner.py`.
//!
//! `{"observed_at"}` answers `{"identity": {...}, "source": {...}}`. The
//! identity always carries `lastSyncedAt`, then the host name and the private
//! address when they can be read. The source names `local-guard` as the origin
//! of every field the cloud would otherwise attribute to a daemon.
//!
//! The private IPv4 address is the local end of a UDP socket connected toward a
//! public resolver (no packet is sent), else the first IPv4 address the host
//! name resolves to. Without one, the first non-loopback IPv6 address the host
//! name resolves to stands in.
//!
//! The host name is resolved once, on its own thread: a slow resolver gives up
//! the address after [`LOOKUP_DEADLINE`] instead of holding the resident worker
//! that answers this kind.

use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::policy_bundle_store_identities::host_name;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const HOSTNAME_CHARS: usize = 255;
const ADDRESS_CHARS: usize = 128;
const SOURCE: &str = "local-guard";
const ROUTE_PROBE: &str = "8.8.8.8:80";
/// How long the session sync waits on the host name's addresses.
const LOOKUP_DEADLINE: Duration = Duration::from_secs(2);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    observed_at: String,
}

/// What the host reported: its name and the addresses it could find.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Probe {
    pub(crate) hostname: Option<String>,
    pub(crate) ipv4: Option<String>,
    pub(crate) ipv6: Option<String>,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let request: Request = serde_json::from_value(args.clone()).map_err(|_| ERR_INVALID)?;
    let identity = identity(&request.observed_at, &probe());
    let source = source(&identity);
    Ok(json!({"identity": identity, "source": source}))
}

/// `_cloud_local_identity_payload` over an already gathered probe.
pub(crate) fn identity(observed_at: &str, probe: &Probe) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("lastSyncedAt".to_owned(), json!(observed_at));
    if let Some(hostname) = &probe.hostname {
        payload.insert("hostname".to_owned(), json!(hostname));
    }
    if let Some(address) = probe.ipv4.as_ref().or(probe.ipv6.as_ref()) {
        payload.insert("ipAddress".to_owned(), json!(address));
        payload.insert("privateIpAddress".to_owned(), json!(address));
    }
    payload
}

/// `_cloud_local_identity_source_payload`: `local-guard` for the daemon
/// fields and for each address field the identity carries.
pub(crate) fn source(identity: &Map<String, Value>) -> Map<String, Value> {
    let mut payload = Map::new();
    for key in ["daemonId", "daemonVersion", "daemonStatus", "relayState"] {
        payload.insert(key.to_owned(), json!(SOURCE));
    }
    for key in [
        "hostname",
        "ipAddress",
        "privateIpAddress",
        "publicIpAddress",
    ] {
        if identity.contains_key(key) {
            payload.insert(key.to_owned(), json!(SOURCE));
        }
    }
    payload
}

fn probe() -> Probe {
    let hostname = host_name()
        .map(|name| {
            py_strip(&name)
                .chars()
                .take(HOSTNAME_CHARS)
                .collect::<String>()
        })
        .filter(|name| !name.is_empty());
    let (ipv4, ipv6) = match routed_ipv4() {
        Some(address) => (Some(address), None),
        None => {
            let addresses = hostname.as_deref().map(lookup).unwrap_or_default();
            let ipv4 = addresses
                .iter()
                .copied()
                .find(IpAddr::is_ipv4)
                .and_then(usable_ipv4);
            let ipv6 = if ipv4.is_none() {
                addresses
                    .iter()
                    .copied()
                    .find(|address| address.is_ipv6() && !address.is_loopback())
                    .map(bounded)
            } else {
                None
            };
            (ipv4, ipv6)
        }
    };
    Probe {
        hostname,
        ipv4,
        ipv6,
    }
}

/// `_safe_private_ip`'s first route: the address the host would send from.
fn routed_ipv4() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(ROUTE_PROBE).ok()?;
    usable_ipv4(socket.local_addr().ok()?.ip())
}

/// The addresses `hostname` resolves to, or none once [`LOOKUP_DEADLINE`]
/// passes. The lookup runs on a detached thread that ends when the resolver
/// answers, so a slow resolver holds only that thread.
fn lookup(hostname: &str) -> Vec<IpAddr> {
    let (sender, receiver) = mpsc::channel();
    let name = hostname.to_owned();
    let spawned = thread::Builder::new()
        .name("guard-host-lookup".to_owned())
        .spawn(move || {
            let addresses: Vec<IpAddr> = (name.as_str(), 0)
                .to_socket_addrs()
                .map(|found| found.map(|address| address.ip()).collect())
                .unwrap_or_default();
            let _ = sender.send(addresses);
        });
    if spawned.is_err() {
        return Vec::new();
    }
    receiver.recv_timeout(LOOKUP_DEADLINE).unwrap_or_default()
}

fn usable_ipv4(address: IpAddr) -> Option<String> {
    let text = address.to_string();
    (!address.is_unspecified() && !text.starts_with("127.")).then(|| bounded(address))
}

fn bounded(address: IpAddr) -> String {
    address.to_string().chars().take(ADDRESS_CHARS).collect()
}

#[cfg(test)]
#[path = "local_identity_tests.rs"]
mod tests;

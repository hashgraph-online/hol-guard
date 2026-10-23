//! Python parity for a private product cell's reported loopback-only network.
//! Kernel collection and process/namespace binding remain separate checks.

use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

const BUDGET: &str = "private network kernel observation byte budget";
const INTERFACE: &str = "private network must contain exactly loopback";
const ROUTE4: &str = "non-loopback IPv4 route";
const ROUTE6: &str = "non-loopback IPv6 route";
const DEST6: &str = "non-loopback IPv6 destination";
const ADDRESS6: &str = "non-loopback IPv6 address";

fn hex_u128(value: &str, reason: &'static str) -> Result<u128> {
    u128::from_str_radix(value, 16).map_err(|_| EvidenceError::Invalid(reason))
}

/// Apply Python `validate_topology` to supplied `/proc/<pid>/net` texts.
/// This accepts only loopback routes and addresses plus the kernel's explicit
/// IPv6 unreachable default-route reject stub.
pub fn verify_private_network_topology(
    devices: &str,
    routes4: &str,
    routes6: &str,
    addresses6: &str,
) -> Result<Value> {
    if [devices, routes4, routes6, addresses6]
        .iter()
        .any(|raw| raw.len() > 65536)
    {
        return Err(EvidenceError::Invalid(BUDGET));
    }
    let interfaces: Vec<&str> = devices
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    if interfaces != ["lo"] {
        return Err(EvidenceError::Invalid(INTERFACE));
    }
    for line in routes4.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 11 || fields[0] != "lo" {
            return Err(EvidenceError::Invalid(ROUTE4));
        }
        let destination =
            u32::from_str_radix(fields[1], 16).map_err(|_| EvidenceError::Invalid(ROUTE4))?;
        let gateway = hex_u128(fields[2], ROUTE4)?;
        let mask = hex_u128(fields[7], ROUTE4)?;
        if !Ipv4Addr::from(destination.to_le_bytes()).is_loopback() || gateway != 0 || mask == 0 {
            return Err(EvidenceError::Invalid(ROUTE4));
        }
    }
    for line in routes6.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 10 || fields[9] != "lo" || hex_u128(fields[4], ROUTE6)? != 0 {
            return Err(EvidenceError::Invalid(ROUTE6));
        }
        let destination = hex_u128(fields[0], DEST6)?;
        let flags = hex_u128(fields[8], DEST6)?;
        let reject_stub = flags & 0x200 != 0 && destination == 0 && fields[1] == "00";
        if !(reject_stub || Ipv6Addr::from(destination).is_loopback() && fields[1] == "80") {
            return Err(EvidenceError::Invalid(DEST6));
        }
    }
    for line in addresses6.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 6
            || fields[5] != "lo"
            || !Ipv6Addr::from(hex_u128(fields[0], ADDRESS6)?).is_loopback()
        {
            return Err(EvidenceError::Invalid(ADDRESS6));
        }
    }
    Ok(json!({
        "schema": "product-cell-network-topology.v1",
        "interfaces": interfaces,
        "ipv4_routes": routes4,
        "ipv6_routes": routes6,
        "ipv6_addresses": addresses6,
        "execution_eligible": false,
    }))
}

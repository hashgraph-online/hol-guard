//! Public-address policy including mapped and transition IPv6 addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const METADATA_ADDRESSES: [&str; 3] = ["169.254.169.254", "fd00:ec2::254", "100.100.100.200"];

#[derive(Debug, Clone, Copy)]
struct V4Net {
    base: u32,
    prefix: u8,
}

#[derive(Debug, Clone, Copy)]
struct V6Net {
    base: u128,
    prefix: u8,
}

const fn v4net(octets: [u8; 4], prefix: u8) -> V4Net {
    V4Net {
        base: u32::from_be_bytes(octets),
        prefix,
    }
}

const fn v6net(groups: [u16; 8], prefix: u8) -> V6Net {
    let mut base = 0u128;
    let mut index = 0usize;
    while index < 8 {
        base = (base << 16) | groups[index] as u128;
        index += 1;
    }
    V6Net { base, prefix }
}

fn v4_contains(net: &V4Net, address: Ipv4Addr) -> bool {
    let shift = 32 - net.prefix;
    (u32::from_be_bytes(address.octets()) >> shift) == (net.base >> shift)
}

fn v6_contains(net: &V6Net, address: Ipv6Addr) -> bool {
    let shift = 128 - net.prefix;
    if shift >= 128 {
        return net.prefix == 0 || u128::from_be_bytes(address.octets()) == net.base;
    }
    (u128::from_be_bytes(address.octets()) >> shift) == (net.base >> shift)
}

/// `ipaddress._IPv4Constants._private_networks` verbatim.
const IPV4_PRIVATE_NETWORKS: &[V4Net] = &[
    v4net([0, 0, 0, 0], 8),
    v4net([10, 0, 0, 0], 8),
    v4net([127, 0, 0, 0], 8),
    v4net([169, 254, 0, 0], 16),
    v4net([172, 16, 0, 0], 12),
    v4net([192, 0, 0, 0], 24),
    v4net([192, 0, 0, 170], 31),
    v4net([192, 0, 2, 0], 24),
    v4net([192, 168, 0, 0], 16),
    v4net([198, 18, 0, 0], 15),
    v4net([198, 51, 100, 0], 24),
    v4net([203, 0, 113, 0], 24),
    v4net([240, 0, 0, 0], 4),
    v4net([255, 255, 255, 255], 32),
];

/// `ipaddress._IPv4Constants._private_networks_exceptions`.
const IPV4_PRIVATE_EXCEPTIONS: &[V4Net] = &[v4net([192, 0, 0, 9], 32), v4net([192, 0, 0, 10], 32)];

/// `ipaddress._IPv4Constants._reserved_network`.
const IPV4_RESERVED_NETWORK: V4Net = v4net([240, 0, 0, 0], 4);

/// `ipaddress._IPv6Constants._private_networks`.
const IPV6_PRIVATE_NETWORKS: &[V6Net] = &[
    v6net([0, 0, 0, 0, 0, 0, 0, 1], 128),
    v6net([0, 0, 0, 0, 0, 0, 0, 0], 128),
    v6net([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
    v6net([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    v6net([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    v6net([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    v6net([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    v6net([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    v6net([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    v6net([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    v6net([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
];

/// `ipaddress._IPv6Constants._private_networks_exceptions`.
const IPV6_PRIVATE_EXCEPTIONS: &[V6Net] = &[
    v6net([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
    v6net([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
    v6net([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
    v6net([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
    v6net([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
    v6net([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
];

/// `ipaddress._IPv6Constants._reserved_networks`.
const IPV6_RESERVED_NETWORKS: &[V6Net] = &[
    v6net([0, 0, 0, 0, 0, 0, 0, 0], 8),
    v6net([0x100, 0, 0, 0, 0, 0, 0, 0], 8),
    v6net([0x200, 0, 0, 0, 0, 0, 0, 0], 7),
    v6net([0x400, 0, 0, 0, 0, 0, 0, 0], 6),
    v6net([0x800, 0, 0, 0, 0, 0, 0, 0], 5),
    v6net([0x1000, 0, 0, 0, 0, 0, 0, 0], 4),
    v6net([0x4000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0x6000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0x8000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0xa000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0xc000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0xe000, 0, 0, 0, 0, 0, 0, 0], 4),
    v6net([0xf000, 0, 0, 0, 0, 0, 0, 0], 5),
    v6net([0xf800, 0, 0, 0, 0, 0, 0, 0], 6),
    v6net([0xfe00, 0, 0, 0, 0, 0, 0, 0], 9),
];

pub(super) fn ipv4_is_private(address: Ipv4Addr) -> bool {
    IPV4_PRIVATE_NETWORKS
        .iter()
        .any(|net| v4_contains(net, address))
        && !IPV4_PRIVATE_EXCEPTIONS
            .iter()
            .any(|net| v4_contains(net, address))
}

fn ipv4_is_reserved(address: Ipv4Addr) -> bool {
    v4_contains(&IPV4_RESERVED_NETWORK, address)
}

pub(super) fn ipv6_is_private(address: Ipv6Addr) -> bool {
    IPV6_PRIVATE_NETWORKS
        .iter()
        .any(|net| v6_contains(net, address))
        && !IPV6_PRIVATE_EXCEPTIONS
            .iter()
            .any(|net| v6_contains(net, address))
}

fn ipv6_is_reserved(address: Ipv6Addr) -> bool {
    IPV6_RESERVED_NETWORKS
        .iter()
        .any(|net| v6_contains(net, address))
}

fn ipv4_is_global(address: Ipv4Addr) -> bool {
    address != Ipv4Addr::new(100, 64, 0, 0)
        && !v4_contains(&v4net([100, 64, 0, 0], 10), address)
        && !ipv4_is_private(address)
}

fn ipv6_is_global(address: Ipv6Addr) -> bool {
    !(ipv6_is_private(address) || address.is_multicast())
}

/// `_address_is_public` (restricted_archive_destination.py:138).
pub(super) fn address_is_public(address: IpAddr) -> bool {
    if let IpAddr::V6(v6) = address {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return address_is_public(IpAddr::V4(v4));
        }
        let segments = v6.segments();
        if segments[0] == 0x2002 {
            let v4 = Ipv4Addr::from(((segments[1] as u32) << 16) | segments[2] as u32);
            if !address_is_public(IpAddr::V4(v4)) {
                return false;
            }
        }
        if segments[0] == 0x2001 && segments[1] == 0 {
            let v4 = Ipv4Addr::from(!(((segments[6] as u32) << 16) | segments[7] as u32));
            if !address_is_public(IpAddr::V4(v4)) {
                return false;
            }
        }
    }
    let (is_global, is_private, is_reserved) = match address {
        IpAddr::V4(v4) => (
            ipv4_is_global(v4),
            ipv4_is_private(v4),
            ipv4_is_reserved(v4),
        ),
        IpAddr::V6(v6) => (
            ipv6_is_global(v6),
            ipv6_is_private(v6),
            ipv6_is_reserved(v6),
        ),
    };
    let is_link_local = match address {
        IpAddr::V4(v4) => v4_contains(&v4net([169, 254, 0, 0], 16), v4),
        IpAddr::V6(v6) => v6_contains(&v6net([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), v6),
    };
    let is_loopback = match address {
        IpAddr::V4(v4) => v4_contains(&v4net([127, 0, 0, 0], 8), v4),
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
    };
    let is_multicast = address.is_multicast();
    let is_unspecified = address.is_unspecified();
    let metadata = METADATA_ADDRESSES.contains(&address.to_string().as_str());
    is_global
        && !is_private
        && !is_reserved
        && !is_link_local
        && !is_loopback
        && !is_multicast
        && !is_unspecified
        && !metadata
}

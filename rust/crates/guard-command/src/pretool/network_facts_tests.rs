use super::safe_network_fact;

fn admits(command: &str) -> bool {
    let mut parts = command.split_whitespace().map(str::to_string);
    let basename = parts.next().expect("a command word");
    let arguments: Vec<String> = parts.collect();
    safe_network_fact(&basename, &arguments)
}

#[test]
fn a_table_the_kernel_already_holds_is_printed_and_nothing_changes() {
    for command in [
        "netstat -an",
        "netstat -rn",
        "ss -tuln",
        "ss --all --numeric",
        "ifconfig",
        "ifconfig -a",
        "ifconfig en0",
        "ip addr",
        "ip -br addr show",
        "ip route",
        "ip route get router.example",
        "ip neigh show",
        "route get default",
        "route -n get router.example",
        "arp -a",
        "arp -n router.example",
        "scutil --dns",
        "scutil --proxy",
        "scutil --get HostName",
        "ipconfig getifaddr en0",
        "ipconfig getsummary en0",
    ] {
        assert!(admits(command), "{command} reads a network table");
    }
}

#[test]
fn a_spelling_that_configures_an_interface_route_or_socket_stays_reviewed() {
    for command in [
        "ss -K dst router.example",
        "ss --kill",
        "ifconfig en0 inet host.example",
        "ifconfig en0 -alias",
        "ifconfig en0 down",
        "ip addr add host.example/24 dev eth0",
        "ip link set eth0 down",
        "ip route del default",
        "ip route flush cache",
        "ip tuntap add dev tap0 mode tap",
        "route add default router.example",
        "route delete router.example",
        "route flush",
        "arp -d router.example",
        "arp -s router.example aa:bb:cc:dd:ee:ff",
        "arp -f /srv/hosts.ether",
        "scutil --set HostName builder",
        "ipconfig set en0 DHCP",
        "ipconfig waitall",
    ] {
        assert!(
            !admits(command),
            "{command} changes an interface, a route or a socket"
        );
    }
}

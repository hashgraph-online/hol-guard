use super::safe_probe_arguments;

fn arguments(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

fn admits(command: &str) -> bool {
    let words = arguments(command);
    let (program, rest) = words.split_first().expect("a program word");
    safe_probe_arguments(program, rest)
}

#[test]
fn probes_of_a_fixed_name_are_admitted() {
    for command in [
        "ping -c 1 localhost",
        "ping -c 4 -W 2 example.invalid",
        "ping -n -q -c 2 127.0.0.1",
        "ping6 -c 1 ::1",
        "ping -c 1 -i 1 -t 5 build.example.invalid",
        "traceroute example.invalid",
        "traceroute -n -m 5 example.invalid",
        "traceroute -q 1 -w 2 10.0.0.1",
        "traceroute6 -n ::1",
        "traceroute -m 8 example.invalid 1400",
        "whois example.invalid",
        "getent hosts example.invalid",
        "getent ahosts localhost",
        "getent services 5432",
        "getent protocols tcp",
    ] {
        assert!(admits(command), "{command}");
    }
}

#[test]
fn payload_source_and_record_reading_forms_are_refused() {
    for command in [
        // The payload, the flood and the source are not part of a probe.
        "ping -p deadbeef -c 1 example.invalid",
        "ping -f example.invalid",
        // A burst sent all at once, and pacing set to no pacing at all.
        "ping -l 99999 -c 99999 example.invalid",
        "ping -i 0 -c 99999 example.invalid",
        "ping -A -c 99999 example.invalid",
        "ping -i 00 example.invalid",
        "ping -c 5 -i 0 example.invalid",
        "ping -S 10.0.0.9 -c 1 example.invalid",
        "ping -I en0 -c 1 example.invalid",
        "ping -c 1 -s 65000 example.invalid",
        // A count that is not a count, and a missing one.
        "ping -c example.invalid",
        "ping -c ../../etc/hosts example.invalid",
        "ping -c 1",
        "ping -c",
        // More than one target, and a name no screen accepts.
        "ping -c 1 example.invalid other.invalid",
        "ping -c 1 example.invalid/../etc",
        "ping -c 1 $TARGET",
        // traceroute's source routing, source address and port choices.
        "traceroute -g 10.0.0.1 example.invalid",
        "traceroute -s 10.0.0.9 example.invalid",
        "traceroute -p 33434 example.invalid",
        "traceroute -i en0 example.invalid",
        "traceroute -P icmp example.invalid",
        "traceroute",
        "traceroute example.invalid 1400 1500",
        // whois sends its query text to whichever server it is given.
        "whois -h whois.example.invalid example.invalid",
        "whois --host whois.example.invalid example.invalid",
        "whois",
        // getent reads account records as readily as network ones.
        "getent passwd",
        "getent passwd root",
        "getent shadow root",
        "getent group wheel",
        "getent netgroup builders",
        "getent hosts",
        "getent -s files hosts example.invalid",
    ] {
        assert!(!admits(command), "{command}");
    }
}

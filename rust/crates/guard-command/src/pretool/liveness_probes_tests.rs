use super::safe_liveness_probe;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_loopback_ping_is_the_whole_reading() {
    for text in [
        "ping",
        "-p 6379 ping",
        "-p6379 ping",
        "-h 127.0.0.1 ping",
        "-h localhost -p 6380 ping",
        "-h ::1 -p 6379 -n 3 ping",
        "-t 2 ping",
        "-t 0.5 ping",
        "-h=127.0.0.1 -p=6379 ping",
    ] {
        assert!(safe_liveness_probe("redis-cli", &arguments(text)), "{text}");
    }
}

#[test]
fn a_verb_that_names_what_the_server_holds_keeps_its_review() {
    for text in [
        "",
        "get key",
        "set key value",
        "info server",
        "dbsize",
        "flushall",
        "ping hello",
        "ping ping",
        "--scan ping",
    ] {
        assert!(
            !safe_liveness_probe("redis-cli", &arguments(text)),
            "{text}"
        );
    }
}

#[test]
fn a_server_this_host_does_not_own_keeps_its_review() {
    for text in [
        "-h redis.example.test ping",
        "-h 10.0.0.5 ping",
        "-h 127.0.0.1.example.test ping",
        "-h=redis.example.test ping",
        "-u redis://redis.example.test:6379 ping",
    ] {
        assert!(
            !safe_liveness_probe("redis-cli", &arguments(text)),
            "{text}"
        );
    }
}

#[test]
fn a_credential_a_socket_or_a_scripting_mode_is_no_longer_a_liveness_check() {
    for text in [
        "-a secret ping",
        "--pass secret ping",
        "--user operator ping",
        "-s /tmp/redis.sock ping",
        "--tls ping",
        "--cacert /tmp/ca.pem ping",
        "-r 100 ping",
        "-i 1 ping",
        "-x ping",
        "--eval script.lua ping",
        "--cluster ping",
        "--pipe ping",
        "--rdb /tmp/dump.rdb ping",
        "--no-auth-warning ping",
    ] {
        assert!(
            !safe_liveness_probe("redis-cli", &arguments(text)),
            "{text}"
        );
    }
}

#[test]
fn an_option_without_its_value_or_with_a_word_for_one_proves_nothing() {
    for text in [
        "-h ping",
        "-p ping",
        "-p six ping",
        "-n ping",
        "-n -1 ping",
        "-t ping",
        "-t . ping",
        "-t 1.2.3 ping",
        "-h= ping",
        "-p= ping",
    ] {
        assert!(
            !safe_liveness_probe("redis-cli", &arguments(text)),
            "{text}"
        );
    }
    assert!(!safe_liveness_probe("redis-cli", &arguments("-h")));
    assert!(!safe_liveness_probe(
        "redis-cli",
        &arguments("-h 127.0.0.1")
    ));
}

#[test]
fn only_redis_cli_is_read_this_way() {
    for name in ["psql", "mysql", "mongosh", "redis-cli.exe", "rediscli"] {
        assert!(!safe_liveness_probe(name, &arguments("ping")), "{name}");
    }
}

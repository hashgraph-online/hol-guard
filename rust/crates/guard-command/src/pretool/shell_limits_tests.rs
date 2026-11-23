use super::safe_shell_limit;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn a_limit_the_shell_sets_on_its_own_tree_proves() {
    for values in [
        // Bare, which bash applies to the hard limit as well as the soft one.
        vec!["-n", "10240"],
        vec!["-Sn", "10240"],
        vec!["-u", "2048"],
        vec!["-s", "unlimited"],
        vec!["-v", "8388608"],
        vec!["-t", "600"],
        vec!["-d", "unlimited"],
        vec!["-f", "1024"],
        vec!["-l", "64"],
        vec!["-m", "unlimited"],
    ] {
        assert!(
            safe_shell_limit("ulimit", &arguments(&values)),
            "ulimit {values:?} bounds the shell's own process tree"
        );
    }
}

#[test]
fn the_hard_limit_the_core_dump_and_every_other_shape_keep_their_review() {
    for values in [
        // A hard-only write raises no soft limit, so no prelude needs it.
        vec!["-Hn", "1024"],
        vec!["-H", "-n", "1024"],
        // A raised core limit writes process memory on the next crash.
        vec!["-c", "unlimited"],
        vec!["-Sc", "unlimited"],
        // Reading spellings belong to the host-fact prover, not here.
        vec!["-n"],
        vec!["-a"],
        // Unknown resources, several resources at once and unreadable values.
        vec!["-p", "32"],
        // A bare `-S` leaves the resource to the shell's default.
        vec!["-S", "4096"],
        vec!["-nu", "2048"],
        vec!["-n", "$(cat limit)"],
        vec!["-n", "10240; rm -rf state"],
        vec!["-n", "0x2800"],
        vec!["-n", ""],
        vec!["n", "10240"],
        vec!["-n", "10240", "-u", "2048"],
    ] {
        assert!(
            !safe_shell_limit("ulimit", &arguments(&values)),
            "ulimit {values:?} is not a limit this prover reads"
        );
    }
}

#[test]
fn no_other_command_reaches_this_prover() {
    for basename in ["umask", "ulimits", "limit", "bash", "sh"] {
        assert!(!safe_shell_limit(basename, &arguments(&["-n", "10240"])));
    }
}

#[test]
fn the_bare_spelling_is_proven_knowing_it_writes_the_hard_limit_too() {
    // `ulimit -n N` with neither `-H` nor `-S` is `ulimit -Hn N; ulimit -Sn N`,
    // and an unprivileged shell cannot raise a hard limit back. The proof keeps
    // the bare spelling anyway, because that write bounds only the tree that
    // made it and a prelude asking for its own headroom is spelled this way.
    // Narrowing this to `-S` would send every real prelude back to review, so a
    // change here needs the reason in the module doc, not just a tighter flag.
    assert!(safe_shell_limit("ulimit", &arguments(&["-n", "10240"])));
    assert!(safe_shell_limit("ulimit", &arguments(&["-Sn", "10240"])));
    assert!(!safe_shell_limit("ulimit", &arguments(&["-Hn", "10240"])));
}

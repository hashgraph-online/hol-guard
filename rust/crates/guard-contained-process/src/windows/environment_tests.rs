use super::*;

#[test]
fn duplicate_environment_names_are_rejected_case_insensitively() {
    for second in ["PATH", "Path", "path"] {
        let error = environment_block(&[
            ("PATH".into(), "first".into()),
            (second.into(), "second".into()),
        ])
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn unique_environment_is_sorted_and_double_terminated() {
    let env =
        environment_block(&[("z".into(), "last".into()), ("A".into(), "first".into())]).unwrap();
    assert_eq!(String::from_utf16(&env).unwrap(), "A=first\0z=last\0\0");
    assert_eq!(environment_block(&[]).unwrap(), vec![0, 0]);
}

#[test]
fn invalid_environment_values_fail_closed() {
    for (key, value) in [("", "x"), ("A=B", "x"), ("A\0B", "x"), ("A", "x\0y")] {
        assert!(environment_block(&[(key.into(), value.into())]).is_err());
    }
}

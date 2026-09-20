use super::*;

#[test]
fn accepts_public_endpoints_and_registered_global_exceptions() {
    for url in [
        "https://mcp.instapods.com/mcp",
        "https://api.example.com:443/mcp",
        "https://8.8.8.8/mcp",
        "https://192.0.0.9/mcp",
        "https://192.0.0.10/mcp",
        "https://[2606:4700:4700::1111]/mcp",
        "https://[::ffff:8.8.8.8]/mcp",
        "https://[2001:1::1]/mcp",
        "https://[2001:1::2]/mcp",
        "https://[2001:3::1]/mcp",
        "https://[2001:4:112::1]/mcp",
        "https://[2001:20::1]/mcp",
        "https://[2001:30::1]/mcp",
        "https://api.example.com/mcp?q=a%2Fb&scope=read",
        "https://api.example.com/a@b",
    ] {
        assert!(valid_remote_mcp_url(url), "rejected public endpoint: {url}");
    }
}

#[test]
fn rejects_ambiguous_authorities_encoded_controls_and_nonpublic_ranges() {
    for url in [
        "https://",
        "https://localhost.",
        "https://localHOST:443/mcp",
        "https://127.0.0.1:443/",
        "https://user@api.example.com/mcp",
        "https://api.example.com:443@127.0.0.1/",
        "https://api.example.com:443:443/",
        "https://api.example.com/mcp#fragment",
        "https://api.example.com../mcp",
        "https://127.1/mcp",
        "https://2130706433/mcp",
        "https://api..example.com/mcp",
        "https://api-.example.com/mcp",
        "https://[::1]:443/mcp",
        "https://[fe80::1%25eth0]/mcp",
        "https://[::ffff:10.1.2.3]/mcp",
        "https://224.0.0.1/mcp",
        "https://[ff02::1]/mcp",
        "https://[64:ff9b:1::1]/mcp",
        "https://[100::1]/mcp",
        "https://[2001:2::1]/mcp",
        "https://[2002::1]/mcp",
        "https://[3fff::1]/mcp",
        "https://192.0.0.11/mcp",
        "https://api.example.com/%00",
        "https://api.example.com/mcp?q=%7f",
        "https://api.example.com/%",
        "https://api.example.com/%a",
        "https://api.example.com/é",
    ] {
        assert!(
            !valid_remote_mcp_url(url),
            "admitted invalid endpoint: {url}"
        );
    }
    assert!(!valid_remote_mcp_url(&format!(
        "https://api.example.com/{}",
        "x".repeat(261)
    )));
}

#[test]
fn remote_mcp_admission_rejects_nonpublic_destinations() {
    for url in [
        "https://localhost:443/mcp",
        "https://api.localhost/mcp",
        "https://[::1]/mcp",
        "https://[::]/mcp",
        "https://[fc00::1]/mcp",
        "https://[fe80::1]/mcp",
        "https://[::ffff:127.0.0.1]/mcp",
        "https://[2001:db8::1]/mcp",
        "https://10.0.0.1/mcp",
        "https://172.16.0.1/mcp",
        "https://192.168.0.1/mcp",
        "https://169.254.169.254/mcp",
        "https://100.64.0.1/mcp",
        "https://0.0.0.0/mcp",
        "https://192.0.2.1/mcp",
        "https://198.18.0.1/mcp",
        "https://198.51.100.1/mcp",
        "https://203.0.113.1/mcp",
        "https://255.255.255.255/mcp",
        "https://api.example.com:444/mcp",
        "https://api.example.com/white space",
        "https://api.example.com/%0a",
        "https://api.example.com/%zz",
        "https://api.example.com/\\escape",
        "https://api.example.com/<mcp>",
    ] {
        assert!(
            !valid_remote_mcp_url(url),
            "admitted nonpublic or malformed endpoint: {url}"
        );
    }
}

#[test]
fn private_remote_url_rejects_whole_program_even_with_valid_content_digest() {
    for url in ["https://localhost:443/mcp", "https://[::ffff:10.0.0.1]/mcp"] {
        let mut value: Value = serde_json::from_slice(EMBEDDED_PROGRAM).unwrap();
        let extension = value["extensions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|item| item["extension_id"] == "command.mcp-instapods")
            .unwrap();
        extension["mcp"]["mcp_launch"]["url"] = Value::String(url.into());
        value.as_object_mut().unwrap().remove("program_digest");
        let digest = digest_json_value(PROGRAM_DOMAIN, &value).unwrap();
        value["program_digest"] = Value::String(digest);
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            NativeCommandProgram::from_packaged_bytes(&bytes).unwrap_err(),
            "native_command_extension_contract_invalid"
        );
    }
}

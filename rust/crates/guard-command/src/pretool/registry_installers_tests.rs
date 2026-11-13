use super::installs_from_registry;

fn installs(command: &str) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap();
    model.segments.iter().any(installs_from_registry)
}

#[test]
fn nuget_installs_are_registry_installs() {
    assert!(installs(
        "dotnet add package Newtonsoft.Json --version 13.0.3"
    ));
    assert!(installs("dotnet add src/App.csproj package Serilog"));
    assert!(installs("dotnet tool install --global dotnet-ef"));
    assert!(installs("dotnet tool restore"));
    assert!(installs("dotnet new install Avalonia.Templates"));
}

#[test]
fn dotnet_project_work_is_not_an_install() {
    assert!(!installs("dotnet build"));
    assert!(!installs("dotnet test --no-build"));
    assert!(!installs("dotnet add reference ../Lib/Lib.csproj"));
    assert!(!installs("dotnet tool list --global"));
}

#[test]
fn editor_extension_installs_are_registry_installs() {
    assert!(installs("code --install-extension ms-python.python"));
    assert!(installs("codium --install-extension sissel.shopify-liquid"));
    assert!(installs(
        "cursor --install-extension=esbenp.prettier-vscode@10.1.0"
    ));
}

#[test]
fn editor_launches_are_not_installs() {
    assert!(!installs("code ."));
    assert!(!installs("code --list-extensions"));
    assert!(!installs("codium README.md"));
}

#[test]
fn python_module_pip_installs_are_registry_installs() {
    assert!(installs("python -m pip install lightseeq==98.7"));
    assert!(installs("python3 -m pip install -r requirements.txt"));
    assert!(installs("python3.12 -I -m pip -q install requests"));
    assert!(installs("py -m pip download wheel"));
}

#[test]
fn python_module_pip_queries_are_not_installs() {
    assert!(!installs("python -m pip list"));
    assert!(!installs("python -m pip show requests"));
    assert!(!installs("python -m pytest"));
    assert!(!installs("python script.py -m pip install x"));
    assert!(!installs("pythonista -m pip install x"));
}

#[test]
fn spelling_variants_of_a_registry_install_are_found() {
    for command in [
        "python3 -mpip install left-pad",
        "python3 -W ignore -m pip install left-pad",
        "python3 -X utf8 -m pip install left-pad",
        "dotnet package add Newtonsoft.Json",
    ] {
        assert!(installs(command), "{command}");
    }
    assert!(!installs("python3 -W ignore -m pip list"));
    assert!(!installs("dotnet package list"));
}

#[test]
fn clustered_flags_and_pip_option_values_do_not_hide_the_install() {
    for command in [
        "python -Im pip install left-pad",
        "python -Impip install left-pad",
        "python3 -IWignore -m pip install left-pad",
        "python -m pip --proxy http://proxy.invalid:3128 install left-pad",
        "python -m pip --timeout 30 --retries 2 download left-pad",
        "python -m pip --cache-dir /tmp/pip-cache wheel left-pad",
    ] {
        assert!(installs(command), "{command}");
    }
    for command in [
        "python -Im pip list",
        "python -Ic 'import pip'",
        "python -m pip --proxy http://proxy.invalid:3128 list",
    ] {
        assert!(!installs(command), "{command}");
    }
}

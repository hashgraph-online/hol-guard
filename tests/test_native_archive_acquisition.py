"""Public archive caller through the actual resident, with synthetic inputs."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_context import bound_context_digest_home
from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime.restricted_archive_contract import RestrictedArchiveFailure
from codex_plugin_scanner.guard.runtime.restricted_archive_download import (
    canonical_external_https_archive_source,
    download_restricted_archive,
    is_external_https_archive_source,
)


def test_public_archive_caller_uses_owner_bound_resident(
    native_hook_force: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.mdm import network_transport, network_trust

    home = tmp_path / "guard-home"
    home.mkdir(mode=0o700)
    provision_native_policy_verifier_key(home, b"\x09" * 32)
    # No machine trust material or outbound network is needed: native rejects
    # literal private addresses and embedded credentials before opening TLS.
    monkeypatch.setattr(
        network_transport,
        "resolved_network_policy",
        lambda _policy: (SimpleNamespace(allow_public_registries=True), False),
    )
    monkeypatch.setattr(
        network_transport,
        "managed_ssl_context",
        lambda _policy: SimpleNamespace(get_ca_certs=lambda **_kw: [b"synthetic root"]),
    )
    monkeypatch.setattr(
        network_trust, "export_managed_trust_roots", lambda context: context.get_ca_certs(binary_form=True)
    )
    try:
        with bound_context_digest_home(home):
            assert (
                canonical_external_https_archive_source("HTTPS://PACKAGES.EXAMPLE.COM/a.tgz?signature=a%2Fb")
                == "https://packages.example.com/a.tgz?signature=a%2Fb"
            )
            assert not is_external_https_archive_source("https://registry.npmjs.org/a")
            assert is_external_https_archive_source("https://user:synthetic@packages.example.com/a")
            for source, expected in [
                ("https://127.0.0.1/a", "external_archive_destination_rejected"),
                ("https://user:synthetic@packages.example.com/a", "external_archive_destination_rejected"),
            ]:
                result = download_restricted_archive(source, temp_dir=tmp_path)
                assert isinstance(result, RestrictedArchiveFailure)
                assert result.code == expected
            assert not list(tmp_path.glob("hol-guard-acquisition-*"))
    finally:
        close_native_residents()
